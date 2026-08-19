/*
 * OpenSSL 3 RAND provider drawing its random numbers from the ESDM's EGD
 * compatibility interface
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * The EGD counterpart of the RPC based provider in common.c: same RAND
 * algorithms, but the random numbers come over the Entropy Gathering Daemon
 * protocol. Its reason to exist is deployment, not capability - a single Unix
 * domain stream socket and no RPC client library reaches into environments
 * where the RPC interface is inconvenient, such as a chroot.
 *
 * Talking the protocol - the connection, its locking and the reconnect
 * handling - lives in libesdm_egd_client; this file is the OpenSSL side. One
 * client is allocated per loaded provider, connected during
 * OSSL_provider_init() and released in the teardown.
 *
 * Prediction resistance
 * ---------------------
 * The EGD protocol cannot express it, so a request asking for it is refused
 * rather than silently served ordinary random data - use the RPC provider.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esdm_egd_client.h"
#include "esdm_logger.h"
#include "helper.h"
#include "prov_error.h"
#include "visibility.h"

/*
 * Built twice: once against the ordinary EGD socket, and once - with
 * ESDM_EGD_PROV_FORCE_PR - against the one serving the prediction resistance
 * generator. The protocol cannot ask for prediction resistance per request, so
 * the socket decides which generator answers; this variant therefore differs
 * from its sibling only in the socket it defaults to, and accepts requests
 * asking for prediction resistance rather than refusing them.
 */
#ifdef ESDM_EGD_PROV_FORCE_PR
#define ESDM_EGD_PROV_NAME "ESDM RNG Provider (EGD, PR)"
#define ESDM_EGD_PROV_PROPERTIES "provider=esdm-egd-pr"
#define ESDM_EGD_PROV_DEFAULT_SOCKET ESDM_SERVER_EGD_PR_SOCKET_PATH
#else
#define ESDM_EGD_PROV_NAME "ESDM RNG Provider (EGD)"
/*
 * Property the algorithms below are tagged with. Deliberately distinct from
 * the "provider=esdm" of the RPC based provider: several of them can be loaded
 * at the same time, and a property query has to be able to name one.
 */
#define ESDM_EGD_PROV_PROPERTIES "provider=esdm-egd"
#define ESDM_EGD_PROV_DEFAULT_SOCKET NULL
#endif

#define ESDM_EGD_PROV_VERSION VERSION
#define ESDM_EGD_PROV_BUILDINFO VERSION

/*
 * Reason codes reported into the OpenSSL error stack, resolved to text by
 * esdm_egd_get_reason_strings(). libcrypto reserves the low numbers for the
 * ERR_R_* reasons shared by all libraries, so start at 100 like OpenSSL's own
 * providers do.
 */
#define ESDM_EGD_R_INIT_FAILED 100
#define ESDM_EGD_R_MALLOC_FAILURE 101
#define ESDM_EGD_R_CONNECTION_FAILURE 102
#define ESDM_EGD_R_TRANSFER_FAILURE 103
#define ESDM_EGD_R_INVALID_ARGUMENT 104
#define ESDM_EGD_R_SEED_LENGTH_UNSUPPORTED 105
#define ESDM_EGD_R_LOCK_FAILURE 106
#define ESDM_EGD_R_PR_UNSUPPORTED 107
#define ESDM_EGD_R_SOCKET_PATH_TOO_LONG 108

/*
 * Name of the openssl.cnf key of this provider's section that names the
 * socket, overriding the ESDM_EGD_SOCKET environment variable and the built in
 * default the client library falls back to.
 */
#define ESDM_EGD_SOCKET_CONF_KEY "egd_socket"

struct esdm_egd_provider_ctx {
	const OSSL_CORE_HANDLE *core;
	OSSL_LIB_CTX *libctx;

	/* The one EGD connection of this provider. */
	struct esdm_egd_client *client;
};

struct esdm_egd_rand_ctx {
	struct esdm_egd_provider_ctx *prov;
	CRYPTO_RWLOCK *lock;
};

/* Is this the variant bound to the prediction resistance socket? */
static inline bool esdm_egd_prov_is_pr(void)
{
#ifdef ESDM_EGD_PROV_FORCE_PR
	return true;
#else
	return false;
#endif
}

/*
 * The client library returns a negative errno. Turn it into an error stack
 * entry naming the socket, since an unreachable or wrong one is by far the
 * most likely cause.
 */
static void esdm_egd_raise_transfer_error(struct esdm_egd_provider_ctx *prov,
					  int ret, size_t requested,
					  const char *what, const char *file,
					  int line, const char *func)
{
	esdm_prov_raise_error(
		prov->core, ESDM_PROV_LOGGER_CLASS, ESDM_EGD_R_TRANSFER_FAILURE,
		file, line, func,
		"requesting %zu %s over the EGD socket %s failed: %s",
		requested, what, esdm_egd_client_socket_path(prov->client),
		strerror(-ret));
}

/* Report against the operation that failed, not against the helper above. */
#define esdm_egd_transfer_error(prov, ret, requested, what)                    \
	esdm_egd_raise_transfer_error(prov, ret, requested, what, __FILE__,    \
				      __LINE__, OPENSSL_FUNC)

/************************************
 * RAND specific provider functions *
 ************************************/

/* Context management */
static OSSL_FUNC_rand_newctx_fn esdm_egd_rand_newctx;
static OSSL_FUNC_rand_freectx_fn esdm_egd_rand_freectx;
/* Random number generator functions: NIST */
static OSSL_FUNC_rand_instantiate_fn esdm_egd_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn esdm_egd_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn esdm_egd_rand_generate;
static OSSL_FUNC_rand_reseed_fn esdm_egd_rand_reseed;
/* Random number generator functions: additional */
static OSSL_FUNC_rand_nonce_fn esdm_egd_rand_nonce;
static OSSL_FUNC_rand_get_seed_fn esdm_egd_rand_get_seed;
static OSSL_FUNC_rand_clear_seed_fn esdm_egd_rand_clear_seed;
static OSSL_FUNC_rand_verify_zeroization_fn esdm_egd_rand_verify_zeroization;
/* Context Locking */
static OSSL_FUNC_rand_enable_locking_fn esdm_egd_rand_enable_locking;
static OSSL_FUNC_rand_lock_fn esdm_egd_rand_lock;
static OSSL_FUNC_rand_unlock_fn esdm_egd_rand_unlock;
/* RAND parameter descriptors */
static OSSL_FUNC_rand_gettable_ctx_params_fn esdm_egd_rand_gettable_ctx_params;
/* RAND parameters */
static OSSL_FUNC_rand_get_ctx_params_fn esdm_egd_rand_get_ctx_params;

static void *esdm_egd_rand_newctx(void *provctx, void *parent __unused,
				  const OSSL_DISPATCH *parent_calls __unused)
{
	struct esdm_egd_provider_ctx *cprov = provctx;
	struct esdm_egd_rand_ctx *rand;

	if (cprov == NULL)
		return NULL;

	rand = OPENSSL_secure_zalloc(sizeof(struct esdm_egd_rand_ctx));
	if (rand == NULL) {
		ESDM_PROV_ERR(cprov->core, ESDM_EGD_R_MALLOC_FAILURE,
			      "allocation of the RNG context failed");
		return NULL;
	}

	rand->prov = cprov;
	return rand;
}

static void esdm_egd_rand_freectx(void *ctx)
{
	struct esdm_egd_rand_ctx *rand = ctx;

	if (rand == NULL)
		return;

	CRYPTO_THREAD_lock_free(rand->lock);
	OPENSSL_secure_clear_free(rand, sizeof(struct esdm_egd_rand_ctx));
}

static int esdm_egd_rand_instantiate(void *ctx, unsigned int strength __unused,
				     int prediction_resistance,
				     const unsigned char *pstr __unused,
				     size_t pstr_len __unused,
				     const OSSL_PARAM params[] __unused)
{
	struct esdm_egd_rand_ctx *rand = ctx;

	if (prediction_resistance && !esdm_egd_prov_is_pr()) {
		ESDM_PROV_ERR(
			rand ? rand->prov->core : NULL,
			ESDM_EGD_R_PR_UNSUPPORTED,
			"the EGD protocol cannot request prediction resistance - use the prediction resistant EGD socket or the RPC based ESDM provider");
		return 0;
	}

	return 1;
}

static int esdm_egd_rand_uninstantiate(void *ctx __unused)
{
	return 1;
}

static int esdm_egd_rand_generate(void *ctx, unsigned char *out, size_t outlen,
				  unsigned int strength __unused,
				  int prediction_resistance,
				  const unsigned char *addin __unused,
				  size_t addin_len __unused)
{
	struct esdm_egd_rand_ctx *rand = ctx;
	struct esdm_egd_provider_ctx *prov;
	int ret;

	if (rand == NULL)
		return 0;
	prov = rand->prov;

	if (out == NULL) {
		ESDM_PROV_ERR(prov->core, ESDM_EGD_R_INVALID_ARGUMENT,
			      "no output buffer provided for %zu bytes",
			      outlen);
		return 0;
	}

	if (prediction_resistance && !esdm_egd_prov_is_pr()) {
		ESDM_PROV_ERR(
			prov->core, ESDM_EGD_R_PR_UNSUPPORTED,
			"the EGD protocol cannot request prediction resistance - use the prediction resistant EGD socket or the RPC based ESDM provider");
		return 0;
	}

	ret = esdm_egd_client_get_random(prov->client, out, outlen);
	if (ret) {
		esdm_egd_transfer_error(prov, ret, outlen,
					"bytes of random data");
		return 0;
	}

	return 1;
}

static int esdm_egd_rand_reseed(void *ctx __unused,
				int prediction_resistance __unused,
				const unsigned char *ent __unused,
				size_t ent_len __unused,
				const unsigned char *addin __unused,
				size_t addin_len __unused)
{
	/* Reseeding is the ESDM's business, not ours. */
	return 1;
}

static size_t esdm_egd_rand_nonce(void *ctx, unsigned char *out,
				  unsigned int strength __unused,
				  size_t min_noncelen,
				  size_t max_noncelen __unused)
{
	struct esdm_egd_rand_ctx *rand = ctx;
	struct esdm_egd_provider_ctx *prov;
	int ret;

	if (rand == NULL)
		return 0;
	prov = rand->prov;

	/* A NULL output buffer only queries the nonce length. */
	if (out == NULL)
		return min_noncelen;

	ret = esdm_egd_client_get_random(prov->client, out, min_noncelen);
	if (ret) {
		esdm_egd_transfer_error(prov, ret, min_noncelen,
					"bytes of nonce data");
		return 0;
	}

	return min_noncelen;
}

static size_t esdm_egd_rand_get_seed(void *ctx, unsigned char **buffer,
				     int entropy_bits, size_t min_len,
				     size_t max_len, int prediction_resistance,
				     const unsigned char *addin __unused,
				     size_t addin_len __unused)
{
	struct esdm_egd_rand_ctx *rand = ctx;
	struct esdm_egd_provider_ctx *prov;
	size_t buf_len;
	int ret;

	*buffer = NULL;

	if (rand == NULL)
		return 0;
	prov = rand->prov;

	if (prediction_resistance && !esdm_egd_prov_is_pr()) {
		ESDM_PROV_ERR(
			prov->core, ESDM_EGD_R_PR_UNSUPPORTED,
			"the EGD protocol cannot request prediction resistance - use the prediction resistant EGD socket or the RPC based ESDM provider");
		return 0;
	}

	if (entropy_bits <= 0) {
		ESDM_PROV_ERR(prov->core, ESDM_EGD_R_INVALID_ARGUMENT,
			      "non-positive entropy request of %i bits",
			      entropy_bits);
		return 0;
	}
	buf_len = ((size_t)entropy_bits + 7) / 8;

	/*
	 * OSSL_FUNC_rand_get_seed() has to hand back at least min_len bytes -
	 * the caller sizes its seed material by that, not by the entropy
	 * request - so round a smaller request up rather than failing. The ESDM
	 * delivers full entropy, so the extra bytes carry the requested entropy
	 * either way. Only a request above max_len is unsatisfiable.
	 */
	if (buf_len < min_len)
		buf_len = min_len;
	if (buf_len > max_len) {
		ESDM_PROV_ERR(
			prov->core, ESDM_EGD_R_SEED_LENGTH_UNSUPPORTED,
			"%i entropy bits require %zu bytes, but the caller accepts at most %zu",
			entropy_bits, buf_len, max_len);
		return 0;
	}

	*buffer = OPENSSL_secure_zalloc(buf_len);
	if (*buffer == NULL) {
		ESDM_PROV_ERR(prov->core, ESDM_EGD_R_MALLOC_FAILURE,
			      "allocation of a %zu byte seed buffer failed",
			      buf_len);
		return 0;
	}

	ret = esdm_egd_client_get_random(prov->client, *buffer, buf_len);
	if (ret) {
		esdm_egd_transfer_error(prov, ret, buf_len,
					"bytes of seed material");
		OPENSSL_secure_clear_free(*buffer, buf_len);
		*buffer = NULL;
		return 0;
	}

	return buf_len;
}

static void esdm_egd_rand_clear_seed(void *ctx __unused, unsigned char *buffer,
				     size_t b_len)
{
	OPENSSL_secure_clear_free(buffer, b_len);
}

static int esdm_egd_rand_verify_zeroization(void *ctx __unused)
{
	return 1;
}

static int esdm_egd_rand_enable_locking(void *ctx)
{
	struct esdm_egd_rand_ctx *rand = ctx;

	if (rand == NULL)
		return 0;

	/*
	 * Nothing to do for a context that already has its lock. libcrypto
	 * hands the same context to several users - a DRBG enables locking on
	 * the parent it was given, and every child does so again - and a second
	 * lock here would replace the first one while it is still held,
	 * leaking it and leaving the two users locking different things.
	 */
	if (rand->lock != NULL)
		return 1;

	rand->lock = CRYPTO_THREAD_lock_new();
	if (rand->lock == NULL) {
		ESDM_PROV_ERR(rand->prov->core, ESDM_EGD_R_LOCK_FAILURE,
			      "creation of the RNG context lock failed");
		return 0;
	}
	return 1;
}

static int esdm_egd_rand_lock(void *ctx)
{
	struct esdm_egd_rand_ctx *rand = ctx;

	if (rand == NULL || rand->lock == NULL)
		return 1;
	return CRYPTO_THREAD_write_lock(rand->lock);
}

static void esdm_egd_rand_unlock(void *ctx)
{
	struct esdm_egd_rand_ctx *rand = ctx;

	if (rand == NULL || rand->lock == NULL)
		return;
	CRYPTO_THREAD_unlock(rand->lock);
}

static const OSSL_PARAM *
esdm_egd_rand_gettable_ctx_params(void *ctx __unused, void *provctx __unused)
{
	static const OSSL_PARAM known_gettable_ctx_params[] = {
		OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, 0),
		OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, 0),
		OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, 0), OSSL_PARAM_END
	};
	return known_gettable_ctx_params;
}

static int esdm_egd_rand_get_ctx_params(void *ctx __unused, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	if (params == NULL)
		return 1;

	/*
	 * Larger requests are split into protocol sized transfers internally,
	 * so this is the same value the RPC based provider reports rather than
	 * the 255 byte limit of a single EGD transfer.
	 */
	p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, 256))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
	if (p != NULL && !OSSL_PARAM_set_uint(p, 256))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
	if (p != NULL && !OSSL_PARAM_set_int(p, EVP_RAND_STATE_READY))
		return 0;

	return 1;
}

static const OSSL_DISPATCH esdm_egd_rand_functions[] = {
	/* Context management */
	{ OSSL_FUNC_RAND_NEWCTX, (void (*)(void))esdm_egd_rand_newctx },
	{ OSSL_FUNC_RAND_FREECTX, (void (*)(void))esdm_egd_rand_freectx },
	/* Random number generator functions: NIST */
	{ OSSL_FUNC_RAND_INSTANTIATE,
	  (void (*)(void))esdm_egd_rand_instantiate },
	{ OSSL_FUNC_RAND_UNINSTANTIATE,
	  (void (*)(void))esdm_egd_rand_uninstantiate },
	{ OSSL_FUNC_RAND_GENERATE, (void (*)(void))esdm_egd_rand_generate },
	{ OSSL_FUNC_RAND_RESEED, (void (*)(void))esdm_egd_rand_reseed },
	/* Random number generator functions: additional */
	{ OSSL_FUNC_RAND_NONCE, (void (*)(void))esdm_egd_rand_nonce },
	{ OSSL_FUNC_RAND_GET_SEED, (void (*)(void))esdm_egd_rand_get_seed },
	{ OSSL_FUNC_RAND_CLEAR_SEED,
	  (void (*)(void))esdm_egd_rand_clear_seed },
	{ OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
	  (void (*)(void))esdm_egd_rand_verify_zeroization },
	/* Context Locking */
	{ OSSL_FUNC_RAND_ENABLE_LOCKING,
	  (void (*)(void))esdm_egd_rand_enable_locking },
	{ OSSL_FUNC_RAND_LOCK, (void (*)(void))esdm_egd_rand_lock },
	{ OSSL_FUNC_RAND_UNLOCK, (void (*)(void))esdm_egd_rand_unlock },
	/* RAND parameter descriptors */
	{ OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
	  (void (*)(void))esdm_egd_rand_gettable_ctx_params },
	/* RAND parameters */
	{ OSSL_FUNC_RAND_GET_CTX_PARAMS,
	  (void (*)(void))esdm_egd_rand_get_ctx_params },
	/* Delimiter */
	{ 0, NULL }
};

/* Direct all pre-defined OpenSSL RAND implementations to the ESDM. */
static const OSSL_ALGORITHM esdm_egd_rands[] = {
	{ "CTR-DRBG", ESDM_EGD_PROV_PROPERTIES, esdm_egd_rand_functions, NULL },
	{ "HASH-DRBG", ESDM_EGD_PROV_PROPERTIES, esdm_egd_rand_functions,
	  NULL },
	{ "HMAC-DRBG", ESDM_EGD_PROV_PROPERTIES, esdm_egd_rand_functions,
	  NULL },
	{ "SEED-SRC", ESDM_EGD_PROV_PROPERTIES, esdm_egd_rand_functions, NULL },
	{ NULL, NULL, NULL, NULL }
};

/******************************
 * General Provider functions *
 ******************************/

static const OSSL_PARAM *esdm_egd_gettable_params(void *provctx __unused)
{
	static const OSSL_PARAM param_types[] = {
		OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL,
				0),
		OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR,
				NULL, 0),
		OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR,
				NULL, 0),
		OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER,
				NULL, 0),
		OSSL_PARAM_END
	};

	return param_types;
}

static int esdm_egd_get_params(void *provctx __unused, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ESDM_EGD_PROV_NAME))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ESDM_EGD_PROV_VERSION))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ESDM_EGD_PROV_BUILDINFO))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* always running */
		return 0;

	return 1;
}

static const OSSL_ALGORITHM *
esdm_egd_query_operation(void *provctx __unused, int operation_id,
			 int *no_cache)
{
	*no_cache = 0;

	switch (operation_id) {
	case OSSL_OP_RAND:
		return esdm_egd_rands;
	}

	return NULL;
}

static void esdm_egd_unquery_operation(void *provctx __unused,
				       int operation_id __unused,
				       const OSSL_ALGORITHM *alg __unused)
{
}

static const OSSL_ITEM *esdm_egd_get_reason_strings(void *provctx __unused)
{
	static const OSSL_ITEM reason_strings[] = {
		{ ESDM_EGD_R_INIT_FAILED,
		  "ESDM EGD provider initialization failed" },
		{ ESDM_EGD_R_MALLOC_FAILURE, "memory allocation failed" },
		{ ESDM_EGD_R_CONNECTION_FAILURE,
		  "cannot connect to the ESDM EGD socket - is esdm-server running with its EGD interface enabled?" },
		{ ESDM_EGD_R_TRANSFER_FAILURE,
		  "the transfer over the ESDM EGD socket failed" },
		{ ESDM_EGD_R_INVALID_ARGUMENT, "invalid argument" },
		{ ESDM_EGD_R_SEED_LENGTH_UNSUPPORTED,
		  "requested seed length cannot be satisfied" },
		{ ESDM_EGD_R_LOCK_FAILURE, "lock creation failed" },
		{ ESDM_EGD_R_PR_UNSUPPORTED,
		  "the EGD protocol cannot express prediction resistance" },
		{ ESDM_EGD_R_SOCKET_PATH_TOO_LONG,
		  "the configured EGD socket path does not fit into a Unix domain socket address" },
		{ 0, NULL }
	};

	return reason_strings;
}

static int esdm_egd_self_test(void *provctx)
{
	struct esdm_egd_provider_ctx *cprov = provctx;
	uint32_t ent_bits = 0;
	int ret;

	if (cprov == NULL)
		return 0;

	/*
	 * The ESDM tests itself - all this has to establish is that the EGD
	 * interface is reachable and speaks the protocol. The entropy count
	 * command is the cheapest complete round trip for that.
	 */
	ret = esdm_egd_client_entropy_count(cprov->client, &ent_bits);
	if (ret) {
		ESDM_PROV_ERR(
			cprov->core, ESDM_EGD_R_CONNECTION_FAILURE,
			"self test: querying the entropy count over the EGD socket %s failed: %s",
			esdm_egd_client_socket_path(cprov->client),
			strerror(-ret));
		return 0;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "ESDM EGD provider: self test passed, %u bits available\n",
		    ent_bits);

	return 1;
}

static void esdm_egd_teardown(void *provctx)
{
	struct esdm_egd_provider_ctx *cprov = provctx;

	if (cprov == NULL)
		return;

	/* The single connection of this provider goes down with it. */
	esdm_egd_client_free(cprov->client);

	OSSL_LIB_CTX_free(cprov->libctx);
	OPENSSL_secure_clear_free(cprov, sizeof(struct esdm_egd_provider_ctx));
}

static const OSSL_DISPATCH esdm_egd_dispatch_table[] = {
	{ OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
	  (void (*)(void))esdm_egd_gettable_params },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))esdm_egd_get_params },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION,
	  (void (*)(void))esdm_egd_query_operation },
	{ OSSL_FUNC_PROVIDER_UNQUERY_OPERATION,
	  (void (*)(void))esdm_egd_unquery_operation },
	{ OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
	  (void (*)(void))esdm_egd_get_reason_strings },
	{ OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))esdm_egd_self_test },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))esdm_egd_teardown },
	{ 0, NULL }
};

DSO_PUBLIC int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
				  const OSSL_DISPATCH *in,
				  const OSSL_DISPATCH **out, void **provctx)
{
	struct esdm_egd_provider_ctx *cprov;
	const char *socket_path;
	int ret;

	/* Pick up the core upcalls before anything can fail. */
	esdm_prov_init_error_reporting(in, handle);

	cprov = OPENSSL_secure_zalloc(sizeof(struct esdm_egd_provider_ctx));
	if (cprov == NULL) {
		ESDM_PROV_ERR(handle, ESDM_EGD_R_MALLOC_FAILURE,
			      "allocation of the provider context failed");
		return 0;
	}

	cprov->core = handle;

	/*
	 * The socket named in this provider's openssl.cnf section wins; with
	 * none configured the client library falls back to the environment and
	 * then to the esdm-server-egd.socket path. This also establishes the one
	 * connection used for the provider's lifetime. An ESDM that is not up
	 * yet is not fatal - the client retries, and refusing to load would take
	 * the whole OpenSSL configuration down. Use the provider self test where
	 * that should be a hard failure.
	 */
	socket_path = esdm_prov_get_conf_param(handle,
					       ESDM_EGD_SOCKET_CONF_KEY);
	if (socket_path == NULL || *socket_path == '\0')
		socket_path = ESDM_EGD_PROV_DEFAULT_SOCKET;

	ret = esdm_egd_client_alloc(&cprov->client, socket_path, 0);
	if (ret == -ENAMETOOLONG) {
		ESDM_PROV_ERR(
			handle, ESDM_EGD_R_SOCKET_PATH_TOO_LONG,
			"the configured EGD socket path does not fit into a Unix domain socket address");
		goto err;
	}
	if (ret) {
		ESDM_PROV_ERR(handle, ESDM_EGD_R_INIT_FAILED,
			      "allocation of the EGD client failed: %s",
			      strerror(-ret));
		goto err;
	}

	cprov->libctx = OSSL_LIB_CTX_new_child(handle, in);
	if (cprov->libctx == NULL) {
		ESDM_PROV_ERR(handle, ESDM_EGD_R_INIT_FAILED,
			      "creation of the child library context failed");
		goto err_disconnect;
	}

	*out = esdm_egd_dispatch_table;
	*provctx = cprov;

	return 1;

err_disconnect:
	esdm_egd_client_free(cprov->client);

err:
	OPENSSL_secure_clear_free(cprov, sizeof(struct esdm_egd_provider_ctx));

	return 0;
}
