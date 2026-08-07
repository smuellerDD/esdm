/*
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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

#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Failures of this provider are failures of the RPC to the ESDM server. */
#define ESDM_PROV_LOGGER_CLASS LOGGER_C_RPC

#include "common.h"
#include "esdm_logger.h"
#include "esdm_rpc_client.h"
#include "helper.h"
#include "math_helper.h"
#include "prov_error.h"
#include "visibility.h"

/*****************
 * Error reporting
 *****************/

/*
 * The RPC helpers return the number of bytes delivered or a negative errno.
 * Turn both into an error stack entry describing what actually went wrong.
 */
static void esdm_prov_rpc_error(const OSSL_CORE_HANDLE *handle, ssize_t ret,
				size_t requested, const char *what,
				const char *file, int line, const char *func)
{
	if (ret < 0)
		esdm_prov_raise_error(
			handle, ESDM_PROV_LOGGER_CLASS, ESDM_R_RPC_FAILURE,
			file, line, func,
			"requesting %zu %s from the ESDM server failed: %s",
			requested, what, strerror((int)-ret));
	else
		esdm_prov_raise_error(
			handle, ESDM_PROV_LOGGER_CLASS,
			ESDM_R_SHORT_RANDOM_DATA, file, line, func,
			"ESDM server delivered %zd of %zu requested %s", ret,
			requested, what);
}

#define ESDM_PROV_RPC_ERR(handle, ret, requested, what)                        \
	esdm_prov_rpc_error(handle, ret, requested, what, __FILE__, __LINE__,  \
			    OPENSSL_FUNC)

/************************************
 * RAND specific provider functions *
 ************************************/

/* Context management */
static OSSL_FUNC_rand_newctx_fn esdm_rand_newctx;
static OSSL_FUNC_rand_freectx_fn esdm_rand_freectx;
/* Random number generator functions: NIST */
static OSSL_FUNC_rand_instantiate_fn esdm_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn esdm_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn esdm_rand_generate;
static OSSL_FUNC_rand_reseed_fn esdm_rand_reseed;
/* Random number generator functions: additional */
static OSSL_FUNC_rand_nonce_fn esdm_rand_nonce;
static OSSL_FUNC_rand_get_seed_fn esdm_rand_get_seed;
static OSSL_FUNC_rand_clear_seed_fn esdm_rand_clear_seed;
static OSSL_FUNC_rand_verify_zeroization_fn esdm_rand_verify_zeroization;
/* Context Locking */
static OSSL_FUNC_rand_enable_locking_fn esdm_rand_enable_locking;
static OSSL_FUNC_rand_lock_fn esdm_rand_lock;
static OSSL_FUNC_rand_unlock_fn esdm_rand_unlock;
/* RAND parameter descriptors */
static OSSL_FUNC_rand_gettable_ctx_params_fn esdm_rand_gettable_ctx_params;
/* RAND parameters */
static OSSL_FUNC_rand_get_ctx_params_fn esdm_rand_get_ctx_params;

static void *esdm_rand_newctx(void *provctx, void *parent __unused,
			      const OSSL_DISPATCH *parent_calls __unused)
{
	struct esdm_provider_ctx *cprov = provctx;
	struct esdm_rand_ctx *rand =
		OPENSSL_secure_zalloc(sizeof(struct esdm_rand_ctx));

	if (rand == NULL) {
		ESDM_PROV_ERR(cprov->core, ESDM_R_MALLOC_FAILURE,
			      "allocation of the RNG context failed");
		return NULL;
	}

	rand->core = cprov->core;
	return rand;
}

static void esdm_rand_freectx(void *ctx)
{
	struct esdm_rand_ctx *rand = ctx;

	if (rand == NULL)
		return;

	CRYPTO_THREAD_lock_free(rand->lock);
	OPENSSL_secure_clear_free(rand, sizeof(struct esdm_rand_ctx));
}

static int esdm_rand_instantiate(void *ctx __unused,
				 unsigned int strength __unused,
				 int prediction_resistance __unused,
				 const unsigned char *pstr __unused,
				 size_t pstr_len __unused,
				 const OSSL_PARAM params[] __unused)
{
	return 1;
}

static int esdm_rand_uninstantiate(void *ctx __unused)
{
	return 1;
}

static int esdm_rand_generate(void *ctx, unsigned char *out, size_t outlen,
			      unsigned int strength __unused,
			      int prediction_resistance,
			      const unsigned char *addin __unused,
			      size_t addin_len __unused)
{
	struct esdm_rand_ctx *rand = ctx;
	const OSSL_CORE_HANDLE *core = rand ? rand->core : NULL;
	ssize_t ret = -EFAULT;

	if (!out) {
		ESDM_PROV_ERR(core, ESDM_R_INVALID_ARGUMENT,
			      "no output buffer provided for %zu bytes",
			      outlen);
		return 0;
	}

#ifdef ESDM_OSSL_PROV_FORCE_PR
	(void)prediction_resistance;
	esdm_invoke(esdm_rpcc_get_random_bytes_pr(out, outlen));
#else
	if (prediction_resistance) {
		esdm_invoke(esdm_rpcc_get_random_bytes_pr(out, outlen));
	} else {
		esdm_invoke(esdm_rpcc_get_random_bytes_full(out, outlen));
	}
#endif
	if (ret != (ssize_t)outlen)
		goto err;

	return 1;

err:
	ESDM_PROV_RPC_ERR(core, ret, outlen, "bytes of random data");

	/*
	 * The RPC may have partially filled out before failing. We return 0
	 * (failure) so OpenSSL must not consume out, but cleanse it anyway so no
	 * partial random data lingers in the caller's buffer.
	 */
	OPENSSL_cleanse(out, outlen);
	return 0;
}

static int
esdm_rand_reseed(void *ctx __unused, int prediction_resistance __unused,
		 const unsigned char *ent __unused, size_t ent_len __unused,
		 const unsigned char *addin __unused, size_t addin_len __unused)
{
	/* Do nothing here, reseeding is done by ESDM itself */

	return 1;
}

static size_t esdm_rand_nonce(void *ctx, unsigned char *out,
			      unsigned int strength __unused,
			      size_t min_noncelen, size_t max_noncelen __unused)
{
	struct esdm_rand_ctx *rand = ctx;
	const OSSL_CORE_HANDLE *core = rand ? rand->core : NULL;
	ssize_t ret = -EFAULT;

	/* A NULL output buffer only queries the nonce length. */
	if (out == NULL)
		return min_noncelen;

	esdm_invoke(esdm_rpcc_get_random_bytes_full(out, min_noncelen));

	if (ret == (ssize_t)min_noncelen)
		return min_noncelen;

	ESDM_PROV_RPC_ERR(core, ret, min_noncelen, "bytes of nonce data");
	OPENSSL_cleanse(out, min_noncelen);
	return 0;
}

static size_t esdm_rand_get_seed(void *ctx, unsigned char **buffer,
				 int entropy_bits, size_t min_len,
				 size_t max_len, int prediction_resistance,
				 const unsigned char *addin __unused,
				 size_t addin_len __unused)
{
	struct esdm_rand_ctx *rand = ctx;
	const OSSL_CORE_HANDLE *core = rand ? rand->core : NULL;
	size_t buf_len = 0;
	ssize_t ret = 0;

	*buffer = NULL;

	if (entropy_bits <= 0) {
		ESDM_PROV_ERR(core, ESDM_R_INVALID_ARGUMENT,
			      "non-positive entropy request of %i bits",
			      entropy_bits);
		return 0;
	}
	buf_len = ((size_t)entropy_bits + 7) / 8;

	/*
	 * OSSL_FUNC_rand_get_seed() has to hand back at least min_len bytes:
	 * the caller sizes its seed material by that, not by the entropy
	 * request. So round a smaller request up rather than failing - ESDM
	 * delivers full entropy, hence the additional bytes carry the requested
	 * entropy either way. Only a request exceeding max_len is unsatisfiable.
	 */
	if (buf_len < min_len)
		buf_len = min_len;
	if (buf_len > max_len) {
		ESDM_PROV_ERR(
			core, ESDM_R_SEED_LENGTH_UNSUPPORTED,
			"%i entropy bits require %zu bytes, but the caller accepts at most %zu",
			entropy_bits, buf_len, max_len);
		return 0;
	}

	*buffer = OPENSSL_secure_zalloc(buf_len);
	if (*buffer == NULL) {
		ESDM_PROV_ERR(core, ESDM_R_MALLOC_FAILURE,
			      "allocation of a %zu byte seed buffer failed",
			      buf_len);
		return 0;
	}
#ifdef ESDM_OSSL_PROV_FORCE_PR
	(void)prediction_resistance;
	esdm_invoke(esdm_rpcc_get_random_bytes_pr(*buffer, buf_len));
#else
	if (prediction_resistance) {
		esdm_invoke(esdm_rpcc_get_random_bytes_pr(*buffer, buf_len));
	} else {
		esdm_invoke(esdm_rpcc_get_random_bytes_full(*buffer, buf_len));
	}
#endif
	/*
	 * A short read would leave the tail of the buffer zeroed, which the
	 * caller would then consume as seed material - treat it as a failure.
	 */
	if (ret != (ssize_t)buf_len)
		goto err;

	return buf_len;

err:
	ESDM_PROV_RPC_ERR(core, ret, buf_len, "bytes of seed material");
	OPENSSL_secure_clear_free(*buffer, buf_len);
	*buffer = NULL;
	return 0;
}

static void esdm_rand_clear_seed(void *ctx __unused, unsigned char *buffer,
				 size_t b_len)
{
	OPENSSL_secure_clear_free(buffer, b_len);
}

static int esdm_rand_verify_zeroization(void *ctx __unused)
{
	return 1;
}

static int esdm_rand_enable_locking(void *ctx)
{
	struct esdm_rand_ctx *rand = ctx;

	if (rand == NULL)
		return 0;

	rand->lock = CRYPTO_THREAD_lock_new();
	if (rand->lock == NULL) {
		ESDM_PROV_ERR(rand->core, ESDM_R_LOCK_FAILURE,
			      "creation of the RNG context lock failed");
		return 0;
	}
	return 1;
}

static int esdm_rand_lock(void *ctx)
{
	struct esdm_rand_ctx *rand = ctx;

	if (rand == NULL || rand->lock == NULL)
		return 1;
	return CRYPTO_THREAD_write_lock(rand->lock);
}

static void esdm_rand_unlock(void *ctx)
{
	struct esdm_rand_ctx *rand = ctx;

	if (rand == NULL || rand->lock == NULL)
		return;
	CRYPTO_THREAD_unlock(rand->lock);
}

static const OSSL_PARAM *esdm_rand_gettable_ctx_params(void *ctx __unused,
						       void *provctx __unused)
{
	static const OSSL_PARAM known_gettable_ctx_params[] = {
		OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, 0),
		OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, 0),
		OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, 0), OSSL_PARAM_END
	};
	return known_gettable_ctx_params;
}

static int esdm_rand_get_ctx_params(void *ctx __unused, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	if (params == NULL)
		return 1;

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

const OSSL_DISPATCH esdm_rand_functions[] = {
	/* Context management */
	{ OSSL_FUNC_RAND_NEWCTX, (void (*)(void))esdm_rand_newctx },
	{ OSSL_FUNC_RAND_FREECTX, (void (*)(void))esdm_rand_freectx },
	/* Random number generator functions: NIST */
	{ OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))esdm_rand_instantiate },
	{ OSSL_FUNC_RAND_UNINSTANTIATE,
	  (void (*)(void))esdm_rand_uninstantiate },
	{ OSSL_FUNC_RAND_GENERATE, (void (*)(void))esdm_rand_generate },
	{ OSSL_FUNC_RAND_RESEED, (void (*)(void))esdm_rand_reseed },
	/* Random number generator functions: additional */
	{ OSSL_FUNC_RAND_NONCE, (void (*)(void))esdm_rand_nonce },
	{ OSSL_FUNC_RAND_GET_SEED, (void (*)(void))esdm_rand_get_seed },
	{ OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))esdm_rand_clear_seed },
	{ OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
	  (void (*)(void))esdm_rand_verify_zeroization },
	/* Context Locking */
	{ OSSL_FUNC_RAND_ENABLE_LOCKING,
	  (void (*)(void))esdm_rand_enable_locking },
	{ OSSL_FUNC_RAND_LOCK, (void (*)(void))esdm_rand_lock },
	{ OSSL_FUNC_RAND_UNLOCK, (void (*)(void))esdm_rand_unlock },
	/* RAND parameter descriptors */
	{ OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
	  (void (*)(void))esdm_rand_gettable_ctx_params },
	/* RAND parameters */
	{ OSSL_FUNC_RAND_GET_CTX_PARAMS,
	  (void (*)(void))esdm_rand_get_ctx_params },
	/* Delimiter */
	{ 0, NULL }
};

/******************************
 * General Provider functions *
 ******************************/

static const OSSL_PARAM *esdm_gettable_params(void *provctx __unused)
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

static int esdm_get_params(void *provctx __unused, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ESDM_PROV_NAME))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ESDM_PROV_VERSION))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ESDM_PROV_BUILDINFO))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
	if (p != NULL &&
	    !OSSL_PARAM_set_int(p, 1)) /* always in running state */
		return 0;

	return 1;
}

static const OSSL_ALGORITHM *
esdm_query_operation(void *provctx __unused, int operation_id, int *no_cache)
{
	*no_cache = 0;

	switch (operation_id) {
	case OSSL_OP_RAND:
		return esdm_rands;
	}

	return NULL;
}

static void esdm_unquery_operation(void *provctx __unused,
				   int operation_id __unused,
				   const OSSL_ALGORITHM *alg __unused)
{
}

static const OSSL_ITEM *esdm_get_reason_strings(void *provctx __unused)
{
	static const OSSL_ITEM reason_strings[] = {
		{ ESDM_R_INIT_FAILED, "ESDM provider initialization failed" },
		{ ESDM_R_MALLOC_FAILURE, "memory allocation failed" },
		{ ESDM_R_RPC_FAILURE,
		  "communication with the ESDM server failed - is esdm-server running and its RPC socket reachable?" },
		{ ESDM_R_SHORT_RANDOM_DATA,
		  "ESDM server delivered less data than requested" },
		{ ESDM_R_INVALID_ARGUMENT, "invalid argument" },
		{ ESDM_R_SEED_LENGTH_UNSUPPORTED,
		  "requested seed length cannot be satisfied" },
		{ ESDM_R_LOCK_FAILURE, "lock creation failed" },
		{ 0, NULL }
	};

	return reason_strings;
}

static int esdm_self_test(void *provctx)
{
	struct esdm_provider_ctx *cprov = provctx;
	int ret = -EFAULT;
	unsigned int ent_cnt;

	/* ESDM does self tests itself, just check if the connection to ESDM is
	* working*/
	esdm_invoke(esdm_rpcc_rnd_get_ent_cnt(&ent_cnt));
	if (ret) {
		ESDM_PROV_ERR(
			cprov ? cprov->core : NULL, ESDM_R_RPC_FAILURE,
			"self test: querying the ESDM entropy count failed: %s",
			strerror(ret < 0 ? -ret : ret));
		return 0;
	}

	return 1;
}

static void esdm_teardown(void *provctx)
{
	struct esdm_provider_ctx *cprov = provctx;

	OSSL_LIB_CTX_free(cprov->libctx);
	OPENSSL_secure_clear_free(cprov, sizeof(struct esdm_provider_ctx));
	esdm_rpcc_fini_unpriv_service();
}

static const OSSL_DISPATCH esdm_dispatch_table[] = {
	{ OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
	  (void (*)(void))esdm_gettable_params },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))esdm_get_params },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION,
	  (void (*)(void))esdm_query_operation },
	{ OSSL_FUNC_PROVIDER_UNQUERY_OPERATION,
	  (void (*)(void))esdm_unquery_operation },
	{ OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
	  (void (*)(void))esdm_get_reason_strings },
	{ OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))esdm_self_test },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))esdm_teardown },
	{ 0, NULL }
};

DSO_PUBLIC int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
				  const OSSL_DISPATCH *in,
				  const OSSL_DISPATCH **out, void **provctx)
{
	struct esdm_provider_ctx *cprov = NULL;

	/* Pick up the error reporting upcalls before anything can fail. */
	esdm_prov_init_error_reporting(in, handle);

	if ((cprov = OPENSSL_secure_zalloc(sizeof(struct esdm_provider_ctx))) ==
	    NULL) {
		ESDM_PROV_ERR(handle, ESDM_R_MALLOC_FAILURE,
			      "allocation of the provider context failed");
		return 0;
	}

	if (esdm_rpcc_init_unpriv_service(NULL) != 0) {
		ESDM_PROV_ERR(
			handle, ESDM_R_INIT_FAILED,
			"initialization of the unprivileged ESDM RPC client failed");
		goto err;
	}

	cprov->core = handle;
	if ((cprov->libctx = OSSL_LIB_CTX_new_child(handle, in)) == NULL) {
		ESDM_PROV_ERR(handle, ESDM_R_INIT_FAILED,
			      "creation of the child library context failed");
		goto err_fini;
	}

	*out = esdm_dispatch_table;
	*provctx = cprov;

	return 1;

	/*
	 * Only drop the RPC client reference if it was actually taken: the
	 * connection is reference counted and shared with everybody else in
	 * this process, so a fini for an init that never happened would tear it
	 * down under another user.
	 */
err_fini:
	esdm_rpcc_fini_unpriv_service();

err:
	OSSL_LIB_CTX_free(cprov->libctx);
	OPENSSL_secure_clear_free(cprov, sizeof(struct esdm_provider_ctx));

	return 0;
}
