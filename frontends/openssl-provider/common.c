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
#include <string.h>

#include "common.h"
#include "esdm_rpc_client.h"
#include "helper.h"
#include "math_helper.h"
#include "visibility.h"

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
		goto err;
	}

	rand->core = cprov->core;
	return rand;

err:
	OPENSSL_secure_clear_free(rand, sizeof(struct esdm_rand_ctx));
	return NULL;
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

static int esdm_rand_generate(void *ctx __unused, unsigned char *out,
			      size_t outlen, unsigned int strength __unused,
			      int prediction_resistance,
			      const unsigned char *addin __unused,
			      size_t addin_len __unused)
{
	ssize_t ret;

	if (!out)
		goto err;

	if (prediction_resistance) {
		esdm_invoke(esdm_rpcc_get_random_bytes_pr(out, outlen));
	} else {
		esdm_invoke(esdm_rpcc_get_random_bytes_full(out, outlen));
	}
	if (ret != (ssize_t)outlen)
		goto err;

	return 1;

err:
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

static size_t esdm_rand_nonce(void *ctx __unused, unsigned char *out,
			      unsigned int outlen, size_t min_noncelen __unused,
			      size_t max_noncelen __unused)
{
	ssize_t ret;

	if (out == NULL)
		return outlen;

	esdm_invoke(esdm_rpcc_get_random_bytes_min(out, outlen));

	if (ret == (ssize_t)outlen)
		return outlen;
	else
		return 0;
}

static size_t esdm_rand_get_seed(void *ctx __unused, unsigned char **buffer,
				 int entropy_bits, size_t min_len __unused,
				 size_t max_len __unused,
				 int prediction_resistance __unused,
				 const unsigned char *addin __unused,
				 size_t addin_len __unused)
{
#define ENTROPY_BUFFER_SIZE 2048
	struct esdm_seed_buffer {
		uint64_t len;
		uint64_t entropy_bits;
		/* should be large enough for entropy from all active sources */
		uint8_t buf[ENTROPY_BUFFER_SIZE];
	} __attribute__((__packed__));
	size_t seed_buffer_size = sizeof(struct esdm_seed_buffer);
	struct esdm_seed_buffer *seed_buffer = NULL;
	ssize_t ret;

	if (ENTROPY_BUFFER_SIZE < min_len)
		goto err;
	if (ENTROPY_BUFFER_SIZE >= max_len)
		goto err;

	seed_buffer = OPENSSL_secure_zalloc(ENTROPY_BUFFER_SIZE);
	esdm_invoke(esdm_rpcc_get_seed((uint8_t *)seed_buffer,
				       ENTROPY_BUFFER_SIZE, 0));
	if (ret <= 0)
		goto err;

	if (seed_buffer->entropy_bits < (uint64_t)entropy_bits)
		goto err;

	*buffer = OPENSSL_secure_zalloc(ENTROPY_BUFFER_SIZE);
	memcpy(*buffer, seed_buffer->buf, ENTROPY_BUFFER_SIZE);
	OPENSSL_secure_clear_free(seed_buffer, ENTROPY_BUFFER_SIZE);

	return ENTROPY_BUFFER_SIZE;

err:
	OPENSSL_secure_clear_free(seed_buffer, seed_buffer_size);
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

	rand->lock = CRYPTO_THREAD_lock_new();
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
	static const OSSL_ITEM reason_strings[] = { { 0, NULL } };

	return reason_strings;
}

static int esdm_self_test(void *provctx __unused)
{
	int ret;
	unsigned int ent_cnt;

	/* ESDM does self tests itself, just check if the connection to ESDM is
	* working*/
	esdm_invoke(esdm_rpcc_rnd_get_ent_cnt(&ent_cnt));

	return ret == 0;
}

static void esdm_teardown(void *provctx)
{
	struct esdm_provider_ctx *cprov = provctx;

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

	if ((cprov = OPENSSL_secure_zalloc(sizeof(struct esdm_provider_ctx))) ==
	    NULL)
		return 0;

	esdm_rpcc_init_unpriv_service(NULL);

	cprov->core = handle;
	if ((cprov->libctx = OSSL_LIB_CTX_new_child(handle, in)) == NULL)
		goto err;

	*out = esdm_dispatch_table;
	*provctx = cprov;

	return 1;

err:
	OSSL_LIB_CTX_free(cprov->libctx);
	OPENSSL_secure_clear_free(cprov, sizeof(struct esdm_provider_ctx));
	esdm_rpcc_fini_unpriv_service();

	return 0;
}
