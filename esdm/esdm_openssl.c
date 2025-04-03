/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>

#include "config.h"
#include "bool.h"
#include "esdm_crypto.h"
#include "esdm_openssl.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "ret_checkers.h"

#define ESDM_OPENSSL_HASH (EVP_sha3_512())

static uint32_t esdm_openssl_hash_digestsize(void *hash)
{
	(void)hash;
	return (uint32_t)EVP_MD_size(ESDM_OPENSSL_HASH);
}

static int esdm_openssl_hash_init(void *hash)
{
	EVP_MD_CTX *ctx = hash;
	int ret = EVP_DigestInit(ctx, ESDM_OPENSSL_HASH);

	if (ret != 1) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "EVP_DigestInit() failed %s\n",
			    ERR_error_string(ERR_get_error(), NULL));
		return -EFAULT;
	}

	return 0;
}

static int esdm_openssl_hash_update(void *hash, const uint8_t *inbuf,
				    size_t inbuflen)
{
	EVP_MD_CTX *ctx = hash;
	int ret = EVP_DigestUpdate(ctx, inbuf, inbuflen);

	if (ret != 1) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "EVP_DigestUpdate() failed %s\n",
			    ERR_error_string(ERR_get_error(), NULL));
		return -EFAULT;
	}

	return 0;
}

static int esdm_openssl_hash_final(void *hash, uint8_t *digest)
{
	EVP_MD_CTX *ctx = hash;
	unsigned int maclen = 0;
	int ret = EVP_DigestFinal(ctx, digest, &maclen);

	if (ret != 1 || maclen != esdm_openssl_hash_digestsize(hash)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "EVP_DigestFinal() failed %s\n",
			    ERR_error_string(ERR_get_error(), NULL));
		return -EFAULT;
	}

	return 0;
}

static int esdm_openssl_hash_alloc(void **hash)
{
	EVP_MD_CTX *tmp, **ctx = (EVP_MD_CTX **)hash;

	tmp = EVP_MD_CTX_create();
	if (!tmp)
		return -ENOMEM;

	*ctx = tmp;

	return 0;
}

static void esdm_openssl_hash_dealloc(void *hash)
{
	EVP_MD_CTX *ctx = hash;

	if (ctx)
		EVP_MD_CTX_destroy(ctx);
}

static const char *esdm_openssl_hash_name(void)
{
	return "OpenSSL SHA3-512";
}

static void esdm_openssl_hash_desc_zero(void *hash)
{
	(void)hash;
}

static int esdm_openssl_hash_selftest(void)
{
	static const uint8_t msg_512[] = { 0x82, 0xD9, 0x19 };
	static const uint8_t exp_512[] = {
		0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5, 0x0A, 0x67, 0xFE, 0x69,
		0xBD, 0x3F, 0xCE, 0xFE, 0x12, 0xE7, 0x1D, 0xE0, 0x4F, 0xA2,
		0x51, 0xC6, 0x7E, 0x9C, 0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC,
		0x89, 0xCA, 0x9B, 0x28, 0x88, 0x3B, 0x2A, 0xDB, 0x22, 0x84,
		0x69, 0x5D, 0xD0, 0x43, 0x77, 0x55, 0x32, 0x19, 0xC8, 0xFD,
		0x07, 0xA9, 0x4C, 0x29, 0xD7, 0x46, 0xCC, 0xEF, 0xB1, 0x09,
		0x6E, 0xDE, 0x42, 0x91
	};
	uint8_t act[sizeof(exp_512)];
	void *hash = NULL;
	int ret;

	CKINT(esdm_openssl_hash_alloc(&hash));
	CKINT(esdm_openssl_hash_init(hash));
	CKINT(esdm_openssl_hash_update(hash, msg_512, sizeof(msg_512)));
	CKINT(esdm_openssl_hash_final(hash, act));

	if (memcmp(act, exp_512, sizeof(exp_512)))
		ret = -EFAULT;

out:
	esdm_openssl_hash_dealloc(hash);
	return ret;
}

const struct esdm_hash_cb esdm_openssl_hash_cb = {
	.hash_name = esdm_openssl_hash_name,
	.hash_selftest = esdm_openssl_hash_selftest,
	.hash_digestsize = esdm_openssl_hash_digestsize,
	.hash_init = esdm_openssl_hash_init,
	.hash_update = esdm_openssl_hash_update,
	.hash_final = esdm_openssl_hash_final,
	.hash_desc_zero = esdm_openssl_hash_desc_zero,
	.hash_alloc = esdm_openssl_hash_alloc,
	.hash_dealloc = esdm_openssl_hash_dealloc,
};

struct esdm_openssl_drng_state {
	EVP_RAND_CTX *drbg, *seed_source;
	unsigned int strength;
	int seeded;
};

static int esdm_openssl_drbg_derive_seed_nonce(const uint8_t *inbuf,
					       size_t inbuflen,
					       uint8_t **entropy_buf,
					       bool need_nonce,
					       uint8_t **nonce_buf)
{
	const char *dom_sep_nonce = "NONCE";
	const char *dom_sep_seed = "SEED0";

	/*
	 * Use simple derivation fn in order to have enough length with only
	 * the aux entropy source. OpenSSL needs at least 48 Byte for initial
	 * seeding in the test entropy.
	 *
	 * Always perform this step in order to make things easier to analyze.
	 * TEST_ENTROPY = SHA3-512("SEED0"||inbuf)
	 * TEST_NONCE   = SHA3-512("NONCE"||inbuf)
	 */
	void *hash = NULL;
	int ret;

	/*
	 * entropy in
	 */
	CKINT(esdm_openssl_hash_alloc(&hash));
	CKINT(esdm_openssl_hash_init(hash));
	CKINT(esdm_openssl_hash_update(hash, (const uint8_t *)dom_sep_seed, 5));
	CKINT(esdm_openssl_hash_update(hash, inbuf, inbuflen));

	/*
	 * we need to allocate these buffers on the heap, as OpenSSL frees them
	 * when setting new test entropy the next time.
	 */
	*entropy_buf = OPENSSL_zalloc(esdm_openssl_hash_digestsize(hash));
	CKINT(esdm_openssl_hash_final(hash, *entropy_buf));

	if (!need_nonce)
		goto out;
	esdm_openssl_hash_dealloc(hash);

	/*
	 * nonce in
	 */
	CKINT(esdm_openssl_hash_alloc(&hash));
	CKINT(esdm_openssl_hash_init(hash));
	CKINT(esdm_openssl_hash_update(hash, (const uint8_t *)dom_sep_nonce,
				       5));
	CKINT(esdm_openssl_hash_update(hash, inbuf, inbuflen));
	/*
	 * we need to allocate these buffers on the heap, as OpenSSL frees them
	 * when setting new test entropy the next time.
	 */
	*nonce_buf = OPENSSL_zalloc(esdm_openssl_hash_digestsize(hash));
	CKINT(esdm_openssl_hash_final(hash, *nonce_buf));

out:
	if (ret) {
		OPENSSL_free(*entropy_buf);
		OPENSSL_free(*nonce_buf);
		*entropy_buf = NULL;
		*nonce_buf = NULL;
	}

	esdm_openssl_hash_dealloc(hash);
	return ret;
}

static int esdm_openssl_drbg_seed(void *drng, const uint8_t *inbuf,
				  size_t inbuflen)
{
	OSSL_PARAM params[3] = { 0 };
	struct esdm_openssl_drng_state *state = drng;
	uint8_t *entropy_buf = NULL;
	uint8_t *nonce_buf = NULL;
	bool free_buffers = false;
	int ret = 0;

	if (!state->seeded) {
		if (esdm_openssl_drbg_derive_seed_nonce(
			    inbuf, inbuflen, &entropy_buf, !state->seeded,
			    &nonce_buf) != 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to derive seed material: %s\n",
				    ERR_error_string(ERR_get_error(), NULL));
			ret = -EFAULT;
			goto out;
		};
		free_buffers = true;
		params[0] = OSSL_PARAM_construct_octet_string(
			OSSL_RAND_PARAM_TEST_ENTROPY, (void *)entropy_buf,
			(size_t)EVP_MD_size(ESDM_OPENSSL_HASH));
		params[1] = OSSL_PARAM_construct_octet_string(
			OSSL_RAND_PARAM_TEST_NONCE, (void *)nonce_buf,
			(size_t)EVP_MD_size(ESDM_OPENSSL_HASH));
		params[2] = OSSL_PARAM_construct_end();

		if (!EVP_RAND_instantiate(state->seed_source, state->strength,
					  0, NULL, 0, params)) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to instantiate seed source: %s\n",
				    ERR_error_string(ERR_get_error(), NULL));
			ret = -EFAULT;
			goto out;
		}
		free_buffers = false;

		if (!EVP_RAND_instantiate(state->drbg, state->strength, 0,
					  (unsigned char *)"", 0, NULL)) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to instantiate DRBG: %s\n",
				    ERR_error_string(ERR_get_error(), NULL));
			ret = -EFAULT;
			goto out;
		}

		state->seeded = 1;
	} else {
		entropy_buf = calloc(1, inbuflen);
		if (entropy_buf == NULL) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to copy entropy buffer for DRBG\n");
			ret = -EFAULT;
			goto out;
		}
		memcpy(entropy_buf, inbuf, inbuflen);
		free_buffers = true;

		params[0] = OSSL_PARAM_construct_octet_string(
			OSSL_RAND_PARAM_TEST_ENTROPY, (void *)entropy_buf,
			inbuflen);
		params[1] = OSSL_PARAM_construct_end();

		if (!EVP_RAND_CTX_set_params(state->seed_source, params)) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to reseed seed source: %s\n",
				    ERR_error_string(ERR_get_error(), NULL));
			ret = -EFAULT;
			goto out;
		}
		free_buffers = false;

		if (!EVP_RAND_reseed(state->drbg, 0, NULL, 0, NULL, 0)) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to reseed DRBG\n");
			ret = -EFAULT;
			goto out;
		}
	}

out:
	if (free_buffers) {
		OPENSSL_free(entropy_buf);
		entropy_buf = NULL;
		OPENSSL_free(nonce_buf);
		nonce_buf = NULL;
	}

	return ret;
}

static ssize_t esdm_openssl_drbg_generate(void *drng, uint8_t *outbuf,
					  size_t outbuflen)
{
	struct esdm_openssl_drng_state *state = drng;

	if (!EVP_RAND_generate(state->drbg, outbuf, outbuflen, state->strength,
			       0, NULL, 0)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "Failed to generate random numbers\n");
		return -EFAULT;
	}

	return (ssize_t)outbuflen;
}

static void
esdm_openssl_drbg_dealloc_internal(struct esdm_openssl_drng_state *state)
{
	if (!state)
		return;

	if (state->drbg) {
		EVP_RAND_uninstantiate(state->drbg);
		EVP_RAND_CTX_free(state->drbg);
	}
	if (state->seed_source) {
		EVP_RAND_uninstantiate(state->seed_source);
		EVP_RAND_CTX_free(state->seed_source);
	}
}

static int esdm_openssl_drbg_alloc(void **drng, uint32_t sec_strength)
{
	OSSL_PARAM params[4];
	struct esdm_openssl_drng_state *state =
		calloc(1, sizeof(struct esdm_openssl_drng_state));
	EVP_RAND *rand = NULL;
	int df = 1;
	int ret = 0;

	(void)sec_strength;

	if (!state)
		return -ENOMEM;

	state->strength = 256;

	rand = EVP_RAND_fetch(NULL, "TEST-RAND", "-fips");
	CKNULL(rand, -ENOMEM);

	state->seed_source = EVP_RAND_CTX_new(rand, NULL);
	CKNULL(state->seed_source, -ENOMEM);
	EVP_RAND_free(rand);
	rand = NULL;

	params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH,
					      &state->strength);
	params[1] = OSSL_PARAM_construct_end();
	if (!EVP_RAND_CTX_set_params(state->seed_source, params)) {
		ret = -EFAULT;
		goto out;
	}

#ifdef ESDM_OPENSSL_DRNG_CTR
	rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
	CKNULL(rand, -ENOMEM);
	state->drbg = EVP_RAND_CTX_new(rand, state->seed_source);
	CKNULL(state->drbg, -ENOMEM);
	state->strength = EVP_RAND_get_strength(state->drbg);

	params[0] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &df);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
						     "AES-256-CTR", 11);
	params[2] = OSSL_PARAM_construct_end();
#endif

#ifdef ESDM_OPENSSL_DRNG_HASH
	rand = EVP_RAND_fetch(NULL, "HASH-DRBG", NULL);
	CKNULL(rand, -ENOMEM);
	state->drbg = EVP_RAND_CTX_new(rand, state->seed_source);
	CKNULL(state->drbg, -ENOMEM);
	state->strength = EVP_RAND_get_strength(state->drbg);

	params[0] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &df);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
						     "SHA512", 6);
	params[2] = OSSL_PARAM_construct_end();
#endif

#ifdef ESDM_OPENSSL_DRNG_HMAC
	rand = EVP_RAND_fetch(NULL, "HMAC-DRBG", NULL);
	CKNULL(rand, -ENOMEM);
	state->drbg = EVP_RAND_CTX_new(rand, state->seed_source);
	CKNULL(state->drbg, -ENOMEM);
	state->strength = EVP_RAND_get_strength(state->drbg);

	params[0] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &df);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
						     "SHA512", 6);
	params[2] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC,
						     "HMAC", 4);
	params[3] = OSSL_PARAM_construct_end();
#endif

	if (!EVP_RAND_CTX_set_params(state->drbg, params)) {
		ret = -EFAULT;
		goto out;
	}

	*drng = state;
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "DRBG core allocated\n");

out:
	if (rand)
		EVP_RAND_free(rand);
	if (ret)
		esdm_openssl_drbg_dealloc_internal(state);

	return ret;
}

static void esdm_openssl_drbg_dealloc(void *drng)
{
	struct esdm_openssl_drng_state *state = drng;

	esdm_openssl_drbg_dealloc_internal(state);

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "DRBG core zeroized and freed\n");

	free(state);
}

static const char *esdm_openssl_drbg_name(void)
{
#ifdef ESDM_OPENSSL_DRNG_CTR
	return "OpenSSL SP800-90A CTR-DRBG";
#endif
#ifdef ESDM_OPENSSL_DRNG_HASH
	return "OpenSSL SP800-90A HASH-DRBG";
#endif
#ifdef ESDM_OPENSSL_DRNG_HMAC
	return "OpenSSL SP800-90A HMAC-DRBG";
#endif

#if !defined(ESDM_OPENSSL_DRNG_CTR) && !defined(ESDM_OPENSSL_DRNG_HASH) &&     \
	!defined(ESDM_OPENSSL_DRNG_HMAC)
#error "Specify at least on OpenSSL DRBG type!"
#endif
}

static int esdm_openssl_drbg_selftest(void)
{
	static const uint8_t ent_nonce[] = {
		0xDD, 0x3D, 0xC1, 0x24, 0x6B, 0xD1, 0xD5, 0xF1, 0xAA, 0xF7,
		0xAA, 0xF2, 0xD5, 0xA8, 0x6D, 0x94, 0xA4, 0xE1, 0xF7, 0x0C,
		0x20, 0x7D, 0x75, 0xE3, 0x23, 0x44, 0x29, 0x64, 0xD4, 0xDF,
		0xDC, 0xE8, 0x22, 0xFF, 0xD9, 0x57, 0x8E, 0xE3, 0x35, 0xE5,
		0x3E, 0x5D, 0x76, 0x36, 0x41, 0x32, 0x37, 0x8B, 0xE3, 0x7F,
		0x7A, 0xE2, 0x40, 0x09, 0x4B, 0xF9, 0xCC, 0x9A, 0xAD, 0x74,
		0xA5, 0x21, 0x4F, 0xE4
	};
	static const uint8_t reseed[] = { 0x4F, 0x4C, 0xDE, 0xAE, 0xC6, 0xDC,
					  0x6D, 0xDB, 0x8B, 0x9B, 0x5F, 0xB6,
					  0xED, 0x6F, 0x3E, 0xF5, 0xFE, 0x82,
					  0x54, 0x82, 0x09, 0x9F, 0x31, 0xBC,
					  0xEC, 0x88, 0x01, 0xD8, 0xAD, 0x61,
					  0x8C, 0x0A };
#ifdef ESDM_OPENSSL_DRNG_CTR
	static const uint8_t exp[] = {
		0xbf, 0x24, 0xc9, 0x5b, 0x22, 0x15, 0x9a, 0x44, 0xc0, 0x1e,
		0x9f, 0xf2, 0x2e, 0x9d, 0x04, 0x24, 0xba, 0x52, 0x06, 0xbb,
		0xa5, 0x41, 0x14, 0x71, 0x06, 0x07, 0xc5, 0xd4, 0x9d, 0x21,
		0x0f, 0x18, 0xf6, 0x37, 0xcc, 0xc7, 0xdb, 0xce, 0x63, 0xc6,
		0x46, 0xf9, 0x1d, 0x38, 0x66, 0x08, 0x72, 0x8a, 0x34, 0x88,
		0xd1, 0x4e, 0x38, 0xc0, 0x42, 0xe7, 0x6f, 0xc7, 0x2e, 0x24,
		0xe4, 0x1b, 0xad, 0x62, 0x1c, 0x0b, 0x46, 0xde, 0x33, 0x7b,
		0x30, 0xe6, 0x5c, 0xf1, 0x10, 0xfc, 0x82, 0x02, 0xa9, 0x4a,
		0x94, 0xe9, 0xa9, 0xe4, 0x0e, 0x33, 0x52, 0xf6, 0x71, 0x53,
		0x1d, 0x29, 0xfe, 0xee, 0x64, 0xc7, 0x4e, 0x22, 0x9f, 0x21,
		0x21, 0xe6, 0x0c, 0x0b, 0x57, 0x50, 0x50, 0xa2, 0x51, 0x7a,
		0x32, 0xcf, 0x39, 0xfa, 0x49, 0x5e, 0xe0, 0xce, 0x28, 0x8e,
	};
#endif
#ifdef ESDM_OPENSSL_DRNG_HASH
	static const uint8_t exp[] = {
		0x9d, 0x58, 0x4e, 0xd2, 0xfc, 0xb7, 0x7c, 0xfc, 0x8a, 0x1e,
		0x2d, 0x08, 0x5a, 0x91, 0x4e, 0xd5, 0x8f, 0xa7, 0xc7, 0x46,
		0x1b, 0xd9, 0x45, 0xb8, 0x00, 0x0d, 0x9c, 0x18, 0x7d, 0x6e,
		0xd8, 0xae, 0x98, 0x19, 0x19, 0x55, 0xf7, 0x9f, 0xec, 0x14,
		0x4f, 0x3a, 0x5d, 0x59, 0xd8, 0xf8, 0x15, 0x2a, 0x2d, 0x08,
		0xdd, 0x7a, 0xe9, 0x90, 0x94, 0x1e, 0xc8, 0x29, 0x74, 0x29,
		0xa7, 0x4f, 0xeb, 0xcb, 0x2b, 0x87, 0xa1, 0xea, 0xbd, 0xee,
		0x5e, 0xad, 0xe2, 0xcb, 0x4f, 0x16, 0x79, 0x35, 0x91, 0xa5,
		0x4e, 0xf0, 0xe8, 0xda, 0x60, 0xda, 0x1c, 0xd1, 0xc3, 0x26,
		0xfe, 0xf3, 0xc2, 0x25, 0x9b, 0xb5, 0x4d, 0xe3, 0x42, 0x4b,
		0xd4, 0xdc, 0x3c, 0x61, 0xe4, 0x2f, 0xdf, 0x32, 0x59, 0x30,
		0x0d, 0x0b, 0xa2, 0x23, 0x88, 0xd4, 0xbd, 0xec, 0x8d, 0xc2,
	};
#endif
#ifdef ESDM_OPENSSL_DRNG_HMAC
	static const uint8_t exp[] = {
		0xf7, 0x67, 0xcc, 0x8b, 0xc6, 0x7c, 0x79, 0x4b, 0xe1, 0x61,
		0xb0, 0x6e, 0x84, 0x27, 0xfa, 0x43, 0x81, 0xc6, 0x7b, 0x44,
		0xe6, 0x2d, 0x0b, 0xc8, 0x04, 0x0b, 0x9c, 0xfb, 0x1e, 0xa1,
		0xd8, 0x56, 0xe8, 0xfb, 0x44, 0x36, 0xb4, 0xe8, 0x61, 0xde,
		0x32, 0xd0, 0x08, 0xed, 0x68, 0x3c, 0xde, 0xea, 0x74, 0x35,
		0xde, 0x31, 0x45, 0x9e, 0x09, 0xa1, 0xf6, 0xff, 0xcd, 0xae,
		0x4e, 0x22, 0xc2, 0x98, 0x56, 0xf7, 0xc7, 0xfd, 0xea, 0x58,
		0x67, 0x72, 0xbb, 0xc6, 0x20, 0x6b, 0xa6, 0x30, 0x36, 0x65,
		0x6d, 0x5d, 0x8e, 0x66, 0xfc, 0x27, 0x0b, 0xe7, 0xe1, 0x36,
		0x07, 0x58, 0xdc, 0xdf, 0x33, 0xca, 0x5f, 0x69, 0xdf, 0x88,
		0x78, 0x91, 0xa5, 0x32, 0x29, 0x28, 0x95, 0xb3, 0xf0, 0x60,
		0xea, 0xe2, 0x84, 0xb3, 0x44, 0x14, 0x08, 0x9b, 0x59, 0xa3,
	};
#endif
	uint8_t act[sizeof(exp)];
	void *drng = NULL;
	int ret;

	CKINT(esdm_openssl_drbg_alloc(&drng, 256));
	CKINT(esdm_openssl_drbg_seed(drng, ent_nonce, sizeof(ent_nonce)));
	CKINT(esdm_openssl_drbg_seed(drng, reseed, sizeof(reseed)));
	if (esdm_openssl_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	if (esdm_openssl_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	if (memcmp(act, exp, sizeof(exp))) {
		ret = -EFAULT;
	}

out:
	esdm_openssl_drbg_dealloc(drng);
	return ret;
}

const struct esdm_drng_cb esdm_openssl_drbg_cb = {
	.drng_name = esdm_openssl_drbg_name,
	.drng_selftest = esdm_openssl_drbg_selftest,
	.drng_alloc = esdm_openssl_drbg_alloc,
	.drng_dealloc = esdm_openssl_drbg_dealloc,
	.drng_seed = esdm_openssl_drbg_seed,
	.drng_generate = esdm_openssl_drbg_generate,
};
