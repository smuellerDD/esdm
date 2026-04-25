/*
 * Copyright (C) 2023 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static int esdm_openssl_drbg_seed_internal(void *drng, const uint8_t *inbuf,
					   size_t inbuflen, bool test_mode)
{
	struct esdm_openssl_drng_state *state = drng;
	struct timespec current_time = { 0 };
	OSSL_PARAM params[3] = { 0 };
	int ret = 0;

	if (!state->seeded) {
		/*
		 * fetch time to use as nonce. Please note, that the nonce
		 * is only used to comply with the OpenSSL API.
		 * Use CLOCK_REALTIME here, as CLOCK_MONOTONIC is already used
		 * to construct the seed buffer.
		 */
		if (!test_mode) {
			ret = clock_gettime(CLOCK_REALTIME, &current_time);
			if (ret) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_MD,
					"Failed to get current time for DRBG nonce\n");
				ret = -EFAULT;
				goto out;
			}
		}

		/*
		 * TEST-RAND will return the full >= 384 of input entropy
		 * in TEST_ENTROPY when the DRBG is seeded. The nonce is
		 * not used to comply with the SP800-90C security argumentation,
		 * just to satisfy OpenSSL's API, which expects a non-zero
		 * nonce, as TEST-RAND declares to deliver nonces.
		 *
		 * Note: const is cast away due to OpenSSL's OSSL_PARAM API
		 * requiring void*. The buffer is not modified by OpenSSL.
		 */
		params[0] = OSSL_PARAM_construct_octet_string(
			OSSL_RAND_PARAM_TEST_ENTROPY, (void *)inbuf, inbuflen);
		params[1] = OSSL_PARAM_construct_octet_string(
			OSSL_RAND_PARAM_TEST_NONCE, (void *)&current_time,
			sizeof(current_time));
		params[2] = OSSL_PARAM_construct_end();

		if (!EVP_RAND_instantiate(state->seed_source, state->strength,
					  0, NULL, 0, params)) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to instantiate seed source: %s\n",
				    ERR_error_string(ERR_get_error(), NULL));
			ret = -EFAULT;
			goto out;
		}

		if (!EVP_RAND_instantiate(state->drbg, state->strength, 0,
					  (unsigned char *)"", 0, NULL)) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to instantiate DRBG: %s\n",
				    ERR_error_string(ERR_get_error(), NULL));
			EVP_RAND_uninstantiate(state->seed_source);
			ret = -EFAULT;
			goto out;
		}

		state->seeded = 1;
	} else {
		params[0] = OSSL_PARAM_construct_octet_string(
			OSSL_RAND_PARAM_TEST_ENTROPY, (void *)inbuf, inbuflen);
		params[1] = OSSL_PARAM_construct_end();

		if (!EVP_RAND_CTX_set_params(state->seed_source, params)) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to reseed seed source: %s\n",
				    ERR_error_string(ERR_get_error(), NULL));
			ret = -EFAULT;
			goto out;
		}

		if (!EVP_RAND_reseed(state->drbg, 0, NULL, 0, NULL, 0)) {
			esdm_logger(LOGGER_ERR, LOGGER_C_MD,
				    "Failed to reseed DRBG\n");
			ret = -EFAULT;
			goto out;
		}
	}

out:
	memset_secure(&current_time, 0, sizeof(current_time));
	return ret;
}

static int esdm_openssl_drbg_seed(void *drng, const uint8_t *inbuf,
				  size_t inbuflen)
{
	return esdm_openssl_drbg_seed_internal(drng, inbuf, inbuflen, false);
}

static ssize_t esdm_openssl_drbg_generate_w_additional_data(void *drng,
							    uint8_t *outbuf,
							    size_t outbuflen,
							    uint8_t *addbuf,
							    size_t addbuflen)
{
	struct esdm_openssl_drng_state *state = drng;

	if (outbuflen > SSIZE_MAX)
		return -EINVAL;

	if (!EVP_RAND_generate(state->drbg, outbuf, outbuflen, state->strength,
			       0, addbuf, addbuflen)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "Failed to generate random numbers\n");
		return -EFAULT;
	}

	return (ssize_t)outbuflen;
}

static ssize_t esdm_openssl_drbg_generate(void *drng, uint8_t *outbuf,
					  size_t outbuflen)
{
	uint8_t *addbuf = NULL;
	size_t addbuflen = 0;

#ifdef ESDM_OPENSSL_DRNG_HMAC
	struct timespec ts;
	ssize_t genret;

	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		return -errno;
	}

	/* always use additional data in order to perform additional mixing steps
	 * inside HMAC-DRBG (recommended by BSI AIS 20/31 V3.0, Sec. 5.3.2 Par. 1079) */
	addbuf = (uint8_t *)&ts;
	addbuflen = sizeof(ts);

	genret = esdm_openssl_drbg_generate_w_additional_data(
		drng, outbuf, outbuflen, addbuf, addbuflen);
	memset_secure(&ts, 0, sizeof(ts));
	return genret;
#else
	return esdm_openssl_drbg_generate_w_additional_data(
		drng, outbuf, outbuflen, addbuf, addbuflen);
#endif
}

static void
esdm_openssl_drbg_dealloc_internal(struct esdm_openssl_drng_state *state)
{
	if (!state) {
		return;
	}
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
	OSSL_PARAM params[5] = { 0 };
	struct esdm_openssl_drng_state *state =
		calloc(1, sizeof(struct esdm_openssl_drng_state));
	EVP_RAND *rand = NULL;
	/* use derivation function */
	int df = 1;
	/* disable count-based auto reseed */
	unsigned int reseed_requests = 0;
	/* disable time-based auto reseed  */
	time_t reseed_time = 0;
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

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
						     "AES-256-CTR", 11);
	params[1] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF, &df);
	params[2] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS,
					      &reseed_requests);
	params[3] = OSSL_PARAM_construct_time_t(
		OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, &reseed_time);
	params[4] = OSSL_PARAM_construct_end();
#endif

#ifdef ESDM_OPENSSL_DRNG_HASH
	(void)df;
	rand = EVP_RAND_fetch(NULL, "HASH-DRBG", NULL);
	CKNULL(rand, -ENOMEM);
	state->drbg = EVP_RAND_CTX_new(rand, state->seed_source);
	CKNULL(state->drbg, -ENOMEM);

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
						     "SHA512", 6);
	params[1] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS,
					      &reseed_requests);
	params[2] = OSSL_PARAM_construct_time_t(
		OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, &reseed_time);
	params[3] = OSSL_PARAM_construct_end();
#endif

#ifdef ESDM_OPENSSL_DRNG_HMAC
	(void)df;
	rand = EVP_RAND_fetch(NULL, "HMAC-DRBG", NULL);
	CKNULL(rand, -ENOMEM);
	state->drbg = EVP_RAND_CTX_new(rand, state->seed_source);
	CKNULL(state->drbg, -ENOMEM);

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
						     "SHA512", 6);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC,
						     "HMAC", 4);
	params[2] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_REQUESTS,
					      &reseed_requests);
	params[3] = OSSL_PARAM_construct_time_t(
		OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, &reseed_time);
	params[4] = OSSL_PARAM_construct_end();
#endif

	if (!EVP_RAND_CTX_set_params(state->drbg, params)) {
		ret = -EFAULT;
		goto out;
	}

	/* Read strength after set_params so it reflects the configured
	 * cipher/digest rather than OpenSSL's pre-configuration default. */
	state->strength = EVP_RAND_get_strength(state->drbg);
	if (!state->strength) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "DRBG reports zero strength after configuration\n");
		ret = -EFAULT;
		goto out;
	}

	*drng = state;
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "DRBG core allocated\n");

out:
	if (rand)
		EVP_RAND_free(rand);
	if (ret) {
		esdm_openssl_drbg_dealloc_internal(state);
		free(state);
	}

	return ret;
}

static void esdm_openssl_drbg_dealloc(void *drng)
{
	struct esdm_openssl_drng_state *state = drng;

	if (!state)
		return;

	esdm_openssl_drbg_dealloc_internal(state);

	memset_secure(state, 0, sizeof(*state));
	free(state);

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "DRBG core zeroized and freed\n");
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
		0xDD, 0xF8, 0xA9, 0x34, 0x3C, 0x95, 0xDC, 0x31, 0x96, 0xC7,
		0x5E, 0x79, 0xD8, 0x82, 0x41, 0x0C, 0x26, 0xA7, 0x5A, 0x57,
		0xD0, 0x5D, 0x2C, 0xAE, 0xE5, 0x2B, 0x28, 0xCB, 0x8F, 0xFE,
		0x1F, 0xF2, 0x3B, 0xA4, 0x0F, 0x94, 0xE0, 0x98, 0x45, 0x04,
		0x1B, 0xAB, 0x97, 0x16, 0x7C, 0x4B, 0xED, 0xD6, 0xFF, 0xFC,
		0x4B, 0x7B, 0x6E, 0x34, 0xA3, 0xB8, 0xE4, 0xF0, 0xF5, 0x25,
		0x8B, 0x8D, 0x1E, 0xBC, 0xA0, 0xEC, 0x2C, 0xEE, 0x1D, 0xC9,
		0x4C, 0x7E, 0x99, 0xDF, 0x5B, 0xA6, 0xB2, 0x57, 0x19, 0xF3,
		0xFC, 0x95, 0x53, 0x25, 0x8C, 0x8E, 0x7E, 0xBA, 0x11, 0xD5,
		0x83, 0x2C, 0xD9, 0x14, 0xDC, 0x54, 0xFF, 0x67, 0xD4, 0x39,
	};
#endif
#ifdef ESDM_OPENSSL_DRNG_HASH
	static const uint8_t exp[] = {
		0x23, 0xA5, 0x20, 0xF9, 0xDB, 0x6A, 0x4A, 0x1B, 0x81, 0x3F,
		0x71, 0xE0, 0x02, 0x53, 0x3B, 0x4F, 0x48, 0xE6, 0x0A, 0x35,
		0xC6, 0x56, 0x87, 0xD2, 0x42, 0xC2, 0x41, 0xC7, 0x7C, 0x2D,
		0x6B, 0x4D, 0xD9, 0x2C, 0x8B, 0x2D, 0xA2, 0xBA, 0x16, 0xF1,
		0xE1, 0x25, 0xE1, 0x89, 0xE7, 0x62, 0x63, 0xE8, 0xB8, 0xA2,
		0xD3, 0xD3, 0x9A, 0xC8, 0x23, 0xCA, 0x25, 0x18, 0x00, 0x4C,
		0xEE, 0xCD, 0xBE, 0xC0, 0x3C, 0x21, 0x64, 0xCC, 0x92, 0x24,
		0xED, 0xA6, 0x2C, 0x98, 0x6C, 0xF1, 0x93, 0xB8, 0x77, 0x5B,
		0xA2, 0x7E, 0x54, 0x89, 0xDF, 0x6A, 0x5D, 0x01, 0x03, 0x59,
		0x0C, 0xA1, 0x96, 0x7B, 0x8B, 0x8D, 0x36, 0x09, 0x58, 0x2C,
		0xA0, 0x5C, 0xD6, 0x3C, 0xCC, 0xA2, 0xD4, 0x2E, 0x05, 0x40,
	};
#endif
#ifdef ESDM_OPENSSL_DRNG_HMAC
	static const uint8_t exp[] = {
		0x8E, 0xAE, 0xE6, 0x5C, 0xD0, 0xD4, 0xB5, 0x85, 0x15, 0x53,
		0x0F, 0x7E, 0x62, 0x66, 0x10, 0xC7, 0x3A, 0x1E, 0x32, 0x6C,
		0x3F, 0xC4, 0x30, 0xB6, 0xF7, 0x21, 0x6D, 0x6C, 0x5C, 0xB3,
		0xEB, 0x3A, 0x3D, 0x59, 0xED, 0x1D, 0xC9, 0xE3, 0xF4, 0xDE,
		0x1D, 0x98, 0xFD, 0x0F, 0x2B, 0xE7, 0xDD, 0xD6, 0xDB, 0x2F,
		0xF3, 0x88, 0xC2, 0x0E, 0x1B, 0x54, 0xEA, 0xBD, 0x00, 0xEE,
		0x27, 0x69, 0x35, 0xD3, 0xD8, 0x63, 0x64, 0xBF, 0x27, 0xCC,
		0xDC, 0x09, 0x1F, 0x45, 0x72, 0x90, 0xD9, 0x1E, 0xE9, 0x4F,
		0xD9, 0x56, 0xAB, 0xD1, 0x29, 0x1B, 0x3A, 0x5B, 0xAD, 0x18,
		0x87, 0x3B, 0xD7, 0x69, 0x21, 0x58, 0x2E, 0x91, 0x40, 0xB9,
		0x81, 0x97, 0x4B, 0x6F, 0xC5, 0xDB, 0xDE, 0x1B, 0x99, 0x51,
	};
#endif
	uint8_t act[sizeof(exp)];
	void *drng = NULL;
	int ret;

	CKINT(esdm_openssl_drbg_alloc(&drng, 256));
	CKINT(esdm_openssl_drbg_seed_internal(drng, ent_nonce,
					      sizeof(ent_nonce), true));
	CKINT(esdm_openssl_drbg_seed_internal(drng, reseed, sizeof(reseed),
					      true));
	if (esdm_openssl_drbg_generate_w_additional_data(
		    drng, act, sizeof(act), NULL, 0) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	if (esdm_openssl_drbg_generate_w_additional_data(
		    drng, act, sizeof(act), NULL, 0) != sizeof(act)) {
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
