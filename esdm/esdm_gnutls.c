/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <nettle/aes.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_crypto.h"
#include "esdm_gnutls.h"
#include "esdm_logger.h"

#define ESDM_GNUTLS_HASH GNUTLS_DIG_SHA512

static uint32_t esdm_gnutls_hash_digestsize(void *hash)
{
	(void)hash;
	return gnutls_hash_get_len(ESDM_GNUTLS_HASH);
}

static int esdm_gnutls_hash_init(void *hash)
{
	(void)hash;
	return 0;
}

static int esdm_gnutls_hash_update(void *hash, const uint8_t *inbuf,
				   size_t inbuflen)
{
	gnutls_hash_hd_t hd = (gnutls_hash_hd_t)hash;

	gnutls_hash(hd, inbuf, inbuflen);
	return 0;
}

static int esdm_gnutls_hash_final(void *hash, uint8_t *digest)
{
	gnutls_hash_hd_t hd = (gnutls_hash_hd_t)hash;

	gnutls_hash_output(hd, digest);
	return 0;
}

static int esdm_gnutls_hash_alloc(void **ctx)
{
	gnutls_hash_hd_t *hd = (gnutls_hash_hd_t *)ctx;

	gnutls_hash_init(hd, ESDM_GNUTLS_HASH);
	return 0;
}

static void esdm_gnutls_hash_dealloc(void *ctx)
{
	gnutls_hash_hd_t hd = (gnutls_hash_hd_t)ctx;

	if (hd)
		gnutls_hash_deinit(hd, NULL);
}

static const char *esdm_gnutls_hash_name(void)
{
	return "GnuTLS SHA-512";
}

static void esdm_gnutls_hash_desc_zero(void *hash)
{
	(void)hash;
}

static int esdm_gnutls_hash_selftest(void)
{
	void *hd = NULL;
	static const uint8_t msg_512[] = { 0x7F, 0xAD, 0x12 };
	static const uint8_t exp_512[] = {
		0x53, 0x35, 0x98, 0xe5, 0x29, 0x49, 0x18, 0xa0, 0xaf, 0x4b,
		0x3a, 0x62, 0x31, 0xcb, 0xd7, 0x19, 0x21, 0xdb, 0x80, 0xe1,
		0x00, 0xa0, 0x74, 0x95, 0xb4, 0x44, 0xc4, 0x7a, 0xdb, 0xbc,
		0x9a, 0x64, 0x76, 0xbb, 0xc8, 0xdb, 0x8e, 0xe3, 0x0c, 0x87,
		0x2f, 0x11, 0x35, 0xf1, 0x64, 0x65, 0x9c, 0x52, 0xce, 0xc7,
		0x7c, 0xcf, 0xb8, 0xc7, 0xd8, 0x57, 0x63, 0xda, 0xee, 0x07,
		0x9f, 0x60, 0x0c, 0x79
	};
	uint8_t act[sizeof(exp_512)];
	int ret = 0;

	esdm_gnutls_hash_alloc(&hd);
	esdm_gnutls_hash_update(hd, msg_512, 3);
	esdm_gnutls_hash_final(hd, act);
	esdm_gnutls_hash_dealloc(hd);
	if (memcmp(act, exp_512, sizeof(exp_512)))
		ret = -EFAULT;

	esdm_gnutls_hash_desc_zero(hd);
	return ret;
}

const struct esdm_hash_cb esdm_gnutls_hash_cb = {
	.hash_name = esdm_gnutls_hash_name,
	.hash_selftest = esdm_gnutls_hash_selftest,
	.hash_digestsize = esdm_gnutls_hash_digestsize,
	.hash_init = esdm_gnutls_hash_init,
	.hash_update = esdm_gnutls_hash_update,
	.hash_final = esdm_gnutls_hash_final,
	.hash_desc_zero = esdm_gnutls_hash_desc_zero,
	.hash_alloc = esdm_gnutls_hash_alloc,
	.hash_dealloc = esdm_gnutls_hash_dealloc,
};

struct drbg_aes_ctx {
	unsigned seeded;
	/* The current key */
	struct aes256_ctx key;

	uint8_t v[AES_BLOCK_SIZE];

	unsigned reseed_counter;
};

int drbg_aes_init(struct drbg_aes_ctx *ctx, unsigned entropy_size,
		  const uint8_t *entropy, unsigned pstring_size,
		  const uint8_t *pstring);

int drbg_aes_reseed(struct drbg_aes_ctx *ctx, unsigned entropy_size,
		    const uint8_t *entropy, unsigned add_size,
		    const uint8_t *add);

int drbg_aes_generate(struct drbg_aes_ctx *ctx, unsigned length, uint8_t *dst,
		      unsigned add_size, const uint8_t *add);

static int esdm_gnutls_drbg_seed(void *drng, const uint8_t *inbuf,
				 size_t inbuflen)
{
	struct drbg_aes_ctx *drbg = (struct drbg_aes_ctx *)drng;

	if (drbg->seeded)
		return drbg_aes_reseed(drbg, (unsigned int)inbuflen, inbuf, 0,
				       NULL) ?
			       0 :
			       -EFAULT;

	return drbg_aes_init(drbg, (unsigned int)inbuflen, inbuf, 0, NULL) ?
		       0 :
		       -EFAULT;
}

static ssize_t esdm_gnutls_drbg_generate(void *drng, uint8_t *outbuf,
					 size_t outbuflen)
{
	struct drbg_aes_ctx *drbg = (struct drbg_aes_ctx *)drng;

	return drbg_aes_generate(drbg, (unsigned int)outbuflen, outbuf, 0,
				 NULL) ?
		       (ssize_t)outbuflen :
		       -EFAULT;
}

static int esdm_gnutls_drbg_alloc(void **drng, uint32_t sec_strength)
{
	struct drbg_aes_ctx *drbg;

	(void)sec_strength;

	drbg = calloc(1, sizeof(*drbg));
	if (!drbg)
		return -ENOMEM;
	*drng = drbg;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "CTR DRBG core allocated\n");

	return 0;
}

static void esdm_gnutls_drbg_dealloc(void *drng)
{
	struct drbg_aes_ctx *drbg = (struct drbg_aes_ctx *)drng;

	if (!drbg)
		return;

	gnutls_memset(drbg, 0, sizeof(*drbg));
	free(drbg);
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "CTR DRBG core zeroized and freed\n");
}

static const char *esdm_gnutls_drbg_name(void)
{
	return "GnuTLS SP800-90A CTR DRBG";
}

static int esdm_gnutls_drbg_selftest(void)
{
	static const uint8_t ent_nonce[] = {
		0xEC, 0xFB, 0x79, 0x32, 0x62, 0x2E, 0x54, 0x5F, 0xF2, 0x32,
		0xED, 0xCB, 0x2F, 0x1B, 0x31, 0x3F, 0xB9, 0x8A, 0x16, 0x21,
		0xCF, 0xF3, 0x86, 0x95, 0xE7, 0x7C, 0xA0, 0x5B, 0xBC, 0x49,
		0x91, 0x5A, 0x5F, 0xDB, 0x56, 0x42, 0x5F, 0xA5, 0x7A, 0x49,
		0xC7, 0x7A, 0x0D, 0x06, 0x3C, 0x5B, 0x20, 0x21, 0x32, 0xA5,
		0xAA, 0x1A, 0x7F, 0xA7, 0x73, 0xA4, 0x81, 0x8D, 0xC5, 0x1D,
		0x08, 0xC0, 0x84, 0xEB
	};
	static const uint8_t pers[] = { 0xB4, 0xD8, 0xB2, 0x45, 0x58, 0x8B,
					0x9A, 0xA3, 0x7A, 0x9C, 0x81, 0x56,
					0x9D, 0xE4, 0x06, 0x8A, 0x1B, 0xB5,
					0x19, 0x72, 0x07, 0x5D, 0x56, 0x5E,
					0x6C, 0x93, 0xAB, 0x3B, 0x11, 0x20,
					0xEB, 0xF0 };
	static const uint8_t reseed_addtl[] = {
		0xFA, 0x9E, 0x7D, 0xF1, 0xEA, 0xE9, 0x45, 0x03,
		0xD5, 0x41, 0xCB, 0x77, 0x7C, 0xDA, 0xD1, 0x89,
		0xD0, 0x6F, 0x88, 0x0F, 0x60, 0x68, 0x5D, 0xD7,
		0x09, 0x62, 0x80, 0x8F, 0xCD, 0x5A, 0xC8, 0xF7
	};
	static const uint8_t reseed_ent[] = {
		0x0C, 0xD9, 0xFB, 0x97, 0x29, 0x4A, 0x3D, 0x98, 0x55, 0x2B,
		0x13, 0x78, 0x52, 0x43, 0xC3, 0x98, 0x3F, 0x32, 0xF9, 0x32,
		0xE9, 0xE4, 0x75, 0xF6, 0x35, 0xA6, 0x3B, 0x27, 0x82, 0x9A,
		0x2E, 0xE8, 0xBA, 0x1E, 0xBB, 0x40, 0x73, 0x10, 0xBB, 0xCA,
		0xA2, 0x72, 0xF4, 0xD6, 0x5E, 0x93, 0x7D, 0x45
	};
	static const uint8_t addtl1[] = { 0x5A, 0x18, 0x78, 0x96, 0x49, 0xCA,
					  0x84, 0x86, 0x2B, 0x94, 0x5D, 0x21,
					  0xC6, 0x9F, 0x7A, 0xCD, 0x10, 0x45,
					  0xCA, 0xAA, 0x1A, 0x7B, 0x3A, 0x61,
					  0x18, 0xB0, 0x64, 0x9F, 0x6A, 0xF2,
					  0xD8, 0x9B };
	static const uint8_t addtl2[] = { 0xE9, 0x82, 0x66, 0x9A, 0x1A, 0xE3,
					  0xC6, 0x43, 0x3E, 0xD9, 0xD7, 0xDD,
					  0x77, 0x1C, 0xD9, 0x00, 0x38, 0x2A,
					  0x26, 0x50, 0x3D, 0x1A, 0xC1, 0x20,
					  0x24, 0x30, 0x05, 0x96, 0x37, 0xC4,
					  0x6E, 0xBF };
	static const uint8_t exp[] = {
		0xc3, 0x5a, 0x3e, 0xbc, 0xef, 0x2a, 0x6d, 0x54, 0x91, 0x36,
		0x5a, 0xc7, 0xed, 0x6d, 0x06, 0xb0, 0xc1, 0x0f, 0x23, 0xbe,
		0x76, 0xb0, 0x43, 0x6b, 0x63, 0x31, 0x19, 0xc1, 0xc9, 0xf8,
		0x87, 0x76, 0xfd, 0x3f, 0xce, 0x52, 0x84, 0x6e, 0x15, 0x10,
		0x47, 0x7e, 0xaf, 0x65, 0x5b, 0xaf, 0x95, 0x3c, 0x8c, 0xdb,
		0x7a, 0xc6, 0xa3, 0xb8, 0x50, 0xc6, 0xa5, 0xdf, 0x63, 0x80,
		0xea, 0x74, 0xe3, 0xa5
	};
	uint8_t act[sizeof(exp)];
	struct drbg_aes_ctx drbg;
	int ret = -EFAULT;

	if (drbg_aes_init(&drbg, sizeof(ent_nonce), ent_nonce, sizeof(pers),
			  pers) == 0)
		goto out;

	if (drbg_aes_reseed(&drbg, sizeof(reseed_ent), reseed_ent,
			    sizeof(reseed_addtl), reseed_addtl) == 0)
		goto out;

	if (drbg_aes_generate(&drbg, sizeof(act), act, sizeof(addtl1),
			      addtl1) == 0)
		goto out;

	if (drbg_aes_generate(&drbg, sizeof(act), act, sizeof(addtl2),
			      addtl2) == 0)
		goto out;

	if (!memcmp(act, exp, sizeof(exp)))
		ret = 0;

out:
	return ret;
}

const struct esdm_drng_cb esdm_gnutls_drbg_cb = {
	.drng_name = esdm_gnutls_drbg_name,
	.drng_selftest = esdm_gnutls_drbg_selftest,
	.drng_alloc = esdm_gnutls_drbg_alloc,
	.drng_dealloc = esdm_gnutls_drbg_dealloc,
	.drng_seed = esdm_gnutls_drbg_seed,
	.drng_generate = esdm_gnutls_drbg_generate,
};
