/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include "memset_secure.h"

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
	int ret = gnutls_hash(hd, inbuf, inbuflen);

	/*
	 * gnutls_hash() can fail (e.g. with HW/PKCS#11-backed digests). Propagate
	 * the failure so the entropy framework does not credit/emit a digest
	 * computed over incompletely-absorbed input.
	 */
	if (ret < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "GnuTLS hash update failed: %s\n",
			    gnutls_strerror(ret));
		return -EFAULT;
	}
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
	int ret;

	ret = gnutls_hash_init(hd, ESDM_GNUTLS_HASH);
	if (ret < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "GnuTLS hash init failed: %s\n",
			    gnutls_strerror(ret));
		*hd = NULL;
		return -EFAULT;
	}
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
	int ret;

	ret = esdm_gnutls_hash_alloc(&hd);
	if (ret)
		return ret;

	esdm_gnutls_hash_update(hd, msg_512, 3);
	esdm_gnutls_hash_final(hd, act);
	esdm_gnutls_hash_desc_zero(hd);
	esdm_gnutls_hash_dealloc(hd);
	if (memcmp(act, exp_512, sizeof(exp_512)))
		ret = -EFAULT;
	else
		ret = 0;

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

#define DRBG_AES_KEY_SIZE AES256_KEY_SIZE
#define DRBG_AES_SEED_SIZE (AES_BLOCK_SIZE + DRBG_AES_KEY_SIZE)

static void esdm_gnutls_put_be32(uint8_t *out, uint32_t val)
{
	out[0] = (uint8_t)(val >> 24);
	out[1] = (uint8_t)(val >> 16);
	out[2] = (uint8_t)(val >> 8);
	out[3] = (uint8_t)val;
}

/*
 * SP800-90A 10.3.3 BCC - CBC-MAC of data (a whole number of blocks) under key.
 */
static void esdm_gnutls_bcc(const struct aes256_ctx *key, const uint8_t *data,
			    size_t datalen, uint8_t out[AES_BLOCK_SIZE])
{
	uint8_t block[AES_BLOCK_SIZE];
	size_t i, j;

	memset(out, 0, AES_BLOCK_SIZE);

	for (i = 0; i < datalen; i += AES_BLOCK_SIZE) {
		for (j = 0; j < AES_BLOCK_SIZE; j++)
			block[j] = out[j] ^ data[i + j];

		aes256_encrypt(key, AES_BLOCK_SIZE, out, block);
	}

	memset_secure(block, 0, sizeof(block));
}

/*
 * SP800-90A 10.3.2 Block_Cipher_df - condense arbitrary-length seed material
 * down to exactly the seed length the DRBG core takes.
 *
 * GnuTLS operates its CTR DRBG without a derivation function, so
 * drbg_aes_init()/drbg_aes_reseed() reject anything whose entropy_size is not
 * DRBG_AES_SEED_SIZE. ESDM on the other hand hands over whatever its entropy
 * sources produced, which varies with the enabled sources and their rates.
 * Deriving the seed here bridges the two.
 *
 * SP800-90A pairs a CTR DRBG with the block cipher based derivation function,
 * not with Hash_df - using the AES-256 core of the DRBG itself keeps this
 * backend a plain SP800-90A CTR_DRBG(AES-256, use df).
 *
 *	S = L || N || input_string || 0x80, zero padded to a block boundary
 *	temp = BCC(K, IV_i || S) for i = 0, 1, ... until keylen + outlen bytes
 *	K = leftmost keylen of temp, X = next outlen of temp
 *	repeatedly X = AES(K, X), collecting the requested number of bytes
 */
static int esdm_gnutls_block_cipher_df(const uint8_t *inbuf, size_t inbuflen,
				       const uint8_t *addtl, size_t addtllen,
				       uint8_t *out, size_t outlen)
{
	/* temp of step 9 - exactly one key plus one block */
	uint8_t temp[DRBG_AES_KEY_SIZE + AES_BLOCK_SIZE];
	uint8_t K[DRBG_AES_KEY_SIZE];
	uint8_t X[AES_BLOCK_SIZE];
	struct aes256_ctx key;
	size_t inputlen = inbuflen + addtllen;
	size_t slen, padded, done, i;
	uint8_t *buf, *S;
	int ret = 0;

	/* The caller only ever derives one seed, which is what temp holds. */
	if (!outlen || outlen > sizeof(temp))
		return -EINVAL;

	/* L || N || input || 0x80 */
	slen = 8 + inputlen + 1;
	padded =
		((slen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

	/* One leading block holds the IV that changes per BCC invocation. */
	buf = calloc(1, AES_BLOCK_SIZE + padded);
	if (!buf)
		return -ENOMEM;
	S = buf + AES_BLOCK_SIZE;

	esdm_gnutls_put_be32(S, (uint32_t)inputlen);
	esdm_gnutls_put_be32(S + 4, (uint32_t)outlen);
	if (inbuflen)
		memcpy(S + 8, inbuf, inbuflen);
	if (addtl && addtllen)
		memcpy(S + 8 + inbuflen, addtl, addtllen);
	S[8 + inputlen] = 0x80;
	/* the remaining padding is already zero from calloc() */

	/* K = 0x00 0x01 0x02 ... keylen-1 */
	for (i = 0; i < sizeof(K); i++)
		K[i] = (uint8_t)i;
	aes256_set_encrypt_key(&key, K);

	for (done = 0, i = 0; done < sizeof(temp);
	     done += AES_BLOCK_SIZE, i++) {
		/* IV = i as 32 bit big endian, zero padded to one block */
		memset(buf, 0, AES_BLOCK_SIZE);
		esdm_gnutls_put_be32(buf, (uint32_t)i);

		esdm_gnutls_bcc(&key, buf, AES_BLOCK_SIZE + padded,
				temp + done);
	}

	aes256_set_encrypt_key(&key, temp);
	memcpy(X, temp + DRBG_AES_KEY_SIZE, sizeof(X));

	for (done = 0; done < outlen;) {
		size_t todo = outlen - done;
		uint8_t next[AES_BLOCK_SIZE];

		if (todo > AES_BLOCK_SIZE)
			todo = AES_BLOCK_SIZE;

		aes256_encrypt(&key, AES_BLOCK_SIZE, next, X);
		memcpy(X, next, sizeof(X));
		memcpy(out + done, X, todo);
		done += todo;

		memset_secure(next, 0, sizeof(next));
	}

	memset_secure(buf, 0, AES_BLOCK_SIZE + padded);
	free(buf);
	memset_secure(temp, 0, sizeof(temp));
	memset_secure(K, 0, sizeof(K));
	memset_secure(X, 0, sizeof(X));
	memset_secure(&key, 0, sizeof(key));

	return ret;
}

static int esdm_gnutls_drbg_seed(void *drng, const uint8_t *inbuf,
				 size_t inbuflen, const uint8_t *addtl,
				 size_t addtllen)
{
	struct drbg_aes_ctx *drbg = (struct drbg_aes_ctx *)drng;
	uint8_t seed[DRBG_AES_SEED_SIZE];
	int ret;

	/*
	 * The additional input is folded into the same derivation rather than
	 * handed to the core separately: SP800-90A forms the seed material as
	 * entropy_input || additional_input and derives from that.
	 */
	ret = esdm_gnutls_block_cipher_df(inbuf, inbuflen, addtl, addtllen,
					  seed, sizeof(seed));
	if (ret)
		return ret;

	if (drbg->seeded)
		ret = drbg_aes_reseed(drbg, sizeof(seed), seed, 0, NULL) ?
			      0 :
			      -EFAULT;
	else
		ret = drbg_aes_init(drbg, sizeof(seed), seed, 0, NULL) ?
			      0 :
			      -EFAULT;

	memset_secure(seed, 0, sizeof(seed));

	return ret;
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
	/*
	 * NIST CAVP known answer test for CTR_DRBG(AES-256, use df), taken from
	 * drbgvectors_no_reseed/CTR_DRBG.rsp, [AES-256 use df] with
	 * PredictionResistance = False, PersonalizationStringLen = 0,
	 * AdditionalInputLen = 0 and ReturnedBitsLen = 512.
	 *
	 * The test covers the backend as it is actually used: the seed material
	 * (entropy_input || nonce) goes through esdm_gnutls_drbg_seed(), i.e.
	 * through Block_Cipher_df, into the GnuTLS CTR DRBG core, followed by
	 * two generate calls - CAVP compares the output of the second one.
	 *
	 * Covering the derivation function here is the point: a subtly wrong df
	 * still yields random looking output, so nothing but a known answer
	 * test over the whole composition detects it.
	 */
	static const struct {
		/* entropy_input || nonce; the personalization string is empty */
		uint8_t seed[DRBG_AES_SEED_SIZE];
		uint8_t exp[64];
	} kat[] = {
		/* CAVP COUNT = 0 */
		{ .seed = { 0x36, 0x40, 0x19, 0x40, 0xfa, 0x8b, 0x1f, 0xba,
			    0x91, 0xa1, 0x66, 0x1f, 0x21, 0x1d, 0x78, 0xa0,
			    0xb9, 0x38, 0x9a, 0x74, 0xe5, 0xbc, 0xcf, 0xec,
			    0xe8, 0xd7, 0x66, 0xaf, 0x1a, 0x6d, 0x3b, 0x14,
			    0x49, 0x6f, 0x25, 0xb0, 0xf1, 0x30, 0x1b, 0x4f,
			    0x50, 0x1b, 0xe3, 0x03, 0x80, 0xa1, 0x37, 0xeb },
		  .exp = { 0x58, 0x62, 0xeb, 0x38, 0xbd, 0x55, 0x8d, 0xd9,
			   0x78, 0xa6, 0x96, 0xe6, 0xdf, 0x16, 0x47, 0x82,
			   0xdd, 0xd8, 0x87, 0xe7, 0xe9, 0xa6, 0xc9, 0xf3,
			   0xf1, 0xfb, 0xaf, 0xb7, 0x89, 0x41, 0xb5, 0x35,
			   0xa6, 0x49, 0x12, 0xdf, 0xd2, 0x24, 0xc6, 0xdc,
			   0x74, 0x54, 0xe5, 0x25, 0x0b, 0x3d, 0x97, 0x16,
			   0x5e, 0x16, 0x26, 0x0c, 0x2f, 0xaf, 0x1c, 0xc7,
			   0x73, 0x5c, 0xb7, 0x5f, 0xb4, 0xf0, 0x7e, 0x1d } },
		/* CAVP COUNT = 1 */
		{ .seed = { 0x13, 0x19, 0x90, 0x90, 0xa4, 0x7f, 0xbd, 0x19,
			    0x84, 0xeb, 0x5f, 0xa9, 0x58, 0x93, 0x45, 0x15,
			    0x46, 0x99, 0xef, 0x73, 0xf0, 0x0c, 0xd6, 0x2b,
			    0x07, 0xc3, 0x41, 0x67, 0xc0, 0x32, 0x7e, 0x53,
			    0x5f, 0x96, 0x8f, 0x93, 0xb6, 0x59, 0xd8, 0xa5,
			    0x75, 0x0a, 0x95, 0x34, 0x5a, 0x8a, 0xe2, 0x0c },
		  .exp = { 0xd1, 0x68, 0x78, 0xc5, 0xb0, 0x6d, 0x7b, 0x6c,
			   0xed, 0x8e, 0x8a, 0xeb, 0x3a, 0x48, 0xd9, 0x5e,
			   0xc8, 0xdd, 0x65, 0x57, 0x33, 0xee, 0xc6, 0xef,
			   0x47, 0x3a, 0x80, 0x78, 0xdf, 0xde, 0xa6, 0x00,
			   0xc0, 0xcc, 0x02, 0x16, 0x8b, 0x4d, 0x6d, 0x74,
			   0x4e, 0xe8, 0x28, 0xba, 0x50, 0x31, 0x94, 0x1f,
			   0x8e, 0x3d, 0x96, 0x58, 0x64, 0x07, 0xaf, 0x79,
			   0xeb, 0xa6, 0x0d, 0x14, 0xaf, 0x47, 0xd5, 0x3a } },
		/* CAVP COUNT = 2 */
		{ .seed = { 0xd6, 0xcc, 0xf8, 0xc8, 0x14, 0x3a, 0xbf, 0xe5,
			    0xfd, 0x70, 0x62, 0x6a, 0xfc, 0x17, 0xf8, 0xae,
			    0xf1, 0x72, 0x02, 0x7c, 0x68, 0xc3, 0x8f, 0x94,
			    0xce, 0x59, 0xf7, 0xae, 0xd5, 0xe9, 0x66, 0x57,
			    0x2e, 0xbc, 0x66, 0xd2, 0xfd, 0x66, 0xb4, 0xbf,
			    0x1e, 0xd2, 0x4f, 0xaf, 0x74, 0x4f, 0xfb, 0xc9 },
		  .exp = { 0x6d, 0x47, 0x4b, 0xa9, 0x71, 0xa8, 0x33, 0x9e,
			   0xca, 0x90, 0x4a, 0x4c, 0x0d, 0xcf, 0x62, 0x65,
			   0x11, 0x6f, 0xbc, 0x66, 0xcb, 0xe5, 0xdd, 0xdf,
			   0xdc, 0x42, 0x10, 0x45, 0x02, 0xeb, 0x21, 0x0e,
			   0x36, 0x60, 0xe1, 0xb1, 0xb7, 0x10, 0xb9, 0x7d,
			   0x83, 0x0c, 0x27, 0x21, 0x2b, 0x33, 0x13, 0x1d,
			   0x85, 0xd2, 0xf7, 0x3f, 0x39, 0x76, 0x07, 0x82,
			   0xf4, 0xb4, 0x7d, 0x44, 0x7b, 0xa6, 0xa6, 0x8a } },
	};
	struct drbg_aes_ctx drbg;
	uint8_t act[64];
	size_t i;
	int ret = 0;

	for (i = 0; i < sizeof(kat) / sizeof(kat[0]); i++) {
		/* drng_seed() inspects ->seeded, so start from a clean state */
		memset(&drbg, 0, sizeof(drbg));

		if (esdm_gnutls_drbg_seed(&drbg, kat[i].seed,
					  sizeof(kat[i].seed), NULL, 0)) {
			ret = -EFAULT;
			goto out;
		}

		if (esdm_gnutls_drbg_generate(&drbg, act, sizeof(act)) !=
			    (ssize_t)sizeof(act) ||
		    esdm_gnutls_drbg_generate(&drbg, act, sizeof(act)) !=
			    (ssize_t)sizeof(act)) {
			ret = -EFAULT;
			goto out;
		}

		if (memcmp(act, kat[i].exp, sizeof(act))) {
			ret = -EFAULT;
			goto out;
		}
	}

out:
	memset_secure(&drbg, 0, sizeof(drbg));
	memset_secure(act, 0, sizeof(act));
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
