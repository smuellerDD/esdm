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
#include "selftest_kat.h"

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
	uint8_t mod[sizeof(msg_512)];
	int ret;

	ret = esdm_gnutls_hash_alloc(&hd);
	if (ret)
		return ret;

	esdm_gnutls_hash_update(hd, msg_512, sizeof(msg_512));
	esdm_gnutls_hash_final(hd, act);
	esdm_gnutls_hash_desc_zero(hd);
	esdm_gnutls_hash_dealloc(hd);

	ret = esdm_kat_check(act, exp_512, sizeof(exp_512));
	if (ret)
		return ret;

	/* A message off by its first byte must not produce that digest */
	ret = esdm_kat_modify(mod, msg_512, sizeof(mod));
	if (ret)
		return ret;

	ret = esdm_gnutls_hash_alloc(&hd);
	if (ret)
		return ret;

	esdm_gnutls_hash_update(hd, mod, sizeof(mod));
	esdm_gnutls_hash_final(hd, act);
	esdm_gnutls_hash_desc_zero(hd);
	esdm_gnutls_hash_dealloc(hd);

	return esdm_kat_check_differs(act, exp_512, sizeof(exp_512));
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
 * drbg_aes_init()/drbg_aes_reseed() reject any entropy_size other than
 * DRBG_AES_SEED_SIZE, while ESDM hands over whatever its entropy sources
 * produced. SP800-90A pairs a CTR DRBG with the block cipher based derivation
 * function rather than Hash_df, so using the DRBG's own AES-256 core keeps this
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

/* Instantiate, reseed, generate twice - the sweep of the records below */
static int esdm_gnutls_drbg_kat(struct drbg_aes_ctx *drbg, const uint8_t *seed,
				size_t seedlen, const uint8_t *reseed,
				size_t reseedlen, uint8_t *act, size_t actlen)
{
	/* drng_seed() inspects ->seeded, so start from a clean state */
	memset(drbg, 0, sizeof(*drbg));

	if (esdm_gnutls_drbg_seed(drbg, seed, seedlen, NULL, 0))
		return -EFAULT;

	if (esdm_gnutls_drbg_seed(drbg, reseed, reseedlen, NULL, 0))
		return -EFAULT;

	if (esdm_gnutls_drbg_generate(drbg, act, actlen) != (ssize_t)actlen ||
	    esdm_gnutls_drbg_generate(drbg, act, actlen) != (ssize_t)actlen)
		return -EFAULT;

	return 0;
}

static int esdm_gnutls_drbg_selftest(void)
{
	/*
	 * NIST CAVP known answer tests for CTR_DRBG(AES-256, use df), taken
	 * from drbgvectors_pr_false/CTR_DRBG.rsp, [AES-256 use df] with
	 * PredictionResistance = False, PersonalizationStringLen = 0,
	 * AdditionalInputLen = 0 and ReturnedBitsLen = 512.
	 *
	 * Each record instantiates, reseeds and then generates twice, with CAVP
	 * comparing the second output - the one sweep FIPS 140-3 IG 10.3.A
	 * accepts in place of separate tests of the instantiate, reseed and
	 * generate functions.
	 *
	 * The test covers the backend as used: the seed material goes through
	 * esdm_gnutls_drbg_seed(), i.e. Block_Cipher_df, into the GnuTLS CTR
	 * DRBG core. Covering the derivation function is the point: a subtly
	 * wrong df still yields random looking output, so only a known answer
	 * test over the whole composition detects it.
	 */
	static const struct {
		/* entropy_input || nonce; the personalization string is empty */
		uint8_t seed[DRBG_AES_SEED_SIZE];
		/* entropy_input of the reseed; its additional input is empty */
		uint8_t reseed[32];
		uint8_t exp[64];
	} kat[] = {
		/* CAVP COUNT = 0 */
		{ .seed = { 0x2d, 0x4c, 0x9f, 0x46, 0xb9, 0x81, 0xc6, 0xa0,
			    0xb2, 0xb5, 0xd8, 0xc6, 0x93, 0x91, 0xe5, 0x69,
			    0xff, 0x13, 0x85, 0x14, 0x37, 0xeb, 0xc0, 0xfc,
			    0x00, 0xd6, 0x16, 0x34, 0x02, 0x52, 0xfe, 0xd5,
			    0x0b, 0xf8, 0x14, 0xb4, 0x11, 0xf6, 0x5e, 0xc4,
			    0x86, 0x6b, 0xe1, 0xab, 0xb5, 0x9d, 0x3c, 0x32 },
		  .reseed = { 0x93, 0x50, 0x0f, 0xae, 0x4f, 0xa3, 0x2b, 0x86,
			      0x03, 0x3b, 0x7a, 0x7b, 0xac, 0x9d, 0x37, 0xe7,
			      0x10, 0xdc, 0xc6, 0x7c, 0xa2, 0x66, 0xbc, 0x86,
			      0x07, 0xd6, 0x65, 0x93, 0x77, 0x66, 0xd2, 0x07 },
		  .exp = { 0x32, 0x2d, 0xd2, 0x86, 0x70, 0xe7, 0x5c, 0x0e,
			   0xa6, 0x38, 0xf3, 0xcb, 0x68, 0xd6, 0xa9, 0xd6,
			   0xe5, 0x0d, 0xdf, 0xd0, 0x52, 0xb7, 0x72, 0xa7,
			   0xb1, 0xd7, 0x82, 0x63, 0xa7, 0xb8, 0x97, 0x8b,
			   0x67, 0x40, 0xc2, 0xb6, 0x5a, 0x95, 0x50, 0xc3,
			   0xa7, 0x63, 0x25, 0x86, 0x6f, 0xa9, 0x7e, 0x16,
			   0xd7, 0x40, 0x06, 0xbc, 0x96, 0xf2, 0x62, 0x49,
			   0xb9, 0xf0, 0xa9, 0x0d, 0x07, 0x6f, 0x08, 0xe5 } },
		/* CAVP COUNT = 1 */
		{ .seed = { 0x20, 0x0f, 0x09, 0x6b, 0x76, 0xe3, 0xbf, 0x2f,
			    0x40, 0x13, 0x3a, 0xe6, 0x64, 0x92, 0x21, 0x08,
			    0x4f, 0x0a, 0xfb, 0x11, 0xf9, 0x6f, 0xe8, 0x6a,
			    0x49, 0x87, 0xae, 0x7b, 0x11, 0x59, 0xd0, 0x32,
			    0x3b, 0xe5, 0x6f, 0x6c, 0x0a, 0xe2, 0x89, 0xdf,
			    0xc6, 0x36, 0xf9, 0x6c, 0xff, 0x5d, 0xaa, 0xa1 },
		  .reseed = { 0x89, 0x51, 0x33, 0xf4, 0xf2, 0xd1, 0xbe, 0x25,
			      0xec, 0x92, 0x9d, 0x42, 0xe9, 0x04, 0xdb, 0xc7,
			      0x74, 0x99, 0x39, 0xad, 0x70, 0x22, 0xa9, 0x03,
			      0x60, 0xa7, 0x43, 0xfd, 0x2c, 0x3f, 0x48, 0x3c },
		  .exp = { 0xbf, 0x12, 0xbf, 0x4d, 0x8e, 0xb6, 0xbb, 0xbd,
			   0x9f, 0x91, 0xa2, 0xef, 0x48, 0xc6, 0xbc, 0x65,
			   0x24, 0xa1, 0x33, 0xdd, 0xe3, 0xc8, 0xd4, 0xf1,
			   0x3d, 0x4b, 0x5c, 0xda, 0xe3, 0xb9, 0xe0, 0x41,
			   0xb9, 0x8c, 0x86, 0x50, 0xad, 0xa9, 0xe1, 0xf2,
			   0xb5, 0xdf, 0x01, 0xd8, 0x75, 0x47, 0x0b, 0x22,
			   0x0c, 0xac, 0xad, 0x0e, 0xe8, 0x87, 0x08, 0x0c,
			   0x27, 0x19, 0x29, 0xf6, 0x95, 0x20, 0x4b, 0x66 } },
		/* CAVP COUNT = 2 */
		{ .seed = { 0x1c, 0xc5, 0xa0, 0x86, 0x83, 0x1f, 0xac, 0x6b,
			    0xa0, 0x46, 0xb7, 0xf5, 0x6c, 0x4e, 0xa5, 0xba,
			    0x7b, 0xcf, 0x9d, 0x85, 0x1b, 0x50, 0x51, 0x25,
			    0x4c, 0x46, 0x83, 0xbf, 0xed, 0x7a, 0x26, 0xf9,
			    0xa8, 0xd4, 0x2c, 0xa3, 0xb0, 0x8c, 0x9c, 0x97,
			    0x4f, 0xa2, 0xc2, 0xec, 0xeb, 0x5a, 0x71, 0xe7 },
		  .reseed = { 0xe8, 0xc1, 0x74, 0xc6, 0x21, 0xaf, 0x92, 0xc5,
			      0x01, 0x2f, 0xc4, 0xca, 0xca, 0x8d, 0x1f, 0xb7,
			      0x2e, 0xa7, 0x99, 0x8f, 0x5f, 0x78, 0xa6, 0xcd,
			      0x5f, 0x3f, 0x25, 0x0f, 0x33, 0x0f, 0x0c, 0x74 },
		  .exp = { 0x66, 0x54, 0xd8, 0x31, 0x40, 0x36, 0x93, 0x59,
			   0x14, 0x76, 0x21, 0x3b, 0xee, 0x7b, 0xea, 0x64,
			   0x4c, 0x50, 0x58, 0xf9, 0x34, 0x54, 0xe8, 0x9e,
			   0xa5, 0xb3, 0x48, 0xbc, 0x53, 0x54, 0xe2, 0xd8,
			   0xab, 0xac, 0x00, 0xd5, 0x3b, 0x38, 0x79, 0xe2,
			   0xc8, 0x9b, 0xc8, 0xf4, 0x90, 0x96, 0x9e, 0x42,
			   0xd7, 0x38, 0xba, 0x37, 0x43, 0x28, 0x22, 0xdf,
			   0x85, 0x9d, 0x63, 0x1c, 0xfc, 0x86, 0xcd, 0x40 } },
	};
	struct drbg_aes_ctx drbg;
	uint8_t act[64];
	uint8_t mod[DRBG_AES_SEED_SIZE];
	size_t i;
	int ret = 0;

	for (i = 0; i < sizeof(kat) / sizeof(kat[0]); i++) {
		ret = esdm_gnutls_drbg_kat(&drbg, kat[i].seed,
					   sizeof(kat[i].seed), kat[i].reseed,
					   sizeof(kat[i].reseed), act,
					   sizeof(act));
		if (ret)
			goto out;

		ret = esdm_kat_check(act, kat[i].exp, sizeof(act));
		if (ret)
			goto out;

		/*
		 * Seed material off by its first byte must not produce that
		 * output - from a DRBG that is instantiated afresh for it, as
		 * the one above is past the state the known answer belongs to.
		 */
		ret = esdm_kat_modify(mod, kat[i].seed, sizeof(mod));
		if (ret)
			goto out;

		ret = esdm_gnutls_drbg_kat(&drbg, mod, sizeof(mod),
					   kat[i].reseed, sizeof(kat[i].reseed),
					   act, sizeof(act));
		if (ret)
			goto out;

		ret = esdm_kat_check_differs(act, kat[i].exp, sizeof(act));
		if (ret)
			goto out;
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
