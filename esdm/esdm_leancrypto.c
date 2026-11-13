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
#include <leancrypto.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_crypto.h"
#include "esdm_leancrypto.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "ret_checkers.h"
#include "selftest_kat.h"

#define ESDM_LEANCRYPTO_HASH lc_sha3_512

/*
 * A hash or XOF context and whether lc_hash_init() succeeded. After a failed
 * self test leancrypto refuses the init and leaves the state as is, possibly
 * with a rate of 0 that update and final silently divide by.
 */
struct esdm_leancrypto_hash {
	struct lc_hash_ctx *ctx;
	bool initialized;
};

static uint32_t esdm_leancrypto_hash_digestsize(void *hash)
{
	struct esdm_leancrypto_hash *h = hash;

	return (uint32_t)lc_hash_digestsize(h->ctx);
}

static int esdm_leancrypto_hash_init(void *hash)
{
	struct esdm_leancrypto_hash *h = hash;
	int ret = lc_hash_init(h->ctx);

	h->initialized = !ret;
	if (ret) {
		/* An init wipes what the context absorbed, a refused one too */
		lc_hash_zero(h->ctx);
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "lc_hash_init() failed: %d\n", ret);
	}
	return ret;
}

static int esdm_leancrypto_hash_update(void *hash, const uint8_t *inbuf,
				       size_t inbuflen)
{
	struct esdm_leancrypto_hash *h = hash;

	if (!h->initialized)
		return -EOPNOTSUPP;

	lc_hash_update(h->ctx, inbuf, inbuflen);
	return 0;
}

static int esdm_leancrypto_hash_final(void *hash, uint8_t *digest)
{
	struct esdm_leancrypto_hash *h = hash;

	if (!h->initialized)
		return -EOPNOTSUPP;

	lc_hash_final(h->ctx, digest);
	h->initialized = false;
	return 0;
}

static int esdm_leancrypto_hash_alloc_type(const struct lc_hash *type,
					   void **ctx)
{
	struct esdm_leancrypto_hash *h = calloc(1, sizeof(*h));
	int ret;

	if (!h)
		return -ENOMEM;

	ret = lc_hash_alloc(type, &h->ctx);
	if (ret) {
		free(h);
		return ret;
	}

	*ctx = h;
	return 0;
}

static int esdm_leancrypto_hash_alloc(void **ctx)
{
	return esdm_leancrypto_hash_alloc_type(ESDM_LEANCRYPTO_HASH, ctx);
}

static void esdm_leancrypto_hash_dealloc(void *ctx)
{
	struct esdm_leancrypto_hash *h = ctx;

	if (!h)
		return;

	lc_hash_zero_free(h->ctx);
	free(h);
}

static const char *esdm_leancrypto_hash_name(void)
{
	return "Leancrypto SHA3-512";
}

static void esdm_leancrypto_hash_desc_zero(void *hash)
{
	(void)hash;
}

/*
 * leancrypto self-tests on first use and reports a failure only as an init or
 * seed error; the KATs here go through those, surfacing its own tests too.
 */
static int esdm_leancrypto_hash_selftest(void)
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
	uint8_t mod[sizeof(msg_512)];
	void *hash = NULL;
	int ret;

	CKINT(esdm_leancrypto_hash_alloc(&hash));
	if (esdm_leancrypto_hash_digestsize(hash) != sizeof(exp_512)) {
		ret = -EFAULT;
		goto out;
	}

	CKINT(esdm_leancrypto_hash_init(hash));
	CKINT(esdm_leancrypto_hash_update(hash, msg_512, sizeof(msg_512)));
	CKINT(esdm_leancrypto_hash_final(hash, act));

	CKINT(esdm_kat_check(act, exp_512, sizeof(exp_512)));

	/* A message off by its first byte must not produce that digest */
	CKINT(esdm_kat_modify(mod, msg_512, sizeof(mod)));
	CKINT(esdm_leancrypto_hash_init(hash));
	CKINT(esdm_leancrypto_hash_update(hash, mod, sizeof(mod)));
	CKINT(esdm_leancrypto_hash_final(hash, act));

	CKINT(esdm_kat_check_differs(act, exp_512, sizeof(exp_512)));

out:
	esdm_leancrypto_hash_dealloc(hash);
	return ret;
}

const struct esdm_hash_cb esdm_leancrypto_hash_cb = {
	.hash_name = esdm_leancrypto_hash_name,
	.hash_selftest = esdm_leancrypto_hash_selftest,
	.hash_digestsize = esdm_leancrypto_hash_digestsize,
	.hash_init = esdm_leancrypto_hash_init,
	.hash_update = esdm_leancrypto_hash_update,
	.hash_final = esdm_leancrypto_hash_final,
	.hash_desc_zero = esdm_leancrypto_hash_desc_zero,
	.hash_alloc = esdm_leancrypto_hash_alloc,
	.hash_dealloc = esdm_leancrypto_hash_dealloc,
};

static int esdm_leancrypto_xof_final(void *xof, uint8_t *out, size_t outlen)
{
	struct esdm_leancrypto_hash *h = xof;

	if (!h->initialized)
		return -EOPNOTSUPP;

	lc_hash_set_digestsize(h->ctx, outlen);
	lc_hash_final(h->ctx, out);
	h->initialized = false;
	return 0;
}

static int esdm_leancrypto_xof_alloc(void **ctx)
{
	return esdm_leancrypto_hash_alloc_type(lc_shake256, ctx);
}

static const char *esdm_leancrypto_xof_name(void)
{
	return "Leancrypto SHAKE256";
}

/* Apart from the allocation and the output, SHAKE256 is a hash to leancrypto */
const struct esdm_xof_cb esdm_leancrypto_xof_cb = {
	.xof_name = esdm_leancrypto_xof_name,
	.xof_init = esdm_leancrypto_hash_init,
	.xof_update = esdm_leancrypto_hash_update,
	.xof_final = esdm_leancrypto_xof_final,
	.xof_alloc = esdm_leancrypto_xof_alloc,
	.xof_dealloc = esdm_leancrypto_hash_dealloc,
};

/*
 * The XDRBG and whether its last seed succeeded: leancrypto generates from an
 * unseeded state as well, from a V of zeros after a failed instantiation.
 */
struct esdm_leancrypto_drng {
	struct lc_rng_ctx *rng;
	bool seeded;
};

static int esdm_leancrypto_drbg_seed(void *drng, const uint8_t *inbuf,
				     size_t inbuflen, const uint8_t *addtl,
				     size_t addtllen)
{
	struct esdm_leancrypto_drng *state = drng;
	uint8_t *seed = NULL;
	size_t seedlen = inbuflen;
	int ret;

	/*
	 * The XDRBG keeps only 84 bytes of additional input alpha, so addtl
	 * (output of zero-credit sources) follows the seed, taken whole.
	 */
	if (addtl && addtllen) {
		if (inbuflen > SIZE_MAX - addtllen)
			return -EINVAL;
		seedlen += addtllen;
		seed = malloc(seedlen);
		if (!seed)
			return -ENOMEM;
		memcpy(seed, inbuf, inbuflen);
		memcpy(seed + inbuflen, addtl, addtllen);
		inbuf = seed;
	}

	ret = lc_rng_seed(state->rng, inbuf, seedlen, NULL, 0);
	state->seeded = !ret;
	if (ret)
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "XDRBG seeding failed: %d\n", ret);

	if (seed) {
		memset_secure(seed, 0, seedlen);
		free(seed);
	}

	return ret;
}

static ssize_t esdm_leancrypto_drbg_generate(void *drng, uint8_t *outbuf,
					     size_t outbuflen)
{
	struct esdm_leancrypto_drng *state = drng;
	int ret;

	if (!state->seeded)
		return -EOPNOTSUPP;

	ret = lc_rng_generate(state->rng, NULL, 0, outbuf, outbuflen);

	return ret ? ret : (ssize_t)outbuflen;
}

static int esdm_leancrypto_drbg_alloc(void **drng, uint32_t sec_strength)
{
	struct esdm_leancrypto_drng *state = calloc(1, sizeof(*state));
	int ret;

	(void)sec_strength;

	if (!state)
		return -ENOMEM;

	ret = lc_xdrbg256_drng_alloc(&state->rng);
	if (ret) {
		free(state);
		return ret;
	}

	*drng = state;
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "XDRBG allocated\n");

	return 0;
}

static void esdm_leancrypto_drbg_dealloc(void *drng)
{
	struct esdm_leancrypto_drng *state = drng;

	if (!state)
		return;

	lc_rng_zero_free(state->rng);
	free(state);
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "XDRBG zeroized and freed\n");
}

static const char *esdm_leancrypto_drbg_name(void)
{
	return "Leancrypto XDRBG with SHAKE256 core";
}

/*
 * Instantiate from 0x00 ... 0x08 and generate (as leancrypto's own XDRBG-256
 * self test starts), then reseed from 0x09 ... 0x28 with additional input
 * 0xa0 ... 0xaf and generate. Answers computed per spec, not by leancrypto.
 */
static int esdm_leancrypto_drbg_selftest(void)
{
	static const uint8_t exp1[] = {
		0x1a, 0xd2, 0xcb, 0x76, 0x3c, 0x71, 0x6d, 0xf0,
		0x79, 0x2c, 0xc0, 0x69, 0x7d, 0x56, 0x6a, 0x65,
		0xb8, 0x36, 0xbe, 0x7d, 0x09, 0x12, 0x7c, 0x65,
		0x47, 0xfc, 0x30, 0x58, 0xaa, 0x24, 0x39, 0x52,
	};
	static const uint8_t exp2[] = {
		0x79, 0x42, 0x1a, 0x2c, 0xdd, 0xcc, 0x6f, 0x67,
		0x68, 0xcc, 0x7a, 0x7d, 0x1c, 0x3d, 0xb5, 0xec,
		0x29, 0xdd, 0xe3, 0x43, 0xb5, 0x75, 0x1a, 0x2e,
		0x02, 0x58, 0x5a, 0x0d, 0x26, 0x06, 0xfd, 0x44,
	};
	uint8_t seed[9 + 32], addtl[16], act[sizeof(exp1)];
	void *drng = NULL;
	unsigned int i;
	int ret;

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;
	for (i = 0; i < sizeof(addtl); i++)
		addtl[i] = (uint8_t)(0xa0 + i);

	CKINT(esdm_leancrypto_drbg_alloc(&drng, 256));

	/* No output before the instantiation */
	if (esdm_leancrypto_drbg_generate(drng, act, sizeof(act)) >= 0) {
		ret = -EFAULT;
		goto out;
	}

	CKINT(esdm_leancrypto_drbg_seed(drng, seed, 9, NULL, 0));
	if (esdm_leancrypto_drbg_generate(drng, act, sizeof(act)) !=
	    sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}
	CKINT(esdm_kat_check(act, exp1, sizeof(exp1)));

	CKINT(esdm_leancrypto_drbg_seed(drng, seed + 9, sizeof(seed) - 9, addtl,
					sizeof(addtl)));
	if (esdm_leancrypto_drbg_generate(drng, act, sizeof(act)) !=
	    sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}
	CKINT(esdm_kat_check(act, exp2, sizeof(exp2)));

	/* A seed off by its first byte must not produce that output */
	esdm_leancrypto_drbg_dealloc(drng);
	drng = NULL;
	seed[0] ^= 0xff;
	CKINT(esdm_leancrypto_drbg_alloc(&drng, 256));
	CKINT(esdm_leancrypto_drbg_seed(drng, seed, 9, NULL, 0));
	if (esdm_leancrypto_drbg_generate(drng, act, sizeof(act)) !=
	    sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}
	CKINT(esdm_kat_check_differs(act, exp1, sizeof(exp1)));

out:
	esdm_leancrypto_drbg_dealloc(drng);
	return ret;
}

const struct esdm_drng_cb esdm_leancrypto_drbg_cb = {
	.drng_name = esdm_leancrypto_drbg_name,
	.drng_selftest = esdm_leancrypto_drbg_selftest,
	.drng_alloc = esdm_leancrypto_drbg_alloc,
	.drng_dealloc = esdm_leancrypto_drbg_dealloc,
	.drng_seed = esdm_leancrypto_drbg_seed,
	.drng_generate = esdm_leancrypto_drbg_generate,
};
