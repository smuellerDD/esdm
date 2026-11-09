/*
 * XDRBG-256 of the entropy pools
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
 * The kernel module esdm_es compiles this file as well, with the environment
 * esdm_portable.h provides there.
 */
#include "esdm_portable.h"
#include "esdm_xdrbg.h"
#include "selftest_kat.h"

/* n of encode(alpha, n): instantiate 0, reseed 1, generate 2 */
#define ESDM_XDRBG_ENCODE_N(x) ((x) * 85)

int esdm_xdrbg_alloc(struct esdm_xdrbg *xdrbg)
{
	xdrbg->xof_cb = esdm_default_xof_cb;
	xdrbg->xof = NULL;
	xdrbg->initially_seeded = false;
	xdrbg->seed_initialized = false;
	xdrbg->inserted = false;
	memset(xdrbg->v, 0, sizeof(xdrbg->v));
	return xdrbg->xof_cb->xof_alloc(&xdrbg->xof);
}

void esdm_xdrbg_zero(struct esdm_xdrbg *xdrbg)
{
	/* What the context absorbed is wiped as it is initialized again */
	xdrbg->initially_seeded = false;
	xdrbg->seed_initialized = false;
	xdrbg->inserted = false;
	memset_secure(xdrbg->v, 0, sizeof(xdrbg->v));
}

void esdm_xdrbg_zero_free(struct esdm_xdrbg *xdrbg)
{
	if (xdrbg->xof && xdrbg->xof_cb)
		xdrbg->xof_cb->xof_dealloc(xdrbg->xof);
	xdrbg->xof = NULL;
	esdm_xdrbg_zero(xdrbg);
}

/*
 * Initialize the context for the seed of the next reseed, absorbing V - or of
 * the instantiate, without one
 */
static int esdm_xdrbg_ctx_init(struct esdm_xdrbg *xdrbg)
{
	const struct esdm_xof_cb *xof_cb = xdrbg->xof_cb;
	int ret;

	CKINT(xof_cb->xof_init(xdrbg->xof));
	if (xdrbg->initially_seeded)
		CKINT(xof_cb->xof_update(xdrbg->xof, xdrbg->v,
					 ESDM_XDRBG_V_SIZE));
	xdrbg->inserted = false;

out:
	return ret;
}

int esdm_xdrbg_seed_init(struct esdm_xdrbg *xdrbg)
{
	int ret;

	if (xdrbg->seed_initialized)
		return 0;

	/* Never allocated or released already: nothing to initialize */
	if (!xdrbg->xof)
		return -EOPNOTSUPP;

	/* A new instantiation */
	esdm_xdrbg_zero(xdrbg);
	CKINT(esdm_xdrbg_ctx_init(xdrbg));
	xdrbg->seed_initialized = true;

out:
	return ret;
}

int esdm_xdrbg_insert(struct esdm_xdrbg *xdrbg, const uint8_t *in, size_t inlen)
{
	int ret;

	CKINT(esdm_xdrbg_seed_init(xdrbg));
	if (!inlen)
		return 0;

	xdrbg->inserted = true;
	ret = xdrbg->xof_cb->xof_update(xdrbg->xof, in, inlen);

	/* The XOF may have absorbed part of the data: no torn state goes on */
	if (ret)
		esdm_xdrbg_zero(xdrbg);

out:
	return ret;
}

/* Absorb encode(alpha, n) of an alpha of at most ESDM_XDRBG_MAX_ALPHA bytes */
static int esdm_xdrbg_encode(struct esdm_xdrbg *xdrbg, uint8_t n,
			     const uint8_t *alpha, size_t alphalen)
{
	const struct esdm_xof_cb *xof_cb = xdrbg->xof_cb;
	uint8_t encode = (uint8_t)(n + alphalen);
	int ret;

	if (alphalen)
		CKINT(xof_cb->xof_update(xdrbg->xof, alpha, alphalen));
	CKINT(xof_cb->xof_update(xdrbg->xof, &encode, sizeof(encode)));

out:
	return ret;
}

/*
 * Instantiate or reseed: the context, which absorbed V and the inserted data,
 * absorbs the seed and alpha, and its output is the new V. The context is left
 * finalized.
 */
static int esdm_xdrbg_seed_nocheck(struct esdm_xdrbg *xdrbg,
				   const uint8_t *seed, size_t seedlen,
				   const uint8_t *alpha, size_t alphalen)
{
	const struct esdm_xof_cb *xof_cb = xdrbg->xof_cb;
	int ret;

	CKINT(esdm_xdrbg_seed_init(xdrbg));
	if (seedlen)
		CKINT(xof_cb->xof_update(xdrbg->xof, seed, seedlen));
	CKINT(esdm_xdrbg_encode(
		xdrbg, ESDM_XDRBG_ENCODE_N(xdrbg->initially_seeded ? 1 : 0),
		alpha, alphalen));
	CKINT(xof_cb->xof_final(xdrbg->xof, xdrbg->v, ESDM_XDRBG_V_SIZE));
	xdrbg->initially_seeded = true;

out:
	return ret;
}

/*
 * Generate from V, chunk by chunk, each one with the V of the previous one,
 * and initialize the context for the next reseed with the V that is left
 */
static int esdm_xdrbg_generate_nocheck(struct esdm_xdrbg *xdrbg,
				       const uint8_t *alpha, size_t alphalen,
				       uint8_t *out, size_t outlen)
{
	const struct esdm_xof_cb *xof_cb = xdrbg->xof_cb;
	uint8_t buf[ESDM_XDRBG_V_SIZE + ESDM_XDRBG_MAX_CHUNK];
	int ret = 0;

	while (outlen) {
		size_t todo = outlen < ESDM_XDRBG_MAX_CHUNK ?
				      outlen :
				      ESDM_XDRBG_MAX_CHUNK;

		CKINT(xof_cb->xof_init(xdrbg->xof));
		CKINT(xof_cb->xof_update(xdrbg->xof, xdrbg->v,
					 ESDM_XDRBG_V_SIZE));
		CKINT(esdm_xdrbg_encode(xdrbg, ESDM_XDRBG_ENCODE_N(2), alpha,
					alphalen));
		CKINT(xof_cb->xof_final(xdrbg->xof, buf,
					ESDM_XDRBG_V_SIZE + todo));

		memcpy(xdrbg->v, buf, ESDM_XDRBG_V_SIZE);
		memcpy(out, buf + ESDM_XDRBG_V_SIZE, todo);
		out += todo;
		outlen -= todo;
	}

	CKINT(esdm_xdrbg_ctx_init(xdrbg));

out:
	memset_secure(buf, 0, sizeof(buf));
	return ret;
}

int esdm_xdrbg_seed(struct esdm_xdrbg *xdrbg, const uint8_t *seed,
		    size_t seedlen, const uint8_t *alpha, size_t alphalen)
{
	int ret;

	if (alphalen > ESDM_XDRBG_MAX_ALPHA)
		return -EINVAL;

	CKINT(esdm_xdrbg_seed_nocheck(xdrbg, seed, seedlen, alpha, alphalen));
	CKINT(esdm_xdrbg_ctx_init(xdrbg));

out:
	if (ret)
		esdm_xdrbg_zero(xdrbg);
	return ret;
}

int esdm_xdrbg_generate(struct esdm_xdrbg *xdrbg, const uint8_t *alpha,
			size_t alphalen, uint8_t *out, size_t outlen)
{
	int ret;

	if (alphalen > ESDM_XDRBG_MAX_ALPHA)
		return -EINVAL;

	/* Refuse to generate from an unseeded state */
	if (!xdrbg->initially_seeded)
		return -EOPNOTSUPP;

	/*
	 * The context absorbed V and data for the next reseed: the seed is
	 * still being inserted, and the V it starts with must stay
	 */
	if (xdrbg->inserted)
		return -EBUSY;

	ret = esdm_xdrbg_generate_nocheck(xdrbg, alpha, alphalen, out, outlen);
	if (ret)
		esdm_xdrbg_zero(xdrbg);
	return ret;
}

int esdm_xdrbg_extract(struct esdm_xdrbg *xdrbg, const uint8_t *alpha,
		       size_t alphalen, uint8_t *out, size_t outlen)
{
	int ret;

	if (!xdrbg->seed_initialized || alphalen > ESDM_XDRBG_MAX_ALPHA)
		return -EINVAL;

	/* Reseed, or instantiate, with what was inserted, and generate */
	CKINT(esdm_xdrbg_seed_nocheck(xdrbg, NULL, 0, alpha, alphalen));
	CKINT(esdm_xdrbg_generate_nocheck(xdrbg, alpha, alphalen, out, outlen));

out:
	if (ret)
		esdm_xdrbg_zero(xdrbg);
	return ret;
}

/*
 * Known-answer test of the XDRBG-256, the self test of its SHAKE256 as well:
 * instantiate from the bytes 0x00 ... 0x3f and generate, reseed from 0x40 ...
 * 0x7f and generate, all with the alpha of auxiliary pool 0. The known answer
 * is XDRBG-256 as specified, computed independently of the ESDM. Each seed is
 * inserted at once, and again in chunks, as the pools insert their data: both
 * give the known answer. tests/crypto/xdrbg_tester.c runs the self test of
 * the reference implementation against it as well.
 */
#define ESDM_XDRBG_KAT_LEN 32

/* Insert a seed of ESDM_XDRBG_V_SIZE bytes at once, or in chunks */
static int esdm_xdrbg_selftest_insert(struct esdm_xdrbg *xdrbg,
				      const uint8_t *seed, bool chunked)
{
	static const uint8_t chunks[] = { 1, 7, 56 };
	unsigned int i;
	int ret = 0;

	BUILD_BUG_ON(1 + 7 + 56 != ESDM_XDRBG_V_SIZE);

	if (!chunked)
		return esdm_xdrbg_insert(xdrbg, seed, ESDM_XDRBG_V_SIZE);

	for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
		CKINT(esdm_xdrbg_insert(xdrbg, seed, chunks[i]));
		seed += chunks[i];
	}

out:
	return ret;
}

int esdm_xdrbg_selftest(void)
{
	/* "ESDM aux pool" and the index 0 as two bytes */
	static const char alpha[] = "ESDM aux pool\0";
	static const uint8_t exp1[] = {
		0xa6, 0x72, 0xf6, 0xb2, 0x42, 0x5b, 0x61, 0xb0,
		0xa3, 0xfe, 0xad, 0x10, 0x1c, 0x71, 0xbc, 0x1e,
		0x2b, 0xef, 0x4c, 0xf6, 0x43, 0xf0, 0xa8, 0xf5,
		0x27, 0x5e, 0x64, 0xaa, 0x66, 0xf1, 0x95, 0x71,
	};
	static const uint8_t exp2[] = {
		0x28, 0x38, 0x6c, 0x23, 0x92, 0xb8, 0xd1, 0x1f,
		0x17, 0xa3, 0x19, 0x95, 0x5c, 0x7b, 0x72, 0x2d,
		0x9f, 0x82, 0xf6, 0x92, 0xc7, 0xe3, 0x1b, 0x78,
		0xae, 0x36, 0xab, 0x87, 0xd2, 0xc6, 0xe7, 0x57,
	};
	struct esdm_xdrbg xdrbg;
	uint8_t seed[2 * ESDM_XDRBG_V_SIZE];
	uint8_t act[ESDM_XDRBG_KAT_LEN];
	unsigned int i;
	int ret;

	BUILD_BUG_ON(sizeof(exp1) != ESDM_XDRBG_KAT_LEN ||
		     sizeof(exp2) != ESDM_XDRBG_KAT_LEN);
	BUILD_BUG_ON(sizeof(alpha) != 15);

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;

	CKINT(esdm_xdrbg_alloc(&xdrbg));

	/* The seeds inserted at once, in chunks, and off by a byte */
	for (i = 0; i < 3; i++) {
		bool chunked = i == 1;

		/* A seed off by its first byte must not produce that output */
		if (i == 2)
			seed[0] ^= 0x01;

		esdm_xdrbg_zero(&xdrbg);
		CKINT(esdm_xdrbg_selftest_insert(&xdrbg, seed, chunked));
		CKINT(esdm_xdrbg_extract(&xdrbg, (const uint8_t *)alpha,
					 sizeof(alpha), act, sizeof(act)));
		if (i == 2) {
			CKINT(esdm_kat_check_differs(act, exp1, sizeof(exp1)));
			break;
		}
		CKINT(esdm_kat_check(act, exp1, sizeof(exp1)));

		CKINT(esdm_xdrbg_selftest_insert(
			&xdrbg, seed + ESDM_XDRBG_V_SIZE, chunked));
		CKINT(esdm_xdrbg_extract(&xdrbg, (const uint8_t *)alpha,
					 sizeof(alpha), act, sizeof(act)));
		CKINT(esdm_kat_check(act, exp2, sizeof(exp2)));
	}

out:
	esdm_xdrbg_zero_free(&xdrbg);
	memset_secure(act, 0, sizeof(act));
	return ret;
}
