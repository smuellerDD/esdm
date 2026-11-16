/*
 * XDRBG-256 against its reference implementation
 *
 * The self test of the reference implementation,
 * https://github.com/smuellerDD/xdrbg (xdrbg256_drng_selftest() of xdrbg.c as
 * of commit a1cbab2), run with esdm_xdrbg_seed() and esdm_xdrbg_generate() in
 * place of its lc_xdrbg256_drng_seed() and lc_xdrbg256_drng_generate():
 * instantiated from the bytes 0x00 ... 0x08 without alpha, the XDRBG-256
 * generates exp1, and with an alpha of the first 83 and 84 bytes of exp1 the
 * first bytes of exp83 and exp84. Like the reference implementation, the test
 * computes the state after an instantiation and the output from it with the
 * SHAKE256 itself, and a reseed as well, which its known answers lack.
 *
 * An alpha of 85 bytes is refused, as by the XDRBG of leancrypto, where the
 * reference implementation uses its first 84 bytes.
 *
 * Its known answers as well with the seed inserted at once and in chunks, and
 * from an extraction without alpha - and so known answers generated with
 * leancrypto for seeds longer than a SHAKE256 block, for an instantiation and
 * a reseed, see exp_long_inst.
 *
 * Beyond the reference implementation: output longer than one chunk, an
 * extraction being a reseed and a generate with the same alpha, and a
 * zeroization wiping the XOF context.
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm_xdrbg.h"
#include "selftest_kat.h"

/*
 * The known answers of the reference implementation, verbatim from
 * xdrbg256_drng_selftest() in xdrbg.c of https://github.com/smuellerDD/xdrbg
 * as of commit a1cbab2. leancrypto has the same in
 * drng/tests/xdrbg256_tester.c (https://github.com/smuellerDD/leancrypto),
 * there with exp1 continued to 345 bytes.
 */
static const uint8_t seed[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static const uint8_t exp1[] = {
	0x1a, 0xd2, 0xcb, 0x76, 0x3c, 0x71, 0x6d, 0xf0, 0x79, 0x2c, 0xc0, 0x69,
	0x7d, 0x56, 0x6a, 0x65, 0xb8, 0x36, 0xbe, 0x7d, 0x09, 0x12, 0x7c, 0x65,
	0x47, 0xfc, 0x30, 0x58, 0xaa, 0x24, 0x39, 0x52, 0x29, 0xea, 0xce, 0x43,
	0xdf, 0x16, 0x2c, 0x4f, 0x1a, 0xed, 0xbd, 0x3f, 0xf5, 0x8e, 0xe6, 0x4d,
	0x93, 0x07, 0x3d, 0x7f, 0x3d, 0xd2, 0x50, 0x3c, 0xae, 0x04, 0x4a, 0x87,
	0x2c, 0x90, 0x30, 0xd4, 0x8e, 0xef, 0x5d, 0x53, 0x0f, 0xb2, 0xdb, 0xec,
	0x16, 0x39, 0x5a, 0xb5, 0x9a, 0xdc, 0x9d, 0x01, 0x7e, 0xe2, 0xac, 0x7c,
	0xe4, 0x3d, 0xfd, 0x93, 0xa6, 0x6c, 0xc1, 0x22, 0x26, 0x64, 0xa0, 0x43,
	0x52, 0x51, 0xf9, 0xb5, 0xa4, 0x91, 0x54, 0x08, 0xf8, 0x8f, 0x16, 0x85,
	0x54, 0xc0, 0x9d, 0xce, 0xc9, 0xd5, 0xd7, 0xa9, 0x51, 0xc0, 0x06, 0x0c,
	0x04, 0x95, 0xcf, 0x7d, 0x27, 0x00, 0x7e, 0x48, 0x6d, 0x2e, 0xbc, 0xf8,
	0xa3, 0x71, 0x3d, 0xb0, 0x2b, 0x75, 0x2a, 0x48, 0x1a, 0xd3, 0xed, 0xc9,
	0xa3, 0x80, 0x88, 0x03, 0xc0, 0x27, 0x75, 0xcc, 0xf5, 0xda, 0x56, 0x8d,
	0x83, 0x36, 0xe6, 0x90, 0x9c, 0xd5, 0x82, 0xfa, 0x70, 0xe9, 0xbf, 0x61,
	0xec, 0x97, 0xcc, 0xdd, 0xdc, 0x4e, 0xe1, 0x64, 0x9f, 0x1e, 0xb3, 0xfa,
	0x97, 0xa7, 0x02, 0x0a, 0x28, 0x01, 0x19, 0xd0, 0x45, 0xe9, 0x21, 0x74,
	0x52, 0x1a, 0xac, 0x5f, 0x58, 0x7c, 0x02, 0x47, 0x45, 0x06, 0x17, 0x71,
	0xc5, 0x2b, 0x0f, 0xa9, 0xed, 0x5c, 0xd1, 0x46, 0x63, 0x57, 0xb5, 0x6a,
	0x5c, 0x95, 0xd1, 0xa4, 0xdf, 0x61, 0x62, 0x39, 0x41, 0x47, 0xb1, 0x4e,
	0x91, 0x7c, 0x50, 0x1f, 0xc0, 0x48, 0x42, 0xb6, 0xea, 0x16, 0x4c, 0x50,
	0x29, 0x12, 0xd0, 0x1c, 0x39, 0x9f, 0x79,
};

static const uint8_t exp83[] = { 0x39, 0x2b, 0x18, 0x96, 0x45,
				 0x81, 0x86, 0x84, 0xcf };

static const uint8_t exp84[] = { 0xf0, 0x85, 0xd6, 0xc8, 0xd1,
				 0x76, 0xd7, 0x12, 0x39 };

/*
 * Known answers for seeds longer than a SHAKE256 block, and for a reseed,
 * which neither the reference implementation nor leancrypto publishes.
 *
 * Generated with the XDRBG-256 of leancrypto, lc_xdrbg256_drng of
 * https://github.com/smuellerDD/leancrypto as of commit da22b8af:
 *
 *	lc_rng_seed(seed_long, XDRBG_TEST_LONG_SEED, alpha_long),
 *	lc_rng_generate(alpha_long, 64 bytes)			-> exp_long_inst
 *	lc_rng_seed(seed_long + XDRBG_TEST_LONG_SEED, XDRBG_TEST_LONG_SEED,
 *		    alpha_long),
 *	lc_rng_generate(alpha_long, 64 bytes)			-> exp_long_reseed
 *
 * with seed_long the bytes i mod 256 for i = 0 ... 2 * XDRBG_TEST_LONG_SEED - 1
 * (its first half seeds the instantiation, its second half the reseed) and
 * alpha_long without its terminating NUL, and confirmed with the XDRBG-256 as
 * specified on hashlib.shake_256 of Python. Both are independent of the ESDM.
 */
#define XDRBG_TEST_LONG_SEED (3 * ESDM_XDRBG_SHAKE256_BLOCK + 17)

static uint8_t seed_long[2 * XDRBG_TEST_LONG_SEED];

static const uint8_t alpha_long[] = "XDRBG-256 long seed";
#define XDRBG_TEST_LONG_ALPHA (sizeof(alpha_long) - 1)

static const uint8_t exp_long_inst[] = {
	0x3f, 0x46, 0xa3, 0xdd, 0x00, 0xed, 0x28, 0x27, 0x73, 0xde, 0xe3,
	0x9f, 0x29, 0xb8, 0xc0, 0x8b, 0xdf, 0xa6, 0x28, 0x7a, 0x33, 0x84,
	0xa7, 0x4a, 0x07, 0xd6, 0xd3, 0x5c, 0xd7, 0x5b, 0xdc, 0x87, 0xda,
	0x16, 0xe1, 0x43, 0x83, 0xe0, 0x78, 0xb6, 0xb0, 0xbb, 0x9e, 0x52,
	0xb9, 0x6d, 0x6e, 0xa4, 0xf8, 0xb8, 0xe2, 0x33, 0x8e, 0x1f, 0xae,
	0xd4, 0x43, 0x02, 0x3b, 0xae, 0x70, 0xba, 0x65, 0x07,
};

static const uint8_t exp_long_reseed[] = {
	0x19, 0x42, 0x6d, 0xc4, 0xa2, 0x61, 0xb0, 0x2b, 0xbd, 0x24, 0xcf,
	0x79, 0x9f, 0x7b, 0xdd, 0x0e, 0x68, 0xea, 0x5c, 0xfb, 0x08, 0xad,
	0x96, 0x5d, 0x1b, 0xb3, 0x45, 0xb2, 0x20, 0x24, 0xe0, 0x4d, 0xfc,
	0x54, 0x37, 0x20, 0xb4, 0x41, 0xf0, 0x4f, 0x97, 0x9b, 0xde, 0x73,
	0xfe, 0xa8, 0x9b, 0xaa, 0x4f, 0xc0, 0x40, 0x11, 0xbb, 0xf5, 0xbc,
	0x25, 0xe4, 0x19, 0x91, 0x1c, 0x6b, 0x8c, 0xdf, 0x28,
};

/* Output of more than two chunks, and the chunks it falls into */
#define XDRBG_TEST_LONG (2 * ESDM_XDRBG_MAX_CHUNK + 5)

static int failures;

static void check(int ok, const char *what)
{
	if (!ok) {
		printf("XDRBG-256: %s\n", what);
		failures++;
	}
}

/* SHAKE256 of the concatenation of up to three pieces, with the XOF itself */
static int shake256(const uint8_t *a, size_t alen, const uint8_t *b,
		    size_t blen, const uint8_t *c, size_t clen, uint8_t *out,
		    size_t outlen)
{
	const struct esdm_xof_cb *xof_cb = esdm_default_xof_cb;
	void *xof = NULL;
	int ret;

	ret = xof_cb->xof_alloc(&xof);
	if (ret)
		return ret;

	ret = xof_cb->xof_init(xof);
	if (!ret && alen)
		ret = xof_cb->xof_update(xof, a, alen);
	if (!ret && blen)
		ret = xof_cb->xof_update(xof, b, blen);
	if (!ret && clen)
		ret = xof_cb->xof_update(xof, c, clen);
	if (!ret)
		ret = xof_cb->xof_final(xof, out, outlen);

	xof_cb->xof_dealloc(xof);
	return ret;
}

/* A new XDRBG, instantiated from the seed of the known answers */
static int xdrbg_new(struct esdm_xdrbg *xdrbg, const uint8_t *alpha,
		     size_t alphalen)
{
	int ret = esdm_xdrbg_alloc(xdrbg);

	if (!ret)
		ret = esdm_xdrbg_seed(xdrbg, seed, sizeof(seed), alpha,
				      alphalen);
	return ret;
}

/* The self test of the reference implementation */
static void xdrbg_reference(void)
{
	uint8_t act[sizeof(exp1)], v[ESDM_XDRBG_V_SIZE];
	uint8_t cmp[ESDM_XDRBG_V_SIZE + sizeof(exp1)];
	struct esdm_xdrbg xdrbg;
	uint8_t encode;

	/* The XDRBG operation */
	check(!xdrbg_new(&xdrbg, NULL, 0) &&
		      !esdm_xdrbg_generate(&xdrbg, NULL, 0, act, sizeof(act)) &&
		      !esdm_kat_check(act, exp1, sizeof(exp1)),
	      "not the known answer of the reference implementation");
	esdm_xdrbg_zero_free(&xdrbg);

	/* The state of the instantiation, from the SHAKE256 itself */
	encode = 0;
	check(!xdrbg_new(&xdrbg, NULL, 0) &&
		      !shake256(seed, sizeof(seed), &encode, 1, NULL, 0, v,
				sizeof(v)) &&
		      !memcmp(xdrbg.v, v, sizeof(v)),
	      "the instantiation does not give the state of the SHAKE256");
	esdm_xdrbg_zero_free(&xdrbg);

	/* The generate operation from that state */
	encode = 2 * 85;
	check(!shake256(v, sizeof(v), &encode, 1, NULL, 0, cmp, sizeof(cmp)) &&
		      !memcmp(cmp + ESDM_XDRBG_V_SIZE, exp1, sizeof(exp1)),
	      "the SHAKE256 does not give the known answer");

	/* An alpha of 83 and of 84 bytes */
	check(!xdrbg_new(&xdrbg, NULL, 0) &&
		      !esdm_xdrbg_generate(&xdrbg, exp1, 83, act,
					   sizeof(exp83)) &&
		      !esdm_kat_check(act, exp83, sizeof(exp83)),
	      "not the known answer with an alpha of 83 bytes");
	esdm_xdrbg_zero_free(&xdrbg);

	check(!xdrbg_new(&xdrbg, NULL, 0) &&
		      !esdm_xdrbg_generate(&xdrbg, exp1, 84, act,
					   sizeof(exp84)) &&
		      !esdm_kat_check(act, exp84, sizeof(exp84)),
	      "not the known answer with an alpha of 84 bytes");
	esdm_xdrbg_zero_free(&xdrbg);

	/*
	 * An alpha of 85 bytes is refused and leaves the state as it is: the
	 * generate with 84 bytes that follows gives their known answer
	 */
	check(!xdrbg_new(&xdrbg, NULL, 0) &&
		      esdm_xdrbg_generate(&xdrbg, exp1, 85, act,
					  sizeof(exp84)) == -EINVAL &&
		      esdm_xdrbg_seed(&xdrbg, NULL, 0, exp1, 85) == -EINVAL &&
		      !esdm_xdrbg_generate(&xdrbg, exp1, 84, act,
					   sizeof(exp84)) &&
		      !esdm_kat_check(act, exp84, sizeof(exp84)),
	      "an alpha of 85 bytes is not refused, or changes the state");
	esdm_xdrbg_zero_free(&xdrbg);

	/* The generate operation with an alpha of 84 bytes, from the SHAKE256 */
	encode = 0;
	check(!shake256(seed, sizeof(seed), &encode, 1, NULL, 0, v, sizeof(v)),
	      "SHAKE256 failed");
	encode = 2 * 85 + 84;
	check(!shake256(v, sizeof(v), exp1, 84, &encode, 1, cmp,
			ESDM_XDRBG_V_SIZE + sizeof(exp84)) &&
		      !memcmp(cmp + ESDM_XDRBG_V_SIZE, exp84, sizeof(exp84)),
	      "the SHAKE256 does not give the known answer with an alpha of 84 bytes");
}

/* A reseed, from the SHAKE256 itself */
static void xdrbg_reseed(void)
{
	static const uint8_t alpha[] = { 'r', 'e', 's', 'e', 'e', 'd' };
	uint8_t v[ESDM_XDRBG_V_SIZE], encode = 85 + sizeof(alpha);
	uint8_t seed_alpha[sizeof(seed) + sizeof(alpha)];
	struct esdm_xdrbg xdrbg;

	memcpy(seed_alpha, seed, sizeof(seed));
	memcpy(seed_alpha + sizeof(seed), alpha, sizeof(alpha));

	check(!xdrbg_new(&xdrbg, NULL, 0), "instantiation failed");
	memcpy(v, xdrbg.v, sizeof(v));
	check(!esdm_xdrbg_seed(&xdrbg, seed, sizeof(seed), alpha,
			       sizeof(alpha)) &&
		      !shake256(v, sizeof(v), seed_alpha, sizeof(seed_alpha),
				&encode, 1, v, sizeof(v)) &&
		      !memcmp(xdrbg.v, v, sizeof(v)),
	      "the reseed does not give the state of the SHAKE256");
	esdm_xdrbg_zero_free(&xdrbg);
}

/* Output of several chunks is that of one generate per chunk */
static void xdrbg_chunks(void)
{
	static const size_t chunks[] = { ESDM_XDRBG_MAX_CHUNK,
					 ESDM_XDRBG_MAX_CHUNK, 5 };
	static uint8_t whole[XDRBG_TEST_LONG], pieces[XDRBG_TEST_LONG];
	struct esdm_xdrbg a, b;
	size_t i, done = 0;
	int ret;

	ret = xdrbg_new(&a, NULL, 0);
	ret |= esdm_xdrbg_generate(&a, NULL, 0, whole, sizeof(whole));
	ret |= xdrbg_new(&b, NULL, 0);
	for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
		ret |= esdm_xdrbg_generate(&b, NULL, 0, pieces + done,
					   chunks[i]);
		done += chunks[i];
	}

	check(!ret && done == sizeof(whole) &&
		      !memcmp(whole, pieces, sizeof(whole)),
	      "output of several chunks is not that of a generate per chunk");
	/* The first chunk starts with the known answer */
	check(!esdm_kat_check(whole, exp1, sizeof(exp1)),
	      "output of several chunks does not start with the known answer");
	check(!memcmp(a.v, b.v, sizeof(a.v)),
	      "output of several chunks leaves another state");

	esdm_xdrbg_zero_free(&a);
	esdm_xdrbg_zero_free(&b);
}

/*
 * The known answers with the seed inserted at once and in chunks. The seed goes
 * in each of these ways:
 *
 *	given to esdm_xdrbg_seed() at once,
 *	inserted at once,
 *	inserted in chunks, empty ones among them,
 *	inserted in those chunks but the last, which is given to
 *	esdm_xdrbg_seed(),
 *	inserted byte by byte.
 *
 * The seed of the reference implementation instantiates the XDRBG-256 that
 * generates exp1, and with an alpha of 83 and of 84 bytes exp83 and exp84.
 *
 * The long seeds, with alpha_long, instantiate the XDRBG-256 that generates
 * exp_long_inst, and reseed it to generate exp_long_reseed. Their chunks are
 * shorter than, as long as and longer than a SHAKE256 block, and end on the
 * block boundaries of the instantiation and inside the blocks of the reseed,
 * where V comes first.
 *
 * An extraction after the whole seed was inserted gives the same known
 * answers: without alpha exp1, with alpha_long exp_long_inst and then
 * exp_long_reseed.
 */
static const size_t seed_chunks[] = { 1, 3, 0, 2, 3 };

static const size_t seed_long_chunks[] = {
	0,
	1,
	ESDM_XDRBG_SHAKE256_BLOCK - 1,
	0,
	ESDM_XDRBG_SHAKE256_BLOCK,
	ESDM_XDRBG_SHAKE256_BLOCK + 1,
	16,
};

#define XDRBG_TEST_NCHUNKS(c) (sizeof(c) / sizeof((c)[0]))

enum xdrbg_seeding {
	xdrbg_seed_once,
	xdrbg_seed_inserted,
	xdrbg_seed_chunks,
	xdrbg_seed_chunks_last,
	xdrbg_seed_bytes,
	xdrbg_seed_ways,
};

static const char *const xdrbg_seeding_name[xdrbg_seed_ways] = {
	[xdrbg_seed_once] = "given at once",
	[xdrbg_seed_inserted] = "inserted at once",
	[xdrbg_seed_chunks] = "inserted in chunks",
	[xdrbg_seed_chunks_last] = "inserted in chunks but the last",
	[xdrbg_seed_bytes] = "inserted byte by byte",
};

/* A seed and the chunks it is inserted in */
struct xdrbg_test_seed {
	const uint8_t *in;
	size_t inlen;
	const size_t *chunks;
	size_t nchunks;
};

/*
 * Insert of the seed of @kat what @how inserts, and return its length: the rest is for
 * esdm_xdrbg_seed()
 */
static size_t xdrbg_insert_as(struct esdm_xdrbg *xdrbg, enum xdrbg_seeding how,
			      const struct xdrbg_test_seed *kat, int *ret)
{
	size_t i, n = kat->nchunks, done = 0;

	if (how == xdrbg_seed_inserted) {
		*ret |= esdm_xdrbg_insert(xdrbg, kat->in, kat->inlen);
		done = kat->inlen;
	} else if (how == xdrbg_seed_chunks || how == xdrbg_seed_chunks_last) {
		if (how == xdrbg_seed_chunks_last)
			n--;
		for (i = 0; i < n; i++) {
			*ret |= esdm_xdrbg_insert(xdrbg, kat->in + done,
						  kat->chunks[i]);
			done += kat->chunks[i];
		}
	} else if (how == xdrbg_seed_bytes) {
		for (; done < kat->inlen; done++)
			*ret |= esdm_xdrbg_insert(xdrbg, kat->in + done, 1);
	}

	return done;
}

/* Seed @xdrbg with the seed of @kat as @how does it */
static int xdrbg_seed_as(struct esdm_xdrbg *xdrbg, enum xdrbg_seeding how,
			 const struct xdrbg_test_seed *kat,
			 const uint8_t *alpha, size_t alphalen)
{
	int ret = 0;
	size_t done = xdrbg_insert_as(xdrbg, how, kat, &ret);

	return ret | esdm_xdrbg_seed(xdrbg, kat->in + done, kat->inlen - done,
				     alpha, alphalen);
}

/* Do the chunks of @kat make its seed? */
static void xdrbg_check_chunks(const struct xdrbg_test_seed *kat)
{
	size_t i, len = 0;

	for (i = 0; i < kat->nchunks; i++)
		len += kat->chunks[i];
	check(len == kat->inlen, "the chunks do not make the seed");
}

/* The known answers of the reference implementation */
static void xdrbg_seeding(void)
{
	static const struct xdrbg_test_seed kat_seed = {
		seed, sizeof(seed), seed_chunks, XDRBG_TEST_NCHUNKS(seed_chunks)
	};
	static const struct {
		const char *name;
		const uint8_t *exp;
		size_t explen;
		size_t alphalen;
	} kat[] = {
		{ "exp1", exp1, sizeof(exp1), 0 },
		{ "exp83", exp83, sizeof(exp83), 83 },
		{ "exp84", exp84, sizeof(exp84), 84 },
	};
	uint8_t act[sizeof(exp1)];
	struct esdm_xdrbg xdrbg;
	enum xdrbg_seeding how;
	char what[128];
	size_t i;
	int ret;

	xdrbg_check_chunks(&kat_seed);

	for (how = xdrbg_seed_once; how < xdrbg_seed_ways; how++) {
		for (i = 0; i < sizeof(kat) / sizeof(kat[0]); i++) {
			ret = esdm_xdrbg_alloc(&xdrbg);
			ret |= xdrbg_seed_as(&xdrbg, how, &kat_seed, NULL, 0);
			ret |= esdm_xdrbg_generate(
				&xdrbg, kat[i].alphalen ? exp1 : NULL,
				kat[i].alphalen, act, kat[i].explen);
			snprintf(what, sizeof(what),
				 "not the known answer %s with the seed %s",
				 kat[i].name, xdrbg_seeding_name[how]);
			check(!ret && !esdm_kat_check(act, kat[i].exp,
						      kat[i].explen),
			      what);
			esdm_xdrbg_zero_free(&xdrbg);
		}

		/* An extraction takes the whole seed inserted */
		if (how == xdrbg_seed_once || how == xdrbg_seed_chunks_last)
			continue;

		ret = esdm_xdrbg_alloc(&xdrbg);
		i = xdrbg_insert_as(&xdrbg, how, &kat_seed, &ret);
		ret |= esdm_xdrbg_extract(&xdrbg, NULL, 0, act, sizeof(exp1));
		snprintf(what, sizeof(what),
			 "an extraction does not give exp1 with the seed %s",
			 xdrbg_seeding_name[how]);
		check(!ret && i == sizeof(seed) &&
			      !esdm_kat_check(act, exp1, sizeof(exp1)),
		      what);
		esdm_xdrbg_zero_free(&xdrbg);
	}
}

/* The known answers of the long seeds, instantiating and reseeding */
static void xdrbg_seeding_long(void)
{
	static const struct xdrbg_test_seed kat_seed[] = {
		{ seed_long, XDRBG_TEST_LONG_SEED, seed_long_chunks,
		  XDRBG_TEST_NCHUNKS(seed_long_chunks) },
		{ seed_long + XDRBG_TEST_LONG_SEED, XDRBG_TEST_LONG_SEED,
		  seed_long_chunks, XDRBG_TEST_NCHUNKS(seed_long_chunks) },
	};
	static const uint8_t *const exp[] = { exp_long_inst, exp_long_reseed };
	static const char *const step[] = { "instantiation", "reseed" };
	uint8_t act[sizeof(exp_long_inst)];
	struct esdm_xdrbg xdrbg;
	enum xdrbg_seeding how;
	char what[128];
	size_t i, done;
	int ret;

	check(sizeof(exp_long_inst) == sizeof(exp_long_reseed),
	      "the long known answers differ in length");
	for (i = 0; i < sizeof(seed_long); i++)
		seed_long[i] = (uint8_t)i;
	xdrbg_check_chunks(&kat_seed[0]);

	for (how = xdrbg_seed_once; how < xdrbg_seed_ways; how++) {
		ret = esdm_xdrbg_alloc(&xdrbg);
		for (i = 0; i < 2; i++) {
			ret |= xdrbg_seed_as(&xdrbg, how, &kat_seed[i],
					     alpha_long, XDRBG_TEST_LONG_ALPHA);
			ret |= esdm_xdrbg_generate(&xdrbg, alpha_long,
						   XDRBG_TEST_LONG_ALPHA, act,
						   sizeof(act));
			snprintf(
				what, sizeof(what),
				"not the known answer of the %s with the long seed %s",
				step[i], xdrbg_seeding_name[how]);
			check(!ret && !esdm_kat_check(act, exp[i], sizeof(act)),
			      what);
		}
		esdm_xdrbg_zero_free(&xdrbg);

		/* An extraction takes the whole seed inserted */
		if (how == xdrbg_seed_once || how == xdrbg_seed_chunks_last)
			continue;

		ret = esdm_xdrbg_alloc(&xdrbg);
		for (i = 0; i < 2; i++) {
			done = xdrbg_insert_as(&xdrbg, how, &kat_seed[i], &ret);
			ret |= esdm_xdrbg_extract(&xdrbg, alpha_long,
						  XDRBG_TEST_LONG_ALPHA, act,
						  sizeof(act));
			snprintf(
				what, sizeof(what),
				"an extraction does not give the known answer of the %s with the long seed %s",
				step[i], xdrbg_seeding_name[how]);
			check(!ret && done == XDRBG_TEST_LONG_SEED &&
				      !esdm_kat_check(act, exp[i], sizeof(act)),
			      what);
		}
		esdm_xdrbg_zero_free(&xdrbg);
	}
}

/* No generate before the seeding, nor while a seed is inserted */
static void xdrbg_insert(void)
{
	uint8_t act[sizeof(exp1)];
	struct esdm_xdrbg xdrbg;
	int ret;

	ret = esdm_xdrbg_alloc(&xdrbg);
	ret |= esdm_xdrbg_insert(&xdrbg, seed, sizeof(seed));
	check(!ret && esdm_xdrbg_generate(&xdrbg, NULL, 0, act, sizeof(act)) ==
			      -EOPNOTSUPP,
	      "an XDRBG generates before its instantiation");
	ret = esdm_xdrbg_seed(&xdrbg, NULL, 0, NULL, 0);

	/* No generate while a seed is inserted, the state stays */
	ret |= esdm_xdrbg_insert(&xdrbg, seed, sizeof(seed));
	check(!ret && esdm_xdrbg_generate(&xdrbg, NULL, 0, act, sizeof(act)) ==
			      -EBUSY,
	      "an XDRBG generates while its seed is inserted");
	check(esdm_xdrbg_seed_initialized(&xdrbg),
	      "a refused generate discarded the state");

	/* Zeroized, it is unseeded, and its instantiation as before */
	esdm_xdrbg_zero(&xdrbg);
	check(!esdm_xdrbg_seed_initialized(&xdrbg) &&
		      esdm_xdrbg_generate(&xdrbg, NULL, 0, act, sizeof(act)) ==
			      -EOPNOTSUPP,
	      "a zeroized XDRBG generates");
	ret = esdm_xdrbg_seed(&xdrbg, seed, sizeof(seed), NULL, 0);
	ret |= esdm_xdrbg_generate(&xdrbg, NULL, 0, act, sizeof(act));
	check(!ret && !esdm_kat_check(act, exp1, sizeof(exp1)),
	      "not the known answer after zeroization");

	esdm_xdrbg_zero_free(&xdrbg);
}

/*
 * The XOF of the crypto backend, counting the initializations of its contexts.
 * Static, as esdm_default_xof_cb points to it.
 */
static const struct esdm_xof_cb *xof_real;
static struct esdm_xof_cb xof_counting;
static unsigned int xof_inits;

static int xof_counting_init(void *xof)
{
	xof_inits++;
	return xof_real->xof_init(xof);
}

/*
 * A zeroization initializes the XOF context again, which wipes what it
 * absorbed, see sha3_tester.c for the built-in SHAKE256
 */
static void xdrbg_zero_wipes(void)
{
	struct esdm_xdrbg xdrbg;
	unsigned int inits;
	int ret;

	xof_real = esdm_default_xof_cb;
	xof_counting = *xof_real;
	xof_counting.xof_init = xof_counting_init;
	esdm_default_xof_cb = &xof_counting;

	ret = esdm_xdrbg_alloc(&xdrbg);
	ret |= esdm_xdrbg_insert(&xdrbg, seed, sizeof(seed));
	inits = xof_inits;
	esdm_xdrbg_zero(&xdrbg);
	check(!ret && xof_inits == inits + 1,
	      "a zeroization leaves what the XOF context absorbed");
	esdm_xdrbg_zero_free(&xdrbg);

	esdm_default_xof_cb = xof_real;
}

/* An extraction is a reseed and a generate, both with its alpha */
static void xdrbg_extract(void)
{
	static const uint8_t alpha[] = { 'E', 'S', 'D', 'M' };
	uint8_t a_out[64], b_out[64];
	struct esdm_xdrbg a, b;
	unsigned int i;
	int ret;

	ret = esdm_xdrbg_alloc(&a);
	ret |= esdm_xdrbg_alloc(&b);
	check(esdm_xdrbg_extract(&a, alpha, sizeof(alpha), a_out,
				 sizeof(a_out)) == -EINVAL,
	      "an XDRBG not initialized for the seed is extracted from");

	/* Instantiate, then reseed */
	for (i = 0; i < 2; i++) {
		ret |= esdm_xdrbg_insert(&a, seed, sizeof(seed));
		ret |= esdm_xdrbg_extract(&a, alpha, sizeof(alpha), a_out,
					  sizeof(a_out));
		ret |= esdm_xdrbg_seed(&b, seed, sizeof(seed), alpha,
				       sizeof(alpha));
		ret |= esdm_xdrbg_generate(&b, alpha, sizeof(alpha), b_out,
					   sizeof(b_out));
		check(!ret && !memcmp(a_out, b_out, sizeof(a_out)),
		      "an extraction is not a seed and a generate");
	}

	esdm_xdrbg_zero_free(&a);
	esdm_xdrbg_zero_free(&b);
}

/* A seed off by its first byte must not produce the known answer */
static void xdrbg_negative(void)
{
	uint8_t act[sizeof(exp1)], mod[sizeof(seed)];
	struct esdm_xdrbg xdrbg;

	check(!esdm_kat_modify(mod, seed, sizeof(mod)) &&
		      !esdm_xdrbg_alloc(&xdrbg) &&
		      !esdm_xdrbg_seed(&xdrbg, mod, sizeof(mod), NULL, 0) &&
		      !esdm_xdrbg_generate(&xdrbg, NULL, 0, act, sizeof(act)) &&
		      !esdm_kat_check_differs(act, exp1, sizeof(exp1)),
	      "a different seed gives the known answer");
	esdm_xdrbg_zero_free(&xdrbg);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	xdrbg_reference();
	xdrbg_reseed();
	xdrbg_chunks();
	xdrbg_seeding();
	xdrbg_seeding_long();
	xdrbg_insert();
	xdrbg_zero_wipes();
	xdrbg_extract();
	xdrbg_negative();

	if (!failures)
		printf("XDRBG-256: passed\n");

	return failures ? 1 : 0;
}
