/*
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

#ifndef _ESDM_XDRBG_H
#define _ESDM_XDRBG_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#include "esdm_xof.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XDRBG-256 (J. Kelsey, S. Lucks, S. Mueller: XDRBG: A Proposed Deterministic
 * Random Bit Generator Based on Any XOF, IACR ToSC 2024(1)): the XDRBG over
 * SHAKE256 with a state V of 64 bytes, as its reference implementation
 * https://github.com/smuellerDD/xdrbg and the one of leancrypto operate it:
 *
 *	instantiate:	V = SHAKE256(seed || encode(alpha, 0), 64)
 *	reseed:		V = SHAKE256(V || seed || encode(alpha, 1), 64)
 *	generate:	V || out = SHAKE256(V || encode(alpha, 2), 64 + |out|),
 *			in chunks of at most ESDM_XDRBG_MAX_CHUNK bytes of
 *			output, each one with the V the previous one left
 *
 * with encode(alpha, n) = alpha || (n * 85 + |alpha|) as one byte (appendix
 * B.2 of the specification), so alpha has at most 84 bytes.
 *
 * The interface is the one of the XDRBG of leancrypto (lc_rng_seed(),
 * lc_rng_generate(), lc_rng_zero() of lc_xdrbg256_drng): esdm_xdrbg_seed()
 * instantiates, or reseeds, esdm_xdrbg_generate() generates, esdm_xdrbg_zero()
 * returns to the unseeded state.
 *
 * On top of it, the seed can be inserted as it comes, which is how the
 * entropy pools absorb their data: the SHAKE256 of the next instantiation
 * or reseed absorbs V and every insert right away (esdm_xdrbg_insert()), and
 * the seed esdm_xdrbg_seed() is given follows what was inserted. A pool
 * extracts (esdm_xdrbg_extract()): it reseeds with what it absorbed and
 * generates, both with its alpha. The output comes from the same squeeze the
 * next V does, but never reveals it, which gives the backtracking resistance;
 * a single unknown input after an extraction suffices for the prediction
 * resistance of the next one.
 *
 * The SHAKE256 is esdm_default_xof_cb: the one of the crypto backend, or the
 * kernel's in the kernel module esdm_es, whose interrupt and scheduler
 * entropy sources condition their time stamps with this XDRBG-256 as well.
 * The caller serializes the calls on one XDRBG.
 */

/* Size of the state V, which is the most entropy a pool holds */
#define ESDM_XDRBG_V_SIZE 64

/* The XDRBG encodes the length of alpha in a byte along with n */
#define ESDM_XDRBG_MAX_ALPHA 84

/*
 * Most output of one generate step, maxout of the specification: what three
 * blocks of the SHAKE256 hold besides the new V
 */
#define ESDM_XDRBG_SHAKE256_BLOCK 136
#define ESDM_XDRBG_MAX_CHUNK (3 * ESDM_XDRBG_SHAKE256_BLOCK - ESDM_XDRBG_V_SIZE)

struct esdm_xdrbg {
	/* The XOF the context is of */
	const struct esdm_xof_cb *xof_cb;

	/*
	 * SHAKE256 context, once initialized for the seed: it absorbs V and
	 * the data inserted for the next instantiation or reseed
	 */
	void *xof;

	/* The state V */
	uint8_t v[ESDM_XDRBG_V_SIZE];

	/* The XDRBG has a state V: it generates, and the next seed reseeds */
	bool initially_seeded;

	/* The context absorbs: the XDRBG is initialized for the seed */
	bool seed_initialized;

	/* The context absorbed data for the next seed besides V */
	bool inserted;
};

/*
 * Allocate the XOF context of @xdrbg, which is unseeded and not initialized
 * for the seed
 */
int esdm_xdrbg_alloc(struct esdm_xdrbg *xdrbg);

/*
 * Discard the state of @xdrbg and all it absorbed: unseeded, it has to be
 * initialized for the seed again
 */
void esdm_xdrbg_zero(struct esdm_xdrbg *xdrbg);

/* Zeroize @xdrbg and release its XOF context */
void esdm_xdrbg_zero_free(struct esdm_xdrbg *xdrbg);

/*
 * Instantiate @xdrbg - reseed it, once seeded - with the data inserted since
 * the last time followed by @seed of @seedlen bytes, and the additional input
 * @alpha of at most ESDM_XDRBG_MAX_ALPHA bytes, initializing it for the seed
 * unless it is.
 * -EINVAL for a longer alpha. On any other error, its state is discarded.
 */
int esdm_xdrbg_seed(struct esdm_xdrbg *xdrbg, const uint8_t *seed,
		    size_t seedlen, const uint8_t *alpha, size_t alphalen);

/*
 * Generate @outlen bytes into @out with the additional input @alpha of at most
 * ESDM_XDRBG_MAX_ALPHA bytes. -EINVAL for a longer alpha, -EOPNOTSUPP unless
 * @xdrbg is seeded, -EBUSY with data inserted for a seed that did not happen
 * yet. On any other error, its state is discarded.
 */
int esdm_xdrbg_generate(struct esdm_xdrbg *xdrbg, const uint8_t *alpha,
			size_t alphalen, uint8_t *out, size_t outlen);

/*
 * Initialize @xdrbg for the seed of a new instantiation unless it is
 * initialized for a seed: unseeded, it absorbs the seed of the instantiate.
 * -EOPNOTSUPP without a context.
 */
int esdm_xdrbg_seed_init(struct esdm_xdrbg *xdrbg);

/* Is @xdrbg initialized for the seed? */
static inline bool esdm_xdrbg_seed_initialized(const struct esdm_xdrbg *xdrbg)
{
	return xdrbg->seed_initialized;
}

/*
 * Insert @inlen bytes of data into the seed of the next instantiation or
 * reseed, initializing @xdrbg for the seed unless it is. On an error, its state
 * is discarded.
 */
int esdm_xdrbg_insert(struct esdm_xdrbg *xdrbg, const uint8_t *in,
		      size_t inlen);

/*
 * Extraction from @xdrbg, initialized for the seed: reseed - instantiate, the
 * first time - with what it absorbed, and generate @outlen bytes into @out,
 * both with the additional input @alpha of at most ESDM_XDRBG_MAX_ALPHA bytes.
 * -EINVAL unless @xdrbg is initialized for the seed, or for a longer alpha. On
 * any other error, its state is discarded.
 */
int esdm_xdrbg_extract(struct esdm_xdrbg *xdrbg, const uint8_t *alpha,
		       size_t alphalen, uint8_t *out, size_t outlen);

/* Known-answer test of the XDRBG-256 and with it of its SHAKE256 */
int esdm_xdrbg_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_XDRBG_H */
