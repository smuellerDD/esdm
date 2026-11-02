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

/*
 * ESDM_DRNG_INIT_SEED_SIZE_BYTES: in the kernel module esdm_es, which
 * compiles esdm_xdrbg.c, the one of its own esdm_definitions.h
 */
#include "esdm_definitions.h"
#include "esdm_xof.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XDRBG-256 (J. Kelsey, S. Lucks, S. Mueller: XDRBG: A Proposed Deterministic
 * Random Bit Generator Based on Any XOF, IACR ToSC 2024(1)): the XDRBG over
 * SHAKE256 with a state V of 64 bytes, as the kernel module esdm_es operates
 * the entropy pools of its interrupt and scheduler entropy sources.
 *
 *	instantiate:	V = SHAKE256(seed || encode(alpha, 0), 64)
 *	reseed:		V = SHAKE256(V || seed || encode(alpha, 1), 64)
 *	generate:	V || out = SHAKE256(V || encode(alpha, 2), 64 + |out|)
 *
 * with encode(alpha, n) = alpha || (n * 85 + |alpha|) as one byte (appendix
 * B.2 of the specification). The seed of a pool is all data inserted into it
 * since its last extraction: the SHAKE256 of the next reseed - or of the
 * instantiation, before the first extraction - absorbs V and every insert as
 * it comes, and an extraction is a reseed followed by a generate. The output
 * comes from the same squeeze the next V does, but never reveals it, which
 * gives the backtracking resistance; a single unknown input after an
 * extraction suffices for the prediction resistance of the next one.
 *
 * The SHAKE256 is esdm_default_xof_cb, the kernel's in the module. The caller
 * serializes the calls on one XDRBG.
 */

/* Size of the state V, which is the most entropy a pool holds */
#define ESDM_XDRBG_V_SIZE 64

/* The XDRBG encodes the length of alpha in a byte along with n */
#define ESDM_XDRBG_MAX_ALPHA 84

/* Most output one extraction generates */
#define ESDM_XDRBG_MAX_OUT ESDM_DRNG_INIT_SEED_SIZE_BYTES

struct esdm_xdrbg {
	/* The XOF the context is of */
	const struct esdm_xof_cb *xof_cb;

	/*
	 * SHAKE256 context of the next reseed, or instantiation: it absorbs V
	 * and the data inserted since the last extraction
	 */
	void *xof;

	/* The context absorbs: the XDRBG is started */
	bool started;

	/* The XDRBG has a state V: the next extraction reseeds it */
	bool instantiated;
};

/* Allocate the XOF context of @xdrbg, which is not started yet */
int esdm_xdrbg_alloc(struct esdm_xdrbg *xdrbg);

/* Zeroize and release the XOF context of @xdrbg */
void esdm_xdrbg_free(struct esdm_xdrbg *xdrbg);

/*
 * Start @xdrbg unless it is: a new instantiation, without state, absorbing
 * its seed. -EOPNOTSUPP without a context.
 */
int esdm_xdrbg_start(struct esdm_xdrbg *xdrbg);

/* Discard the state of @xdrbg and all it absorbed: it has to be started again */
void esdm_xdrbg_discard(struct esdm_xdrbg *xdrbg);

/* Is @xdrbg started? */
static inline bool esdm_xdrbg_started(const struct esdm_xdrbg *xdrbg)
{
	return xdrbg->started;
}

/*
 * Insert @inlen bytes of data into the seed of the next extraction, starting
 * @xdrbg if it is not. On an error, its state is discarded.
 */
int esdm_xdrbg_insert(struct esdm_xdrbg *xdrbg, const uint8_t *in,
		      size_t inlen);

/*
 * Extraction from the started @xdrbg: reseed - instantiate, the first time -
 * with what it absorbed, and generate @outlen bytes (at most
 * ESDM_XDRBG_MAX_OUT) into @out, all with the additional input @alpha (at
 * most ESDM_XDRBG_MAX_ALPHA bytes). On an error, its state is discarded.
 */
int esdm_xdrbg_extract(struct esdm_xdrbg *xdrbg, const uint8_t *alpha,
		       size_t alphalen, uint8_t *out, size_t outlen);

/* Known-answer test of the XDRBG-256 and with it of its SHAKE256 */
int esdm_xdrbg_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_XDRBG_H */
