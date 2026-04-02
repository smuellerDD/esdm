/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_HASH_DRBG_H
#define ESDM_HASH_DRBG_H

#include "esdm_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(ESDM_DRBG_HASH_STATELEN) || !defined(ESDM_DRBG_HASH_BLOCKLEN) ||      \
	!defined(ESDM_DRBG_HASH_CORE)
#error "Do not include this header file directly! Use esdm_hash_drbg_<hashtype>.h"
#endif

struct esdm_drbg_hash_state {
	struct esdm_drbg_state drbg;
	struct esdm_hash_ctx hash_ctx; /* Cipher handle - HASH_MAX_STATE_SIZE */
	uint8_t *V; /* internal state 10.1.1.1 1a) - DRBG_STATELEN */
	uint8_t *C; /* static value 10.1.1.1 1b) - DRBG_STATELEN */
	uint8_t *scratchpad; /* working mem DRBG_STATELEN + DRBG_BLOCKLEN */

	/* Number of RNG requests since last reseed -- 10.1.1.1 1c) */
	size_t reseed_ctr;
};

#define ESDM_DRBG_HASH_STATE_SIZE(x)                                             \
	(3 * ESDM_DRBG_HASH_STATELEN + ESDM_DRBG_HASH_BLOCKLEN +                   \
	 ESDM_HASH_STATE_SIZE(x))
#define ESDM_DRBG_HASH_CTX_SIZE(x)                                               \
	(ESDM_DRBG_HASH_STATE_SIZE(x) + sizeof(struct esdm_drbg_hash_state))

void esdm_drbg_hash_seed(struct esdm_drbg_state *drbg, struct esdm_drbg_string *seed);
size_t esdm_drbg_hash_generate(struct esdm_drbg_state *drbg, uint8_t *buf,
			     size_t buflen, struct esdm_drbg_string *addtl);
void esdm_drbg_hash_zero(struct esdm_drbg_state *drbg);

#define _ESDM_DRBG_HASH_SET_CTX(name, ctx, offset)                               \
	_ESDM_DRBG_SET_CTX((&name->drbg), esdm_drbg_hash_seed,                     \
			 esdm_drbg_hash_generate, esdm_drbg_hash_zero);            \
	_ESDM_HASH_SET_CTX((&name->hash_ctx), ESDM_DRBG_HASH_CORE, ctx, offset);   \
	name->V = (uint8_t *)((uint8_t *)ctx + offset +                        \
			      ESDM_HASH_STATE_SIZE(ESDM_DRBG_HASH_CORE));          \
	name->C = (uint8_t *)((uint8_t *)ctx + offset +                        \
			      ESDM_HASH_STATE_SIZE(ESDM_DRBG_HASH_CORE) +          \
			      ESDM_DRBG_HASH_STATELEN);                          \
	name->scratchpad = (uint8_t *)((uint8_t *)ctx + offset +               \
				       ESDM_HASH_STATE_SIZE(ESDM_DRBG_HASH_CORE) + \
				       2 * ESDM_DRBG_HASH_STATELEN);             \
	name->reseed_ctr = 0

#define ESDM_DRBG_HASH_SET_CTX(name)                                             \
	_ESDM_DRBG_HASH_SET_CTX(name, name, sizeof(struct esdm_drbg_hash_state))

/**
 * @brief Allocate stack memory for the Hash DRBG context
 *
 * @param [in] name Name of the stack variable
 */
#define ESDM_DRBG_HASH_CTX_ON_STACK(name)                                        \
	ESDM_ALIGNED_BUFFER(name##_ctx_buf,                                      \
			  ESDM_DRBG_HASH_CTX_SIZE(ESDM_DRBG_HASH_CORE), uint64_t); \
	struct esdm_drbg_hash_state *name##_hash =                               \
		(struct esdm_drbg_hash_state *)name##_ctx_buf;                   \
	ESDM_DRBG_HASH_SET_CTX(name##_hash);                                     \
	struct esdm_drbg_state *name = (struct esdm_drbg_state *)name##_hash;      \
	esdm_drbg_hash_zero(name)

/**
 * @brief Allocate Hash DRBG context on heap
 *
 * @param [out] drbg Allocated Hash DRBG context
 *
 * @return: 0 on success, < 0 on error
 */
int esdm_drbg_hash_alloc(struct esdm_drbg_state **drbg);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_HASH_DRBG_H */
