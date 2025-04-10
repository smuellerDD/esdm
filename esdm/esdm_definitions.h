/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef _ESDM_DEFINITIONS_H
#define _ESDM_DEFINITIONS_H

#include <stdint.h>
#include <time.h>

#include "atomic.h"
#include "config.h"
#include "esdm_hash_common.h"
#include "math_helper.h"

/*************************** General ESDM parameter ***************************/

/* Security strength of ESDM -- this must match DRNG security strength */
#define ESDM_DRNG_SECURITY_STRENGTH_BYTES 32
#define ESDM_DRNG_SECURITY_STRENGTH_BITS (ESDM_DRNG_SECURITY_STRENGTH_BYTES * 8)
#define ESDM_DRNG_INIT_SEED_SIZE_BITS                                          \
	(ESDM_DRNG_SECURITY_STRENGTH_BITS + ESDM_SEED_BUFFER_INIT_ADD_BITS)
#define ESDM_DRNG_INIT_SEED_SIZE_BYTES (ESDM_DRNG_INIT_SEED_SIZE_BITS >> 3)

/*
 * SP800-90A defines a maximum request size of 1<<16 bytes. The given value is
 * considered a safer margin.
 *
 * This value is allowed to be changed.
 */
#define ESDM_DRNG_MAX_REQSIZE (1 << 12)

/*
 * SP800-90A defines a maximum number of requests between reseeds of 2^48.
 * The given value is considered a much safer margin, balancing requests for
 * frequent reseeds with the need to conserve entropy. This value MUST NOT be
 * larger than INT_MAX because it is used in an atomic_t.
 *
 * This value is allowed to be changed.
 */
#define ESDM_DRNG_RESEED_THRESH (1 << 20)

/*
 * Maximum DRNG generation operations without reseed having full entropy
 * This value defines the absolute maximum value of DRNG generation operations
 * without a reseed holding full entropy. ESDM_DRNG_RESEED_THRESH is the
 * threshold when a new reseed is attempted. But it is possible that this fails
 * to deliver full entropy. In this case the DRNG will continue to provide data
 * even though it was not reseeded with full entropy. To avoid in the extreme
 * case that no reseed is performed for too long, this threshold is enforced.
 * If that absolute low value is reached, the ESDM is marked as not operational.
 *
 * This value is allowed to be changed.
 */
#define ESDM_DRNG_MAX_WITHOUT_RESEED (1 << 30)

/*
 * Min required seed entropy is 128 bits covering the minimum entropy
 * requirement of SP800-131A and the German BSI's TR02102.
 *
 * This value is allowed to be changed.
 */
#define ESDM_FULL_SEED_ENTROPY_BITS ESDM_DRNG_SECURITY_STRENGTH_BITS
#define ESDM_MIN_SEED_ENTROPY_BITS 128
#define ESDM_INIT_ENTROPY_BITS 32

/* AIS20/31: NTG.1.4 minimum entropy rate for one entropy source*/
#define ESDM_AIS2031_NPTRNG_MIN_ENTROPY 240

/*
 * Wakeup value
 *
 * This value is allowed to be changed but must not be larger than the
 * digest size of the hash operation used update the aux_pool.
 */
#define ESDM_WRITE_WAKEUP_ENTROPY (ESDM_NUM_AUX_POOLS * SHA512_DIGEST_SIZE)

/*
 * Define the digest size for the conditioning components
 */
#define ESDM_MAX_DIGESTSIZE SHA512_DIGEST_SIZE

/*
 * Oversampling factor of timer-based events to obtain
 * ESDM_DRNG_SECURITY_STRENGTH_BYTES. This factor is used when a
 * high-resolution time stamp is not available. In this case, jiffies and
 * register contents are used to fill the entropy pool. These noise sources
 * are much less entropic than the high-resolution timer. The entropy content
 * is the entropy content assumed with ESDM_[IRQ|SCHED]_ENTROPY_BITS divided by
 * ESDM_ES_OVERSAMPLING_FACTOR.
 *
 * This value is allowed to be changed.
 */
#define ESDM_ES_OVERSAMPLING_FACTOR 10

/* Alignmask that is intended to be identical to CRYPTO_MINALIGN */
#define ESDM_KCAPI_ALIGN 8

/*
 * This definition must provide a buffer that is equal to SHASH_DESC_ON_STACK
 * as it will be casted into a struct hash_ctx.
 */
#define ESDM_POOL_SIZE HASH_MAX_DESCSIZE

/* Sleep time for poll operations */
static const struct timespec poll_ts = { .tv_sec = 0, .tv_nsec = 1U << 29 };

/****************************** Helper code ***********************************/

static inline uint32_t esdm_fast_noise_entropylevel(uint32_t ent_bits,
						    uint32_t requested_bits)
{
	/* Obtain entropy statement */
	ent_bits = ent_bits * requested_bits / ESDM_DRNG_SECURITY_STRENGTH_BITS;
	/* Cap entropy to buffer size in bits */
	ent_bits = min_uint32(ent_bits, requested_bits);
	return ent_bits;
}

/* Convert entropy in bits into nr. of events with the same entropy content. */
static inline uint32_t esdm_entropy_to_data(uint32_t entropy_bits,
					    uint32_t entropy_rate)
{
	return ((entropy_bits * entropy_rate) /
		ESDM_DRNG_SECURITY_STRENGTH_BITS);
}

/* Convert number of events into entropy value. */
static inline uint32_t esdm_data_to_entropy(uint32_t num, uint32_t entropy_rate)
{
	return ((num * ESDM_DRNG_SECURITY_STRENGTH_BITS) / entropy_rate);
}

static inline uint32_t atomic_read_u32(atomic_t *v)
{
	return (uint32_t)atomic_read(v);
}

#endif /* _ESDM_DEFINITIONS_H */
