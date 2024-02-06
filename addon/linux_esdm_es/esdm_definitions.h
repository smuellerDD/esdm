/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_DEFINITIONS_H
#define _ESDM_DEFINITIONS_H

#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <linux/fips.h>
#include <linux/slab.h>

#include "esdm_hash_kcapi.h"

/*************************** General ESDM parameter ***************************/

/*
 * Specific settings for different use cases
 */
#ifdef CONFIG_CRYPTO_FIPS
#define ESDM_OVERSAMPLE_ES_BITS 64
#define ESDM_SEED_BUFFER_INIT_ADD_BITS 128
#else /* CONFIG_CRYPTO_FIPS */
#define ESDM_OVERSAMPLE_ES_BITS 0
#define ESDM_SEED_BUFFER_INIT_ADD_BITS 0
#endif /* CONFIG_CRYPTO_FIPS */

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

/*
 * If the switching support is configured, we must provide support up to
 * the largest digest size. Without switching support, we know it is only
 * the built-in digest size.
 */
#define ESDM_MAX_DIGESTSIZE ESDM_HASH_DIGESTSIZE_BYTES

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
#define ESDM_KCAPI_ALIGN ARCH_KMALLOC_MINALIGN

/*
 * This definition must provide a buffer that is equal to SHASH_DESC_ON_STACK
 * as it will be casted into a struct shash_desc.
 */
#define ESDM_POOL_SIZE (sizeof(struct shash_desc) + HASH_MAX_DESCSIZE)

/* low 9 bits - can set 512 bits of entropy max */
#define ESDM_ES_MGR_REQ_BITS_MASK 0x1ff
#define ESDM_ES_MGR_RESET_BIT 0x80000000

/****************************** Helper code ***********************************/

static inline u32 esdm_fast_noise_entropylevel(u32 ent_bits, u32 requested_bits)
{
	/* Obtain entropy statement */
	ent_bits = ent_bits * requested_bits / ESDM_DRNG_SECURITY_STRENGTH_BITS;
	/* Cap entropy to buffer size in bits */
	ent_bits = min_t(u32, ent_bits, requested_bits);
	return ent_bits;
}

/* Convert entropy in bits into nr. of events with the same entropy content. */
static inline u32 esdm_entropy_to_data(u32 entropy_bits, u32 entropy_rate)
{
	return ((entropy_bits * entropy_rate) /
		ESDM_DRNG_SECURITY_STRENGTH_BITS);
}

/* Convert number of events into entropy value. */
static inline u32 esdm_data_to_entropy(u32 num, u32 entropy_rate)
{
	return ((num * ESDM_DRNG_SECURITY_STRENGTH_BITS) / entropy_rate);
}

static inline u32 atomic_read_u32(atomic_t *v)
{
	return (u32)atomic_read(v);
}

/* Obtain the digest size provided by the used hash in bits */
static inline u32 esdm_get_digestsize(void)
{
	return ESDM_HASH_DIGESTSIZE_BITS;
}

static inline u32 esdm_security_strength(void)
{
	/*
	 * We use a hash to read the entropy in the entropy pool. According to
	 * SP800-90B table 1, the entropy can be at most the digest size.
	 * Considering this together with the last sentence in section 3.1.5.1.2
	 * the security strength of a (approved) hash is equal to its output
	 * size. On the other hand the entropy cannot be larger than the
	 * security strength of the used DRBG.
	 */
	return min_t(u32, ESDM_FULL_SEED_ENTROPY_BITS, esdm_get_digestsize());
}

static inline bool esdm_sp80090c_compliant(void)
{
	/* SP800-90C compliant oversampling is only requested in FIPS mode */
	return fips_enabled;
}

static inline u32 esdm_compress_osr(void)
{
	return esdm_sp80090c_compliant() ? ESDM_OVERSAMPLE_ES_BITS : 0;
}

static inline u32 esdm_reduce_by_osr(u32 entropy_bits)
{
	u32 osr_bits = esdm_compress_osr();

	return (entropy_bits >= osr_bits) ? (entropy_bits - osr_bits) : 0;
}

#endif /* _ESDM_DEFINITIONS_H */
