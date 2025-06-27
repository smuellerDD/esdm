/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_DEFINITIONS_H
#define _ESDM_DEFINITIONS_H

#include <linux/fips.h>
#include <linux/slab.h>

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

/* low 9 bits - can set 512 bits of entropy max */
#define ESDM_ES_MGR_REQ_BITS_MASK 0x1ff
#define ESDM_ES_MGR_RESET_BIT 0x80000000

/****************************** Helper code ***********************************/

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
	return ESDM_DRNG_SECURITY_STRENGTH_BITS;
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
