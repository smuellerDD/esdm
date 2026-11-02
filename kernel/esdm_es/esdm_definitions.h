/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_DEFINITIONS_H
#define _ESDM_DEFINITIONS_H

#include <linux/fips.h>
#include <linux/math64.h>
#include <linux/minmax.h>
#include <linux/slab.h>

/* Security strength and seed sizes, as the ESDM has them */
#include "esdm_seed_sizes.h"

/*************************** General ESDM parameter ***************************/

/*
 * Specific settings for different use cases: the SP800-90C oversampling of a
 * FIPS kernel
 */
#ifdef CONFIG_CRYPTO_FIPS
#define ESDM_OVERSAMPLE_ES_BITS ESDM_SP80090C_OVERSAMPLE_ES_BITS
#define ESDM_SEED_BUFFER_INIT_ADD_BITS ESDM_SP80090C_SEED_BUFFER_INIT_ADD_BITS
#else /* CONFIG_CRYPTO_FIPS */
#define ESDM_OVERSAMPLE_ES_BITS 0
#define ESDM_SEED_BUFFER_INIT_ADD_BITS 0
#endif /* CONFIG_CRYPTO_FIPS */

/* Alignmask that is intended to be identical to CRYPTO_MINALIGN */
#define ESDM_KCAPI_ALIGN ARCH_KMALLOC_MINALIGN

/****************************** Helper code ***********************************/

/*
 * The entropy rate is the number of events for 256 bits of entropy. It is any
 * value from the default up to U32_MAX, which credits no entropy at all - set by
 * the module parameter or by user space through the ESDM_*_CONF ioctl. The
 * conversions are therefore done in 64 bits: in 32 bits, a large rate wraps the
 * product around to an arbitrary, possibly tiny, number of events.
 */

/*
 * Convert entropy in bits into nr. of events with at least that entropy
 * content. Round up: esdm_data_to_entropy() rounds down, so converting the
 * rounded-down number of events back yields less than entropy_bits whenever
 * the rate is not a multiple of ESDM_DRNG_SECURITY_STRENGTH_BITS.
 */
static inline u32 esdm_entropy_to_data(u32 entropy_bits, u32 entropy_rate)
{
	u64 events = ((u64)entropy_bits * entropy_rate +
		      ESDM_DRNG_SECURITY_STRENGTH_BITS - 1) /
		     ESDM_DRNG_SECURITY_STRENGTH_BITS;

	return (u32)min_t(u64, events, U32_MAX);
}

/* Convert number of events into entropy value. */
static inline u32 esdm_data_to_entropy(u32 num, u32 entropy_rate)
{
	/* At most num, as the rate is at least ESDM_DRNG_SECURITY_STRENGTH_BITS */
	return (u32)min_t(u64,
			  div_u64((u64)num * ESDM_DRNG_SECURITY_STRENGTH_BITS,
				  entropy_rate),
			  U32_MAX);
}

static inline u32 atomic_read_u32(atomic_t *v)
{
	return (u32)atomic_read(v);
}

static inline u32 esdm_security_strength(void)
{
	/*
	 * We use a DRBG to read the entropy in the entropy pool.
	 * This limits the output entropy to the security strength
	 * of the DRBG.
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
	/*
	 * adjusted by 1 bit too reach full entropy in internal state after DRBG
	 * update
	 */
	return esdm_sp80090c_compliant() ? (ESDM_OVERSAMPLE_ES_BITS + 1) : 0;
}

static inline u32 esdm_init_osr(void)
{
	/*
	 * adjusted by 1 bit too reach full entropy in internal state after DRBG
	 * update
	 */
	return esdm_sp80090c_compliant() ?
		       (ESDM_SEED_BUFFER_INIT_ADD_BITS + 1) :
		       0;
}

static inline u32 esdm_reduce_by_osr(u32 entropy_bits)
{
	u32 osr_bits = esdm_compress_osr();

	return (entropy_bits >= osr_bits) ? (entropy_bits - osr_bits) : 0;
}

static inline u32 esdm_reduce_by_init_osr(u32 entropy_bits)
{
	u32 osr_bits = esdm_init_osr();

	return (entropy_bits >= osr_bits) ? (entropy_bits - osr_bits) : 0;
}

/*
 * round requested bits to full blocks of DRBG output with bits per block typically
 * set to the DRBG's security strength
 */
static inline u32 esdm_full_blocks(u32 requested_bits, u32 bits_per_block)
{
	return (requested_bits + bits_per_block - 1) / bits_per_block;
}

#endif /* _ESDM_DEFINITIONS_H */
