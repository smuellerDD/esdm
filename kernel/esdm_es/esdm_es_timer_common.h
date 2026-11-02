/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM Slow Noise Source: Time stamp array handling
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_TIMER_COMMON_H
#define _ESDM_ES_TIMER_COMMON_H

#include "esdm_es_mgr_cb.h"

/************************** Configuration parameters **************************/
/*
choice
	prompt "ESDM Entropy Collection Pool Size"
	default ESDM_COLLECTION_SIZE_1024
	depends on ESDM_TIMER_COMMON
	help
	  Select the size of the ESDM entropy collection pool
	  storing data for the interrupt as well as the scheduler
	  entropy sources without performing a compression
	  operation. The larger the collection size is, the faster
	  the average interrupt handling will be. The collection
	  size represents the number of bytes of the per-CPU memory
	  used to batch up entropy event data.

	  The default value is good for regular operations. Choose
	  larger sizes for servers that have no memory limitations.
	  If runtime memory is precious, choose a smaller size.

	  The collection size is unrelated to the entropy rate
	  or the amount of entropy the ESDM can process.

	config ESDM_COLLECTION_SIZE_32
	depends on !ESDM_OVERSAMPLE_ENTROPY_SOURCES
		bool "32 interrupt events"

	config ESDM_COLLECTION_SIZE_256
	depends on !ESDM_OVERSAMPLE_ENTROPY_SOURCES
		bool "256 interrupt events"

	config ESDM_COLLECTION_SIZE_512
		bool "512 interrupt events"

	config ESDM_COLLECTION_SIZE_1024
		bool "1024 interrupt events (default)"

	config ESDM_COLLECTION_SIZE_2048
		bool "2048 interrupt events"

	config ESDM_COLLECTION_SIZE_4096
		bool "4096 interrupt events"

	config ESDM_COLLECTION_SIZE_8192
		bool "8192 interrupt events"

endchoice

config ESDM_COLLECTION_SIZE
	int
	default 32 if ESDM_COLLECTION_SIZE_32
	default 256 if ESDM_COLLECTION_SIZE_256
	default 512 if ESDM_COLLECTION_SIZE_512
	default 1024 if ESDM_COLLECTION_SIZE_1024
	default 2048 if ESDM_COLLECTION_SIZE_2048
	default 4096 if ESDM_COLLECTION_SIZE_4096
	default 8192 if ESDM_COLLECTION_SIZE_8192

 */

/*
 * The oversampling rate is the default number of events per bit of entropy.
 * The health test cutoffs scale with it and saturate at 15 (esdm_health.h),
 * so the ring size derived from it below is the only bound.
 */
#if !defined(ESDM_ES_OSR) || ESDM_ES_OSR < 1 || ESDM_ES_OSR > 25
#error "ESDM_ES_OSR must be within 1 to 25"
#endif

/*
 * Events the largest request takes at the default rate: the DRBG blocks of an
 * initial seed with the oversampling of each, plus the oversampling
 * esdm_es_drbg_avail_entropy() deducts twice. One CPU's ring must hold them,
 * or the source of a single CPU system never serves that request.
 */
#define ESDM_ES_OSR_BITS (ESDM_OVERSAMPLE_ES_BITS + 1)
#define ESDM_ES_MAX_REQUEST_EVENTS                                             \
	(ESDM_ES_OSR *                                                         \
	 (((ESDM_DRNG_INIT_SEED_SIZE_BITS + ESDM_DRNG_SECURITY_STRENGTH_BITS - \
	    1) / ESDM_DRNG_SECURITY_STRENGTH_BITS) *                           \
		  (ESDM_DRNG_SECURITY_STRENGTH_BITS + ESDM_ES_OSR_BITS) +      \
	  2 * ESDM_ES_OSR_BITS))

/*
 * A power of two for the index mask, holding one event less than its slots.
 * 4096 slots for the default OSR of 3, more only as a higher OSR requires.
 */
#define CONFIG_ESDM_COLLECTION_SIZE                                            \
	(ESDM_ES_MAX_REQUEST_EVENTS < 4096  ? 4096 :                           \
	 ESDM_ES_MAX_REQUEST_EVENTS < 8192  ? 8192 :                           \
	 ESDM_ES_MAX_REQUEST_EVENTS < 16384 ? 16384 :                          \
					      32768)

/******************************************************************************/

bool esdm_gcd_tested(void);
void esdm_gcd_set(u64 running_gcd);
u64 esdm_gcd_get(void);
u64 esdm_gcd_analyze(u64 *history, size_t nelem);
void esdm_gcd_add_value(u64 time);
bool esdm_highres_timer(void);

struct esdm_es_ring;

/*
 * Hot-path timestamp handling shared by the interrupt and scheduler entropy
 * sources: take a timestamp, fold in the GCD, run the health test and on
 * success append the event to the source's per-CPU @ring. @es selects the
 * health-test instance; @raw_hires_store and @perf_time are the source's
 * testing hooks (no-ops unless the respective testing option is enabled).
 */
void esdm_time_process(struct esdm_es_ring *ring, enum esdm_internal_es es,
		       bool (*raw_hires_store)(u64 value),
		       bool (*perf_time)(u64 start));

/*
 * Number of time values to store in the array - in small environments
 * only one atomic_t variable per CPU is used.
 */
#define ESDM_DATA_NUM_VALUES (CONFIG_ESDM_COLLECTION_SIZE)
#define ESDM_DATA_NUM_VALUES_MASK (ESDM_DATA_NUM_VALUES - 1)

int __init esdm_init_time_source(void);
void esdm_time_source_exit(void);

#endif /* _ESDM_ES_TIMER_COMMON_H */
