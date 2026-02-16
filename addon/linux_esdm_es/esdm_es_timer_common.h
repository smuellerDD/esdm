/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM Slow Noise Source: Time stamp array handling
 *
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_TIMER_COMMON_H
#define _ESDM_ES_TIMER_COMMON_H

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
#define CONFIG_ESDM_COLLECTION_SIZE 4096

/******************************************************************************/

/*************************** General ESDM parameter ***************************/

/* Helper to concatenate a macro with an integer type */
#define ESDM_PASTER(x, y) x##y
#define ESDM_UINT32_C(x) ESDM_PASTER(x, U)

bool esdm_gcd_tested(void);
void esdm_gcd_set(u64 running_gcd);
u64 esdm_gcd_get(void);
u64 esdm_gcd_analyze(u64 *history, size_t nelem);
void esdm_gcd_add_value(u64 time);
bool esdm_highres_timer(void);

static inline u64 esdm_delta_abs(u64 a, u64 b)
{
	return (b > a) ? (b - a) : (a - b);
}

/*
 * Number of time values to store in the array - in small environments
 * only one atomic_t variable per CPU is used.
 */
#define ESDM_DATA_NUM_VALUES (CONFIG_ESDM_COLLECTION_SIZE)
#define ESDM_DATA_NUM_VALUES_MASK (ESDM_DATA_NUM_VALUES - 1)

int __init esdm_init_time_source(void);

#endif /* _ESDM_ES_TIMER_COMMON_H */
