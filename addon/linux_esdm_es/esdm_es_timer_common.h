/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM Slow Noise Source: Time stamp array handling
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
	depends on ESDM_CONTINUOUS_COMPRESSION_ENABLED
	depends on !ESDM_SWITCHABLE_CONTINUOUS_COMPRESSION
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
#define CONFIG_ESDM_COLLECTION_SIZE 1024

/******************************************************************************/

/*************************** General ESDM parameter ***************************/

/* Helper to concatenate a macro with an integer type */
#define ESDM_PASTER(x, y) x ## y
#define ESDM_UINT32_C(x) ESDM_PASTER(x, U)

bool esdm_gcd_tested(void);
void esdm_gcd_set(u32 running_gcd);
u32 esdm_gcd_get(void);
u32 esdm_gcd_analyze(u32 *history, size_t nelem);
void esdm_gcd_add_value(u32 time);
bool esdm_highres_timer(void);

/*
 * To limit the impact on the interrupt handling, the ESDM concatenates
 * entropic LSB parts of the time stamps in a per-CPU array and only
 * injects them into the entropy pool when the array is full.
 */

/* Store multiple integers in one u32 */
#define ESDM_DATA_SLOTSIZE_BITS		(8)
#define ESDM_DATA_SLOTSIZE_MASK		((1 << ESDM_DATA_SLOTSIZE_BITS) - 1)
#define ESDM_DATA_ARRAY_MEMBER_BITS	(4 << 3) /* ((sizeof(u32)) << 3) */
#define ESDM_DATA_SLOTS_PER_UINT	(ESDM_DATA_ARRAY_MEMBER_BITS / \
					 ESDM_DATA_SLOTSIZE_BITS)

/*
 * Number of time values to store in the array - in small environments
 * only one atomic_t variable per CPU is used.
 */
#define ESDM_DATA_NUM_VALUES		(CONFIG_ESDM_COLLECTION_SIZE)
/* Mask of LSB of time stamp to store */
#define ESDM_DATA_WORD_MASK		(ESDM_DATA_NUM_VALUES - 1)

#define ESDM_DATA_SLOTS_MASK		(ESDM_DATA_SLOTS_PER_UINT - 1)
#define ESDM_DATA_ARRAY_SIZE		(ESDM_DATA_NUM_VALUES /	\
					 ESDM_DATA_SLOTS_PER_UINT)

/* Starting bit index of slot */
static inline unsigned int esdm_data_slot2bitindex(unsigned int slot)
{
	return (ESDM_DATA_SLOTSIZE_BITS * slot);
}

/* Convert index into the array index */
static inline unsigned int esdm_data_idx2array(unsigned int idx)
{
	return idx / ESDM_DATA_SLOTS_PER_UINT;
}

/* Convert index into the slot of a given array index */
static inline unsigned int esdm_data_idx2slot(unsigned int idx)
{
	return idx & ESDM_DATA_SLOTS_MASK;
}

/* Convert value into slot value */
static inline unsigned int esdm_data_slot_val(unsigned int val,
					      unsigned int slot)
{
	return val << esdm_data_slot2bitindex(slot);
}

/*
 * Return the pointers for the previous and current units to inject a u32 into.
 * Also return the mask which the u32 word is to be processed.
 */
static inline void esdm_data_split_u32(u32 *ptr, u32 *pre_ptr, u32 *mask)
{
	/* ptr to previous unit */
	*pre_ptr = (*ptr - ESDM_DATA_SLOTS_PER_UINT) & ESDM_DATA_WORD_MASK;
	*ptr &= ESDM_DATA_WORD_MASK;

	/* mask to split data into the two parts for the two units */
	*mask = ((1 << (*pre_ptr & (ESDM_DATA_SLOTS_PER_UINT - 1)) *
			ESDM_DATA_SLOTSIZE_BITS)) - 1;
}

int __init esdm_init_time_source(void);

#endif /* _ESDM_ES_TIMER_COMMON_H */
