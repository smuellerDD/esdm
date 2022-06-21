// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Interrupt data collection
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/irq_regs.h>
#include <asm/ptrace.h>
#include <crypto/hash.h>
#include <linux/esdm_irq.h>
#include <linux/module.h>
#include <linux/random.h>

#include "esdm_es_mgr_cb.h"
#include "esdm_es_irq.h"
#include "esdm_es_timer_common.h"
#include "esdm_hash_kcapi.h"
#include "esdm_health.h"
#include "esdm_testing.h"

/************************** Configuration parameters **************************/
/*
choice
	prompt "Continuous entropy compression boot time setting"
	default ESDM_CONTINUOUS_COMPRESSION_ENABLED
	depends on ESDM_IRQ
	help
	  Select the default behavior of the interrupt entropy source
	  continuous compression operation.

	  The ESDM IRQ ES collects entropy data during each interrupt.
	  For performance reasons, a amount of entropy data defined by
	  the ESDM entropy collection pool size is concatenated into
	  an array. When that array is filled up, a hash is calculated
	  to compress the entropy. That hash is calculated in
	  interrupt context.

	  In case such hash calculation in interrupt context is deemed
	  too time-consuming, the continuous compression operation
	  can be disabled. If disabled, the collection of entropy will
	  not trigger a hash compression operation in interrupt context.
	  The compression happens only when the DRNG is reseeded which is
	  in process context. This implies that old entropy data
	  collected after the last DRNG-reseed is overwritten with newer
	  entropy data once the collection pool is full instead of
	  retaining its entropy with the compression operation.

	config ESDM_CONTINUOUS_COMPRESSION_ENABLED
		bool "Enable continuous compression (default)"

	config ESDM_CONTINUOUS_COMPRESSION_DISABLED
		bool "Disable continuous compression"

endchoice

config ESDM_ENABLE_CONTINUOUS_COMPRESSION
	bool
	default y if ESDM_CONTINUOUS_COMPRESSION_ENABLED
	default n if ESDM_CONTINUOUS_COMPRESSION_DISABLED

*/
#define CONFIG_ESDM_ENABLE_CONTINUOUS_COMPRESSION

/*
config ESDM_SWITCHABLE_CONTINUOUS_COMPRESSION
	bool "Runtime-switchable continuous entropy compression"
	depends on ESDM_IRQ
	help
	  Per default, the interrupt entropy source continuous
	  compression operation behavior is hard-wired into the kernel.
	  Enable this option to allow it to be configurable at boot time.

	  To modify the default behavior of the continuous
	  compression operation, use the kernel command line option
	  of lrng_sw_noise.lrng_pcpu_continuous_compression.

	  If unsure, say N.
*/
#undef CONFIG_ESDM_SWITCHABLE_CONTINUOUS_COMPRESSION

/*
config ESDM_IRQ_ENTROPY_RATE
	int "Interrupt Entropy Source Entropy Rate"
	depends on ESDM_IRQ
	range 256 4294967295 if ESDM_IRQ_DFLT_TIMER_ES
	range 4294967295 4294967295 if !ESDM_IRQ_DFLT_TIMER_ES
	default 256 if ESDM_IRQ_DFLT_TIMER_ES
	default 4294967295 if !ESDM_IRQ_DFLT_TIMER_ES
	help
	  The ESDM will collect the configured number of interrupts to
	  obtain 256 bits of entropy. This value can be set to any between
	  256 and 4294967295. The ESDM guarantees that this value is not
	  lower than 256. This lower limit implies that one interrupt event
	  is credited with one bit of entropy. This value is subject to the
	  increase by the oversampling factor, if no high-resolution timer
	  is found.

	  In order to effectively disable the interrupt entropy source,
	  the option has to be set to 4294967295. In this case, the
	  interrupt entropy source will still deliver data but without
	  being credited with entropy.
*/
#define CONFIG_ESDM_IRQ_ENTROPY_RATE 256

/*
config LRNG_RUNTIME_ES_CONFIG
	bool "Enable runtime configuration of entropy sources"
	help
	  When enabling this option, the LRNG provides the mechanism
	  allowing to alter the entropy rate of each entropy source
	  during boot time and runtime.

	  Each entropy source allows its entropy rate changed with
	  a kernel command line option. When not providing any
	  option, the default specified during kernel compilation
	  is applied.
 */
#undef CONFIG_ESDM_RUNTIME_ES_CONFIG

/******************************************************************************/

static void *esdm_irq_hash_state = NULL;
static rwlock_t esdm_hash_lock = __RW_LOCK_UNLOCKED(esdm_hash_lock);

/*
 * Number of interrupts to be recorded to assume that DRNG security strength
 * bits of entropy are received.
 * Note: a value below the DRNG security strength should not be defined as this
 *	 may imply the DRNG can never be fully seeded in case other noise
 *	 sources are unavailable.
 */
#define ESDM_IRQ_ENTROPY_BITS ESDM_UINT32_C(CONFIG_ESDM_IRQ_ENTROPY_RATE)


/* Number of interrupts required for ESDM_DRNG_SECURITY_STRENGTH_BITS entropy */
static u32 esdm_irq_entropy_bits = ESDM_IRQ_ENTROPY_BITS;

static u32 irq_entropy __read_mostly = ESDM_IRQ_ENTROPY_BITS;
#ifdef CONFIG_ESDM_RUNTIME_ES_CONFIG
module_param(irq_entropy, uint, 0444);
MODULE_PARM_DESC(irq_entropy,
		 "How many interrupts must be collected for obtaining 256 bits of entropy\n");
#endif

/* Per-CPU array holding concatenated IRQ entropy events */
static DEFINE_PER_CPU(u32 [ESDM_DATA_ARRAY_SIZE], esdm_irq_array)
						__aligned(ESDM_KCAPI_ALIGN);
static DEFINE_PER_CPU(u32, esdm_irq_array_ptr) = 0;
static DEFINE_PER_CPU(atomic_t, esdm_irq_array_irqs) = ATOMIC_INIT(0);

/*
 * The entropy collection is performed by executing the following steps:
 * 1. fill up the per-CPU array holding the time stamps
 * 2. once the per-CPU array is full, a compression of the data into
 *    the entropy pool is performed - this happens in interrupt context
 *
 * If step 2 is not desired in interrupt context, the following boolean
 * needs to be set to false. This implies that old entropy data in the
 * per-CPU array collected since the last DRNG reseed is overwritten with
 * new entropy data instead of retaining the entropy with the compression
 * operation.
 *
 * Impact on entropy:
 *
 * If continuous compression is enabled, the maximum entropy that is collected
 * per CPU between DRNG reseeds is equal to the digest size of the used hash.
 *
 * If continuous compression is disabled, the maximum number of entropy events
 * that can be collected per CPU is equal to ESDM_DATA_ARRAY_SIZE. This amount
 * of events is converted into an entropy statement which then represents the
 * maximum amount of entropy collectible per CPU between DRNG reseeds.
 */
static bool esdm_irq_continuous_compression __read_mostly =
#ifdef CONFIG_ESDM_ENABLE_CONTINUOUS_COMPRESSION
	true
#else
	false
#endif
;

#ifdef CONFIG_ESDM_SWITCHABLE_CONTINUOUS_COMPRESSION
module_param(esdm_irq_continuous_compression, bool, 0444);
MODULE_PARM_DESC(esdm_irq_continuous_compression,
		 "Perform entropy compression if per-CPU entropy data array is full\n");
#endif

/*
 * Per-CPU entropy pool with compressed entropy event
 *
 * The per-CPU entropy pool is defined as the hash state. New data is simply
 * inserted into the entropy pool by performing a hash update operation.
 * To read the entropy pool, a hash final must be invoked. However, before
 * the entropy pool is released again after a hash final, the hash init must
 * be performed.
 */
static DEFINE_PER_CPU(u8 [ESDM_POOL_SIZE], esdm_irq_pool)
						__aligned(ESDM_KCAPI_ALIGN);
/*
 * Lock to allow other CPUs to read the pool - as this is only done during
 * reseed which is infrequent, this lock is hardly contended.
 */
static DEFINE_PER_CPU(spinlock_t, esdm_irq_lock);
static DEFINE_PER_CPU(bool, esdm_irq_lock_init) = false;

static bool esdm_irq_pool_online(int cpu)
{
	return per_cpu(esdm_irq_lock_init, cpu);
}

static void __init esdm_irq_check_compression_state(void)
{
	/* One pool must hold sufficient entropy for disabled compression */
	if (!esdm_irq_continuous_compression) {
		u32 max_ent = min_t(u32, esdm_get_digestsize(),
				    esdm_data_to_entropy(ESDM_DATA_NUM_VALUES,
							esdm_irq_entropy_bits));
		if (max_ent < esdm_security_strength()) {
			pr_warn("Force continuous compression operation to ensure ESDM can hold enough entropy\n");
			esdm_irq_continuous_compression = true;
		}
	}
}

void __init esdm_irq_es_init(bool highres_timer)
{
	/* Set a minimum number of interrupts that must be collected */
	irq_entropy = max_t(u32, ESDM_IRQ_ENTROPY_BITS, irq_entropy);

	if (highres_timer) {
		esdm_irq_entropy_bits = irq_entropy;
	} else {
		u32 new_entropy = irq_entropy * ESDM_ES_OVERSAMPLING_FACTOR;

		esdm_irq_entropy_bits = (irq_entropy < new_entropy) ?
					 new_entropy : irq_entropy;
		pr_warn("operating without high-resolution timer and applying IRQ oversampling factor %u\n",
			ESDM_ES_OVERSAMPLING_FACTOR);
	}

	esdm_irq_check_compression_state();
}

/*
 * Reset all per-CPU pools - reset entropy estimator but leave the pool data
 * that may or may not have entropy unchanged.
 */
static void esdm_irq_reset(void)
{
	int cpu;

	/* Trigger GCD calculation anew. */
	esdm_gcd_set(0);

	for_each_online_cpu(cpu)
		atomic_set(per_cpu_ptr(&esdm_irq_array_irqs, cpu), 0);
}

static u32 esdm_irq_avail_pool_size(void)
{
	u32 max_size = 0, max_pool = esdm_get_digestsize();
	int cpu;

	if (!esdm_irq_continuous_compression)
		max_pool = min_t(u32, max_pool, ESDM_DATA_NUM_VALUES);

	for_each_online_cpu(cpu) {
		if (esdm_irq_pool_online(cpu))
			max_size += max_pool;
	}

	return max_size;
}

/* Return entropy of unused IRQs present in all per-CPU pools. */
static u32 esdm_irq_avail_entropy(u32 __unused)
{
	u32 digestsize_irqs, irq = 0;
	int cpu;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(esdm_int_es_irq))
		return 0;

	/* Obtain the cap of maximum numbers of IRQs we count */
	digestsize_irqs = esdm_entropy_to_data(esdm_get_digestsize(),
					       esdm_irq_entropy_bits);
	if (!esdm_irq_continuous_compression) {
		/* Cap to max. number of IRQs the array can hold */
		digestsize_irqs = min_t(u32, digestsize_irqs,
					ESDM_DATA_NUM_VALUES);
	}

	for_each_online_cpu(cpu) {
		if (!esdm_irq_pool_online(cpu))
			continue;
		irq += min_t(u32, digestsize_irqs,
			     atomic_read_u32(per_cpu_ptr(&esdm_irq_array_irqs,
							 cpu)));
	}

	/* Consider oversampling rate */
	return esdm_reduce_by_osr(esdm_data_to_entropy(irq,
						       esdm_irq_entropy_bits));
}

static u32
esdm_irq_pool_hash_one(const struct esdm_hash_cb *pcpu_hash_cb,
		       void *pcpu_hash, int cpu, u8 *digest, u32 *digestsize)
{
	struct shash_desc *pcpu_shash =
		(struct shash_desc *)per_cpu_ptr(esdm_irq_pool, cpu);
	spinlock_t *lock = per_cpu_ptr(&esdm_irq_lock, cpu);
	unsigned long flags;
	u32 digestsize_irqs, found_irqs;

	/* Lock guarding against reading / writing to per-CPU pool */
	spin_lock_irqsave(lock, flags);

	*digestsize = pcpu_hash_cb->hash_digestsize(pcpu_hash);
	digestsize_irqs = esdm_entropy_to_data(*digestsize << 3,
					       esdm_irq_entropy_bits);

	/* Obtain entropy statement like for the entropy pool */
	found_irqs = atomic_xchg_relaxed(
				per_cpu_ptr(&esdm_irq_array_irqs, cpu), 0);
	/* Cap to maximum amount of data we can hold in hash */
	found_irqs = min_t(u32, found_irqs, digestsize_irqs);

	/* Cap to maximum amount of data we can hold in array */
	if (!esdm_irq_continuous_compression)
		found_irqs = min_t(u32, found_irqs, ESDM_DATA_NUM_VALUES);

	/* Store all not-yet compressed data in data array into hash, ... */
	if (pcpu_hash_cb->hash_update(pcpu_shash,
				(u8 *)per_cpu_ptr(esdm_irq_array, cpu),
				ESDM_DATA_ARRAY_SIZE * sizeof(u32)) ?:
	    /* ... get the per-CPU pool digest, ... */
	    pcpu_hash_cb->hash_final(pcpu_shash, digest) ?:
	    /* ... re-initialize the hash, ... */
	    pcpu_hash_cb->hash_init(pcpu_shash, pcpu_hash) ?:
	    /* ... feed the old hash into the new state. */
	    pcpu_hash_cb->hash_update(pcpu_shash, digest, *digestsize))
		found_irqs = 0;

	spin_unlock_irqrestore(lock, flags);
	return found_irqs;
}

/*
 * Hash all per-CPU pools and return the digest to be used as seed data for
 * seeding a DRNG. The caller must guarantee backtracking resistance.
 * The function will only copy as much data as entropy is available into the
 * caller-provided output buffer.
 *
 * This function handles the translation from the number of received interrupts
 * into an entropy statement. The conversion depends on ESDM_IRQ_ENTROPY_BITS
 * which defines how many interrupts must be received to obtain 256 bits of
 * entropy. With this value, the function esdm_data_to_entropy converts a given
 * data size (received interrupts, requested amount of data, etc.) into an
 * entropy statement. esdm_entropy_to_data does the reverse.
 *
 * @eb: entropy buffer to store entropy
 * @requested_bits: Requested amount of entropy
 * @fully_seeded: indicator whether ESDM is fully seeded
 */
static void esdm_irq_pool_hash(struct entropy_buf *eb, u32 requested_bits)
{
	SHASH_DESC_ON_STACK(shash, NULL);
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;
	u8 digest[ESDM_MAX_DIGESTSIZE];
	unsigned long flags;
	u32 found_irqs, collected_irqs = 0, collected_ent_bits, requested_irqs,
	    returned_ent_bits;
	int ret, cpu;
	void *hash;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(esdm_int_es_irq)) {
		eb->e_bits = 0;
		return;
	}

	/* Lock guarding replacement of hash */
	read_lock_irqsave(&esdm_hash_lock, flags);

	hash = esdm_irq_hash_state;
	if (!hash)
		goto out;

	/* The hash state of filled with all per-CPU pool hashes. */
	ret = hash_cb->hash_init(shash, hash);
	if (ret)
		goto err;

	/* Cap to maximum entropy that can ever be generated with given hash */
	esdm_cap_requested(hash_cb->hash_digestsize(hash) << 3, requested_bits);
	requested_irqs = esdm_entropy_to_data(requested_bits +
					      esdm_compress_osr(),
					      esdm_irq_entropy_bits);

	/*
	 * Harvest entropy from each per-CPU hash state - even though we may
	 * have collected sufficient entropy, we will hash all per-CPU pools.
	 */
	for_each_online_cpu(cpu) {
		u32 digestsize, pcpu_unused_irqs = 0;

		/* If pool is not online, then no entropy is present. */
		if (!esdm_irq_pool_online(cpu))
			continue;

		found_irqs = esdm_irq_pool_hash_one(hash_cb, hash,
						    cpu, digest,
						    &digestsize);

		/* Inject the digest into the state of all per-CPU pools */
		ret = hash_cb->hash_update(shash, digest, digestsize);
		if (ret)
			goto err;

		collected_irqs += found_irqs;
		if (collected_irqs > requested_irqs) {
			pcpu_unused_irqs = collected_irqs - requested_irqs;
			atomic_add_return_relaxed(pcpu_unused_irqs,
				per_cpu_ptr(&esdm_irq_array_irqs, cpu));
			collected_irqs = requested_irqs;
		}
		pr_debug("%u interrupts used from entropy pool of CPU %d, %u interrupts remain unused\n",
			 found_irqs - pcpu_unused_irqs, cpu, pcpu_unused_irqs);
	}

	ret = hash_cb->hash_final(shash, digest);
	if (ret)
		goto err;

	collected_ent_bits = esdm_data_to_entropy(collected_irqs,
						  esdm_irq_entropy_bits);
	/* Apply oversampling: discount requested oversampling rate */
	returned_ent_bits = esdm_reduce_by_osr(collected_ent_bits);

	pr_debug("obtained %u bits by collecting %u bits of entropy from entropy pool noise source\n",
		 returned_ent_bits, collected_ent_bits);

	memcpy(eb->e, digest, returned_ent_bits >> 3);
	eb->e_bits = returned_ent_bits;

out:
	hash_cb->hash_desc_zero(shash);
	read_unlock_irqrestore(&esdm_hash_lock, flags);
	memzero_explicit(digest, sizeof(digest));
	return;

err:
	eb->e_bits = 0;
	goto out;
}

/* Compress the esdm_irq_array array into esdm_irq_pool */
static void esdm_irq_array_compress(void)
{
	struct shash_desc *shash =
			(struct shash_desc *)this_cpu_ptr(esdm_irq_pool);
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;
	spinlock_t *lock = this_cpu_ptr(&esdm_irq_lock);
	unsigned long flags, flags2;
	void *hash;
	bool init = false;

	read_lock_irqsave(&esdm_hash_lock, flags);
	hash = esdm_irq_hash_state;
	if (!hash)
		goto out;

	if (unlikely(!this_cpu_read(esdm_irq_lock_init))) {
		init = true;
		spin_lock_init(lock);
		this_cpu_write(esdm_irq_lock_init, true);
		pr_debug("Initializing per-CPU entropy pool for CPU %d on NUMA node %d with hash %s\n",
			 raw_smp_processor_id(), numa_node_id(),
			 hash_cb->hash_name());
	}

	spin_lock_irqsave(lock, flags2);

	if (unlikely(init) && hash_cb->hash_init(shash, hash)) {
		this_cpu_write(esdm_irq_lock_init, false);
		pr_warn("Initialization of hash failed\n");
	} else if (esdm_irq_continuous_compression) {
		/* Add entire per-CPU data array content into entropy pool. */
		if (hash_cb->hash_update(shash,
					(u8 *)this_cpu_ptr(esdm_irq_array),
					ESDM_DATA_ARRAY_SIZE * sizeof(u32)))
			pr_warn_ratelimited("Hashing of entropy data failed\n");
	}

	spin_unlock_irqrestore(lock, flags2);

out:
	read_unlock_irqrestore(&esdm_hash_lock, flags);
}

/* Compress data array into hash */
static void esdm_irq_array_to_hash(u32 ptr)
{
	u32 *array = this_cpu_ptr(esdm_irq_array);

	if (ptr < ESDM_DATA_WORD_MASK)
		return;

	if (esdm_raw_array_entropy_store(*array)) {
		u32 i;

		/*
		 * If we fed even a part of the array to external analysis, we
		 * mark that the entire array and the per-CPU pool to have no
		 * entropy. This is due to the non-IID property of the data as
		 * we do not fully know whether the existing dependencies
		 * diminish the entropy beyond to what we expect it has.
		 */
		atomic_set(this_cpu_ptr(&esdm_irq_array_irqs), 0);

		for (i = 1; i < ESDM_DATA_ARRAY_SIZE; i++)
			esdm_raw_array_entropy_store(*(array + i));
	} else {
		esdm_irq_array_compress();
	}
}

/*
 * Concatenate full 32 bit word at the end of time array even when current
 * ptr is not aligned to sizeof(data).
 */
static void _esdm_irq_array_add_u32(u32 data)
{
	/* Increment pointer by number of slots taken for input value */
	u32 pre_ptr, mask, ptr = this_cpu_add_return(esdm_irq_array_ptr,
						     ESDM_DATA_SLOTS_PER_UINT);
	unsigned int pre_array;

	/*
	 * This function injects a unit into the array - guarantee that
	 * array unit size is equal to data type of input data.
	 */
	BUILD_BUG_ON(ESDM_DATA_ARRAY_MEMBER_BITS != (sizeof(data) << 3));

	/*
	 * The following logic requires at least two units holding
	 * the data as otherwise the pointer would immediately wrap when
	 * injection an u32 word.
	 */
	BUILD_BUG_ON(ESDM_DATA_NUM_VALUES <= ESDM_DATA_SLOTS_PER_UINT);

	esdm_data_split_u32(&ptr, &pre_ptr, &mask);

	/* MSB of data go into previous unit */
	pre_array = esdm_data_idx2array(pre_ptr);
	/* zeroization of slot to ensure the following OR adds the data */
	this_cpu_and(esdm_irq_array[pre_array], ~(0xffffffff & ~mask));
	this_cpu_or(esdm_irq_array[pre_array], data & ~mask);

	/* Invoke compression as we just filled data array completely */
	if (unlikely(pre_ptr > ptr))
		esdm_irq_array_to_hash(ESDM_DATA_WORD_MASK);

	/* LSB of data go into current unit */
	this_cpu_write(esdm_irq_array[esdm_data_idx2array(ptr)],
		       data & mask);

	if (likely(pre_ptr <= ptr))
		esdm_irq_array_to_hash(ptr);
}

/* Concatenate data of max ESDM_DATA_SLOTSIZE_MASK at the end of time array */
static void esdm_irq_array_add_slot(u32 data)
{
	/* Get slot */
	u32 ptr = this_cpu_inc_return(esdm_irq_array_ptr) &
							ESDM_DATA_WORD_MASK;
	unsigned int array = esdm_data_idx2array(ptr);
	unsigned int slot = esdm_data_idx2slot(ptr);

	BUILD_BUG_ON(ESDM_DATA_ARRAY_MEMBER_BITS % ESDM_DATA_SLOTSIZE_BITS);
	/* Ensure consistency of values */
	BUILD_BUG_ON(ESDM_DATA_ARRAY_MEMBER_BITS !=
		     sizeof(esdm_irq_array[0]) << 3);

	/* zeroization of slot to ensure the following OR adds the data */
	this_cpu_and(esdm_irq_array[array],
		     ~(esdm_data_slot_val(0xffffffff & ESDM_DATA_SLOTSIZE_MASK,
					  slot)));
	/* Store data into slot */
	this_cpu_or(esdm_irq_array[array], esdm_data_slot_val(data, slot));

	esdm_irq_array_to_hash(ptr);
}

static void
esdm_time_process_common(u32 time, void(*add_time)(u32 data))
{
	enum esdm_health_res health_test;

	if (esdm_raw_hires_entropy_store(time))
		return;

	health_test = esdm_health_test(time, esdm_int_es_irq);
	if (health_test > esdm_health_fail_use)
		return;

	if (health_test == esdm_health_pass)
		atomic_inc_return(this_cpu_ptr(&esdm_irq_array_irqs));

	add_time(time);
}

/*
 * Batching up of entropy in per-CPU array before injecting into entropy pool.
 */
static void esdm_time_process(void)
{
	u32 now_time = random_get_entropy();

	if (unlikely(!esdm_gcd_tested())) {
		/* When GCD is unknown, we process the full time stamp */
		esdm_time_process_common(now_time, _esdm_irq_array_add_u32);
		esdm_gcd_add_value(now_time);
	} else {
		/* GCD is known and applied */
		esdm_time_process_common((now_time / esdm_gcd_get()) &
					 ESDM_DATA_SLOTSIZE_MASK,
					 esdm_irq_array_add_slot);
	}

	esdm_perf_time(now_time);
}

/* Hot code path - Callback for interrupt handler */
static void esdm_add_interrupt_randomness(int irq)
{
	if (esdm_highres_timer()) {
		esdm_time_process();
	} else {
		struct pt_regs *regs = get_irq_regs();
		static atomic_t reg_idx = ATOMIC_INIT(0);
		u64 ip;
		u32 tmp;

		if (regs) {
			u32 *ptr = (u32 *)regs;
			int reg_ptr = atomic_add_return_relaxed(1, &reg_idx);
			size_t n = (sizeof(struct pt_regs) / sizeof(u32));

			ip = instruction_pointer(regs);
			tmp = *(ptr + (reg_ptr % n));
			tmp = esdm_raw_regs_entropy_store(tmp) ? 0 : tmp;
			_esdm_irq_array_add_u32(tmp);
		} else {
			ip = _RET_IP_;
		}

		esdm_time_process();

		/*
		 * The XOR operation combining the different values is not
		 * considered to destroy entropy since the entirety of all
		 * processed values delivers the entropy (and not each
		 * value separately of the other values).
		 */
		tmp = esdm_raw_jiffies_entropy_store(jiffies) ? 0 : jiffies;
		tmp ^= esdm_raw_irq_entropy_store(irq) ? 0 : irq;
		tmp ^= esdm_raw_retip_entropy_store(ip) ? 0 : ip;
		tmp ^= ip >> 32;
		_esdm_irq_array_add_u32(tmp);
	}
}

static void esdm_irq_es_state(unsigned char *buf, size_t buflen)
{
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;

	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 " Hash for operating entropy pool: %s\n"
		 " Available entropy: %u\n"
		 " per-CPU interrupt collection size: %u\n"
		 " Standards compliance: %s\n"
		 " High-resolution timer: %s\n"
		 " Continuous compression: %s\n",
		 hash_cb->hash_name(),
		 esdm_irq_avail_entropy(0),
		 ESDM_DATA_NUM_VALUES,
		 esdm_sp80090b_compliant(esdm_int_es_irq) ? "SP800-90B " : "",
		 esdm_highres_timer() ? "true" : "false",
		 esdm_irq_continuous_compression ? "true" : "false");
}

static void esdm_irq_set_entropy_rate(u32 rate)
{
	esdm_irq_entropy_bits = max_t(u32, ESDM_IRQ_ENTROPY_BITS, rate);
}

struct esdm_es_cb esdm_es_irq = {
	.name 			= "IRQ",
	.get_ent		= esdm_irq_pool_hash,
	.curr_entropy		= esdm_irq_avail_entropy,
	.max_entropy		= esdm_irq_avail_pool_size,
	.state			= esdm_irq_es_state,
	.reset			= esdm_irq_reset,
	.set_entropy_rate	= esdm_irq_set_entropy_rate,
};

/************************** Registration with Kernel **************************/

/* Initialization state of the module to prevent races with the exit code. */
enum {
	esdm_es_init_unused,
	esdm_es_init_registering,
	esdm_es_init_registered,
	esdm_es_init_unregistering,
};
static atomic_t esdm_es_irq_init_state = ATOMIC_INIT(esdm_es_init_unused);

static void esdm_es_irq_set_callbackfn(struct work_struct *work)
{
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;
	unsigned long flags;
	int ret;

	/*
	 * We wait until the Linux-RNG is fully initialized and received
	 * sufficient seed because we steal one of his primary noise sources
	 * such that this noise source will not deliver data to it any more.
	 */
	do {
		ret = wait_for_random_bytes();
	} while (ret == -ERESTARTSYS);

	if (atomic_xchg(&esdm_es_irq_init_state, esdm_es_init_registered) !=
			esdm_es_init_registering) {
		atomic_set(&esdm_es_irq_init_state, esdm_es_init_unused);
		return;
	}

	write_lock_irqsave(&esdm_hash_lock, flags);
	esdm_irq_hash_state = hash_cb->hash_alloc();
	if (IS_ERR(esdm_irq_hash_state)) {
		pr_warn("could not allocate new ESDM pool hash (%ld)\n",
			PTR_ERR(esdm_irq_hash_state));
	}

	ret = esdm_irq_register(esdm_add_interrupt_randomness);
	if (ret) {
		hash_cb->hash_dealloc(esdm_irq_hash_state);
		esdm_irq_hash_state = NULL;
	}

	write_unlock_irqrestore(&esdm_hash_lock, flags);
	pr_info("ESDM IRQ ES registered\n");
}

static DECLARE_WORK(esdm_es_irq_set_callback, esdm_es_irq_set_callbackfn);

int __init esdm_es_irq_module_init(void)
{
	if (atomic_cmpxchg(&esdm_es_irq_init_state, esdm_es_init_unused,
			   esdm_es_init_registering) != esdm_es_init_unused)
		return -EAGAIN;

	/*
	 * Move the actual work into a thread considering that it has the
	 * potential to sleep for some unspecified amount of time.
	 */
	schedule_work(&esdm_es_irq_set_callback);
	return 0;
}

void esdm_es_irq_module_exit(void)
{
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;
	unsigned long flags;

	if (atomic_read(&esdm_es_irq_init_state) == esdm_es_init_unused)
		return;

	/* If we are in still in registering phase, do not process it */
	if (atomic_xchg(&esdm_es_irq_init_state, esdm_es_init_unregistering) <
			esdm_es_init_registered)
		return;

	/*
	 * The lock can only be taken once the sleeping on wait_for_random_bytes
	 * completes. This guarantees that we do not clash with the waiting
	 * in the init function.
	 */
	write_lock_irqsave(&esdm_hash_lock, flags);

	esdm_irq_unregister(esdm_add_interrupt_randomness);
	hash_cb->hash_dealloc(esdm_irq_hash_state);
	esdm_irq_hash_state = NULL;

	write_unlock_irqrestore(&esdm_hash_lock, flags);

	pr_info("ESDM IRQ ES unregistered\n");
	atomic_set(&esdm_es_irq_init_state, esdm_es_init_unused);
}
