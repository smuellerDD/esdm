// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Interrupt data collection
 *
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/irq_regs.h>
#include <asm/ptrace.h>
#include <crypto/drbg.h>
#include <linux/esdm_irq.h>
#include <linux/module.h>
#include <linux/random.h>

#include "esdm_es_mgr_cb.h"
#include "esdm_es_irq.h"
#include "esdm_es_timer_common.h"
#include "esdm_drbg_kcapi.h"
#include "esdm_health.h"
#include "esdm_testing.h"

static void *esdm_irq_drbg_state = NULL;
static const char esdm_irq_drbg_domain_separation[] = "ESDM_IRQ_DRBG";
/*
 * Number of interrupts to be recorded to assume that DRNG security strength
 * bits of entropy are received.
 * Note: a value below the DRNG security strength should not be defined as this
 *	 may imply the DRNG can never be fully seeded in case other noise
 *	 sources are unavailable.
 */
#define ESDM_IRQ_ENTROPY_BITS CONFIG_ESDM_IRQ_ENTROPY_RATE

/* Number of interrupts required for ESDM_DRNG_SECURITY_STRENGTH_BITS entropy */
static u32 esdm_irq_entropy_bits = ESDM_IRQ_ENTROPY_BITS;

static u32 irq_entropy __read_mostly = ESDM_IRQ_ENTROPY_BITS;
#ifdef CONFIG_ESDM_RUNTIME_ES_CONFIG
module_param(irq_entropy, uint, 0444);
MODULE_PARM_DESC(
	irq_entropy,
	"How many interrupts must be collected for obtaining 256 bits of entropy\n");
#endif

/* Per-CPU array holding concatenated IRQ entropy events */
static DEFINE_PER_CPU(u64 *, esdm_irq_array) __aligned(ESDM_KCAPI_ALIGN);
/* prev. timestamp for delta calculation */
static DEFINE_PER_CPU(u64, esdm_irq_last_timestamp) = 0;
/* ring buffer read ptr */
static DEFINE_PER_CPU(u32, esdm_irq_array_rp) = 0;
/* ring buffer write ptr */
static DEFINE_PER_CPU(u32, esdm_irq_array_wp) = 0;
/* two seed buffers, in case wp < rp, one if wp > rp */
static DEFINE_PER_CPU(struct drbg_string, esdm_irq_seed_data_0);
static DEFINE_PER_CPU(struct drbg_string, esdm_irq_seed_data_1);

void __init esdm_irq_es_init(bool highres_timer)
{
	/* 25 is arbitrary, but will never the less be far to
	 * large for the current event array size */
	BUG_ON(ESDM_ES_OSR <= 0 || ESDM_ES_OSR > 25);

	/* reseeding possible with current array size? */
	BUG_ON(ESDM_ES_OSR * (256 + 64) * 2 > ESDM_DATA_NUM_VALUES);

	/* Set a minimum number of interrupts that must be collected */
	irq_entropy = max_t(u32, ESDM_IRQ_ENTROPY_BITS, irq_entropy);

	esdm_irq_entropy_bits = irq_entropy;

	/* One pool should hold sufficient entropy for a single request from user-space */
	u32 max_ent = esdm_data_to_entropy(ESDM_DATA_NUM_VALUES,
					   esdm_irq_entropy_bits);
	if (max_ent < esdm_security_strength()) {
		pr_devel(
			"interrupt entropy source will never provide %u bits of entropy required for fully seeding the DRNG all by itself\n",
			esdm_security_strength());
	}
}

/*
 * Reset all per-CPU pools - reset entropy estimator and pool data
 * also called on halt/shutdown and vmfork
 */
static void esdm_irq_reset(void)
{
	int cpu;

	/* Trigger GCD calculation anew. */
	esdm_gcd_set(0);

	for_each_online_cpu (cpu) {
		smp_store_release(per_cpu_ptr(&esdm_irq_array_rp, cpu), 0);
		smp_store_release(per_cpu_ptr(&esdm_irq_array_wp, cpu), 0);
		memzero_explicit(*per_cpu_ptr(&esdm_irq_array, cpu),
				 ESDM_DATA_NUM_VALUES * sizeof(u64));
		*per_cpu_ptr(&esdm_irq_last_timestamp, cpu) = 0;
	}

	/* keep DRBG state, as it will not output anything, until a reseed
	 * as the counters were set to zero */
}

static u32 esdm_irq_avail_pool_size(void)
{
	u32 max_pool = ESDM_DATA_NUM_VALUES, max_size = 0;
	int cpu;

	for_each_online_cpu (cpu)
		max_size += max_pool;

	return max_size;
}

/* Return entropy of unused IRQs present in all per-CPU pools. */
static u32 esdm_irq_avail_entropy(u32 __unused)
{
	u32 events = 0;
	u32 r_pos, w_pos;
	int cpu;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(esdm_int_es_irq))
		return 0;

	for_each_online_cpu (cpu) {
		r_pos = READ_ONCE(*per_cpu_ptr(&esdm_irq_array_rp, cpu));
		w_pos = READ_ONCE(*per_cpu_ptr(&esdm_irq_array_wp, cpu));

		events += (w_pos >= r_pos) ?
				  w_pos - r_pos :
				  ESDM_DATA_NUM_VALUES - r_pos + w_pos;
	}

	if (esdm_sp80090c_compliant()) {
		return esdm_reduce_by_osr(
			esdm_data_to_entropy(events, esdm_irq_entropy_bits));
	} else {
		return esdm_data_to_entropy(events, esdm_irq_entropy_bits);
	}
}

/* process events and return one DRBG output block
 *
 * Length is capped with DRBG's security strength */
static bool esdm_irq_pool_extract_block(uint8_t *block, size_t partial_len,
					u32 *returned_bits)
{
	u32 found_events, collected_events = 0, collected_ent_bits,
			  requested_events, returned_ent_bits, requested_bits;
	LIST_HEAD(seedlist);
	bool ok = false;
	int ret, cpu;

	/* init returned bits with 0, increase, if generate successful */
	*returned_bits = 0;

	if ((partial_len >> 3) >
	    esdm_drbg_cb->drbg_sec_strength(esdm_irq_drbg_state)) {
		pr_warn("more bits than DRBG security strength requested\n");
		goto out;
	}

	/* Always request DRBG security strength for each block, generate less
	 * bytes with DRBG, if advised by partial_len */
	requested_bits = esdm_drbg_cb->drbg_sec_strength(esdm_irq_drbg_state);
	if (!esdm_drbg_cb->drbg_is_initialized(esdm_irq_drbg_state)) {
		requested_events =
			esdm_entropy_to_data(requested_bits + esdm_init_osr(),
					     esdm_irq_entropy_bits);
	} else {
		requested_events = esdm_entropy_to_data(
			requested_bits + esdm_compress_osr(),
			esdm_irq_entropy_bits);
	}

	for_each_online_cpu (cpu) {
		struct drbg_string *seed_string_0;
		struct drbg_string *seed_string_1;
		u32 used_events = 0;
		u32 r_pos, w_pos;

		if (collected_events >= requested_events)
			break;

		w_pos = READ_ONCE(*per_cpu_ptr(&esdm_irq_array_wp, cpu));
		r_pos = smp_load_acquire(per_cpu_ptr(&esdm_irq_array_rp, cpu));

		found_events = (w_pos >= r_pos) ?
				       w_pos - r_pos :
				       ESDM_DATA_NUM_VALUES - r_pos + w_pos;

		/* Cap to maximum amount of data we can hold in array */
		found_events = min_t(u32, found_events, ESDM_DATA_NUM_VALUES);

		if (!found_events)
			continue;

		used_events = min_t(u32, requested_events - collected_events,
				    found_events);
		collected_events += used_events;
		seed_string_0 = per_cpu_ptr(&esdm_irq_seed_data_0, cpu);
		seed_string_1 = per_cpu_ptr(&esdm_irq_seed_data_1, cpu);

		/* can use a consecutive block as seed chunk */
		if (w_pos > r_pos) {
			drbg_string_fill(
				seed_string_0,
				(u8 *)(*per_cpu_ptr(&esdm_irq_array, cpu) +
				       r_pos),
				used_events * sizeof(u64));
			list_add_tail(&seed_string_0->list, &seedlist);
		} else { /* need to skip parts in the 'middle' of the event array */
			u32 used_at_end = ESDM_DATA_NUM_VALUES - r_pos;

			drbg_string_fill(
				seed_string_0,
				(u8 *)(*per_cpu_ptr(&esdm_irq_array, cpu) +
				       r_pos),
				used_at_end * sizeof(u64));
			list_add_tail(&seed_string_0->list, &seedlist);

			if (used_at_end < used_events) {
				drbg_string_fill(seed_string_1,
						 (u8 *)*per_cpu_ptr(
							 &esdm_irq_array, cpu),
						 (used_events - used_at_end) *
							 sizeof(u64));
				list_add_tail(&seed_string_1->list, &seedlist);
			}
		}

		smp_store_release(per_cpu_ptr(&esdm_irq_array_rp, cpu),
				  (r_pos + used_events) &
					  ESDM_DATA_NUM_VALUES_MASK);

		pr_debug(
			"%u interrupt-based events used from entropy array of CPU %d, %u interrupt-based events remain unused\n",
			used_events, cpu, found_events - used_events);
	}

	collected_ent_bits =
		esdm_data_to_entropy(collected_events, esdm_irq_entropy_bits);
	/* Apply oversampling: discount requested oversampling rate */
	if (!esdm_drbg_cb->drbg_is_initialized(esdm_irq_drbg_state)) {
		returned_ent_bits = esdm_reduce_by_init_osr(collected_ent_bits);
	} else {
		returned_ent_bits = esdm_reduce_by_osr(collected_ent_bits);
	}

	pr_debug(
		"obtained %u bits by collecting %u bits of entropy from entropy pool noise source\n",
		returned_ent_bits, collected_ent_bits);

	if (esdm_drbg_cb->drbg_sec_strength(esdm_irq_drbg_state) >
	    returned_ent_bits) {
		pr_warn("returned bits too small in interrupt-based noise source: %u\n",
			returned_ent_bits);
		goto out;
	}

	ret = esdm_drbg_cb->drbg_seed(esdm_irq_drbg_state, &seedlist);
	if (ret) {
		pr_warn("unable to seed drbg in interrupt-based noise source\n");
		goto out;
	}

	ret = esdm_drbg_cb->drbg_generate(
		esdm_irq_drbg_state, block, partial_len,
		(u8 *)esdm_irq_drbg_domain_separation,
		sizeof(esdm_irq_drbg_domain_separation) - 1);
	if (ret != partial_len) {
		pr_warn("unable to generate drbg output in interrupt-based noise source\n");
	} else {
		*returned_bits = min(requested_bits, 8 * partial_len);
		ok = true;
	}

out:
	return ok;
}

/*
 * Collect all per-CPU pools, process with internal DRBG and return the output
 * to be used as seed data for seeding a DRNG.
 * The caller must not guarantee backtracking resistance, as the internal
 * cryptographic post-processing with a DRBG is always used.
 * The function will only copy as much data as entropy is available into the
 * caller-provided output buffer (further restricted by the internal DRBG's
 * security strength).
 *
 * This function handles the translation from the number of received interrupts
 * into an entropy statement. The conversion depends on ESDM_IRQ_ENTROPY_BITS
 * which defines how many interrupts must be received to obtain 256 bits of
 * entropy. With this value, the function esdm_data_to_entropy converts a given
 * data size (received interrupts, requested amount of data, etc.) into an
 * entropy statement. esdm_entropy_to_data does the reverse.
 *
 * With DRBG-based cryptographic post-processing only full blocks can be read.
 * This is done in esdm_irq_pool_extract_block.
 *
 * @eb: entropy buffer to store entropy
 * @requested_bits: Requested amount of entropy
 * @fully_seeded: indicator whether ESDM is fully seeded
 */
static void esdm_irq_pool_extract(struct entropy_buf *eb, u32 requested_bits)
{
	const u32 esdm_security_strength =
		esdm_drbg_cb->drbg_sec_strength(esdm_irq_drbg_state);
	const u32 full_blocks =
		esdm_full_blocks(requested_bits, esdm_security_strength);
	u32 done;

	/* only set entropy, when generate was successful */
	eb->e_bits = 0;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(esdm_int_es_irq)) {
		return;
	}

	/*
	 * Only deliver, when at least all requested blocks are available, one compress osr for the
	 * default case (no initialize with additional 64 Bit) is already counted in esdm_irq_avail_entropy()
	 * add additional 64 bit in order to match 128 extra bit on full init
	 */
	if (esdm_irq_avail_entropy(0) <
	    full_blocks * esdm_security_strength +
		    full_blocks * esdm_compress_osr()) {
		return;
	}

	done = 0;
	while (done < requested_bits) {
		u32 bits_returned;
		bool ok = esdm_irq_pool_extract_block(
			eb->e + (done >> 3),
			min(esdm_security_strength, requested_bits - done) >> 3,
			&bits_returned);
		if (!ok) {
			pr_warn("DRBG block extract failed, bits returned: %u!\n",
				bits_returned);
			memzero_explicit(eb->e, sizeof(eb->e));
			goto out;
		}
		done += esdm_security_strength;
	}
	eb->e_bits = requested_bits;

out:
	return;
}

static void esdm_irq_array_add(u64 data)
{
	u64 *irq_array = READ_ONCE(*this_cpu_ptr(&esdm_irq_array));
	u32 w_pos = smp_load_acquire(this_cpu_ptr(&esdm_irq_array_wp));
	u32 r_pos = READ_ONCE(*this_cpu_ptr(&esdm_irq_array_rp));

	// full?
	if (((w_pos + 1) & ESDM_DATA_NUM_VALUES_MASK) == r_pos) {
		return;
	}

	irq_array[w_pos] = data;
	smp_store_release(this_cpu_ptr(&esdm_irq_array_wp),
			  (w_pos + 1) & ESDM_DATA_NUM_VALUES_MASK);
}

static void esdm_time_process_common(u64 time, void (*add_time)(u64 data))
{
	enum esdm_health_res health_test;
	u64 *last_timestamp = this_cpu_ptr(&esdm_irq_last_timestamp);
	u64 delta = time - *last_timestamp;

	if (*last_timestamp == 0) {
		*last_timestamp = time;
		return;
	}

	*last_timestamp = time;

	if (esdm_raw_hires_entropy_store(delta))
		return;

	health_test = esdm_health_test(time, esdm_int_es_irq);
	if (health_test > esdm_health_fail_use)
		return;

	if (health_test == esdm_health_pass)
		add_time(time);
}

/*
 * Batching up of entropy in per-CPU array before injecting into entropy pool.
 */
static void esdm_time_process(void)
{
	u64 now_time = random_get_entropy();

	if (unlikely(!esdm_gcd_tested())) {
		/* When GCD is unknown, we process the full time stamp */
		esdm_time_process_common(now_time, esdm_irq_array_add);
		esdm_gcd_add_value(now_time);
	} else {
		/* GCD is known and applied */
		esdm_time_process_common(now_time / esdm_gcd_get(),
					 esdm_irq_array_add);
	}

	esdm_irq_perf_time(now_time);
}

/* Hot code path - Callback for interrupt handler */
static void esdm_add_interrupt_randomness(int irq)
{
	esdm_time_process();
}

static void esdm_irq_es_state(unsigned char *buf, size_t buflen)
{
	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 " DRBG for operating entropy pool: %s\n"
		 " Available entropy: %u\n"
		 " per-CPU interrupt collection size: %u\n"
		 " Standards compliance: %s\n"
#ifdef CONFIG_CRYPTO_FIPS
		 " FIPS mode enabled: %i\n"
#endif /* CONFIG_CRYPTO_FIPS */
		 " High-resolution timer: %s\n",
		 esdm_drbg_cb->drbg_name(), esdm_irq_avail_entropy(0),
		 ESDM_DATA_NUM_VALUES,
		 esdm_sp80090b_compliant(esdm_int_es_irq) ? "SP800-90B" : "",
#ifdef CONFIG_CRYPTO_FIPS
		 fips_enabled,
#endif /* CONFIG_CRYPTO_FIPS */
		 esdm_highres_timer() ? "true" : "false");
}

static void esdm_irq_set_entropy_rate(u32 rate)
{
	esdm_irq_entropy_bits = max_t(u32, ESDM_IRQ_ENTROPY_BITS, rate);
}

struct esdm_es_cb esdm_es_irq = {
	.name = "IRQ",
	.get_ent = esdm_irq_pool_extract,
	.curr_entropy = esdm_irq_avail_entropy,
	.max_entropy = esdm_irq_avail_pool_size,
	.state = esdm_irq_es_state,
	.reset = esdm_irq_reset,
	.set_entropy_rate = esdm_irq_set_entropy_rate,
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
	int ret;
	int cpu;

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

	/* switch to XDRBG, if upstream in the kernel */
	esdm_irq_drbg_state = esdm_drbg_cb->drbg_alloc(
		(u8 *)esdm_irq_drbg_domain_separation,
		sizeof(esdm_irq_drbg_domain_separation) - 1);
	if (!esdm_irq_drbg_state) {
		pr_warn("could not alloc DRBG for post-processing\n");
		goto err;
	}

	for_each_possible_cpu(cpu)
	{
		u64 **irq_array_cpu = per_cpu_ptr(&esdm_irq_array, cpu);
		*irq_array_cpu =
			kmalloc(ESDM_DATA_NUM_VALUES * sizeof(u64), GFP_KERNEL);
		if (!(*irq_array_cpu))
			goto free_arrays;
	}

	ret = esdm_irq_register(esdm_add_interrupt_randomness);
	if (ret) {
		pr_warn("cannot register ESDM IRQ ES\n");
		goto free_arrays;
	}

	pr_info("ESDM IRQ ES registered, DRBG: %s\n",
		esdm_drbg_cb->drbg_name());
	return;

free_arrays:
	for_each_possible_cpu(cpu)
	{
		u64 **irq_array_cpu = per_cpu_ptr(&esdm_irq_array, cpu);
		kfree_sensitive(*irq_array_cpu);
		*irq_array_cpu = NULL;
	}

err:
	if (esdm_irq_drbg_state) {
		esdm_drbg_cb->drbg_dealloc(esdm_irq_drbg_state);
		esdm_irq_drbg_state = NULL;
	}
	atomic_set(&esdm_es_irq_init_state, esdm_es_init_unused);
}

static DECLARE_WORK(esdm_es_irq_set_callback, esdm_es_irq_set_callbackfn);

int __init esdm_es_irq_module_init(void)
{
	if (!esdm_highres_timer()) {
		pr_warn("Not registering IRQ hook (missing highres timer)!\n");
		return -EINVAL;
	}

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
	int cpu;

	if (atomic_read(&esdm_es_irq_init_state) == esdm_es_init_unused)
		return;

	/* If we are in still in registering phase, do not process it */
	if (atomic_xchg(&esdm_es_irq_init_state, esdm_es_init_unregistering) <
	    esdm_es_init_registered)
		return;

	pr_warn("Unloading the ESDM IRQ ES works only on a best effort basis for "
		"development purposes!\n");

	/* we cannot really guarantee, that this is enough on SMP systems without
	 * adding global locks, which are hindering performance 99% of the time.
	 * -> ONLY UNLOAD FOR DEBUGGING and DEVELOPMENT PURPOSES <- */
	local_bh_disable();
	esdm_irq_unregister(esdm_add_interrupt_randomness);
	local_bh_enable();

	if (esdm_irq_drbg_state) {
		esdm_drbg_cb->drbg_dealloc(esdm_irq_drbg_state);
		esdm_irq_drbg_state = NULL;
	} else {
		pr_warn("ESDM IRQ ES DRBG state was never registered!\n");
	}

	esdm_irq_reset();

	for_each_possible_cpu(cpu)
	{
		u64 **irq_array_cpu = per_cpu_ptr(&esdm_irq_array, cpu);
		kfree_sensitive(*irq_array_cpu);
		*irq_array_cpu = NULL;
	}

	pr_info("ESDM IRQ ES unregistered\n");

	atomic_set(&esdm_es_irq_init_state, esdm_es_init_unused);
}
