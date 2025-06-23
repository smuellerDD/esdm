// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Scheduler-based data collection
 *
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/ptrace.h>
#include <crypto/hash.h>
#include <linux/esdm_sched.h>
#include <linux/module.h>
#include <linux/random.h>

#include "esdm_es_mgr_cb.h"
#include "esdm_es_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_drbg_kcapi.h"
#include "esdm_hash_kcapi.h"
#include "esdm_health.h"
#include "esdm_testing.h"

/************************** Configuration parameters **************************/
/*
int "Scheduler Entropy Source Entropy Rate"
	depends on ESDM_SCHED
	range 256 4294967295 if ESDM_SCHED_DFLT_TIMER_ES
	range 4294967295 4294967295 if !ESDM_SCHED_DFLT_TIMER_ES
	default 256 if ESDM_SCHED_DFLT_TIMER_ES
	default 4294967295 if !ESDM_SCHED_DFLT_TIMER_ES
	help
	  The ESDM will collect the configured number of context switches
	  triggered by the scheduler to obtain 256 bits of entropy. This
	  value can be set to any between 256 and 4294967295. The ESDM
	  guarantees that this value is not lower than 256. This lower
	  limit implies that one interrupt event is credited with one bit
	  of entropy. This value is subject to the increase by the
	  oversampling factor, if no high-resolution timer is found.

	  In order to effectively disable the scheduler entropy source,
	  the option has to be set to 4294967295. In this case, the
	  scheduler entropy source will still deliver data but without
	  being credited with entropy.
 */
#define CONFIG_ESDM_SCHED_ENTROPY_RATE 256

/*
config ESDM_RUNTIME_ES_CONFIG
	bool "Enable runtime configuration of entropy sources"
	help
	  When enabling this option, the ESDM provides the mechanism
	  allowing to alter the entropy rate of each entropy source
	  during boot time and runtime.

	  Each entropy source allows its entropy rate changed with
	  a kernel command line option. When not providing any
	  option, the default specified during kernel compilation
	  is applied.
 */
#undef CONFIG_ESDM_RUNTIME_ES_CONFIG

/******************************************************************************/

static void *esdm_sched_hash_state = NULL;
static void *esdm_sched_drbg_state = NULL;

/*
 * Number of scheduler-based context switches to be recorded to assume that
 * DRNG security strength bits of entropy are received.
 * Note: a value below the DRNG security strength should not be defined as this
 *	 may imply the DRNG can never be fully seeded in case other noise
 *	 sources are unavailable.
 */
#define ESDM_SCHED_ENTROPY_BITS ESDM_UINT32_C(CONFIG_ESDM_SCHED_ENTROPY_RATE)

/* Number of events required for ESDM_DRNG_SECURITY_STRENGTH_BITS entropy */
static u32 esdm_sched_entropy_bits = ESDM_SCHED_ENTROPY_BITS * ESDM_ES_MIN_OVERSAMPLING_FACTOR;

static u32 sched_entropy __read_mostly = ESDM_SCHED_ENTROPY_BITS * ESDM_ES_MIN_OVERSAMPLING_FACTOR;
#ifdef CONFIG_ESDM_RUNTIME_ES_CONFIG
module_param(sched_entropy, uint, 0444);
MODULE_PARM_DESC(
	sched_entropy,
	"How many scheduler-based context switches must be collected for obtaining 256 bits of entropy\n");
#endif

/* Per-CPU array holding concatenated entropy events */
static DEFINE_PER_CPU(u32[ESDM_DATA_ARRAY_SIZE], esdm_sched_array)
	__aligned(ESDM_KCAPI_ALIGN);
static DEFINE_PER_CPU(u32, esdm_sched_array_ptr) = 0;
static DEFINE_PER_CPU(atomic_t, esdm_sched_array_events) = ATOMIC_INIT(0);

static void __init esdm_sched_check_compression_state(void)
{
	/* One pool should hold sufficient entropy for disabled compression */
	u32 max_ent = min_t(u32, esdm_get_digestsize(),
			    esdm_data_to_entropy(ESDM_DATA_NUM_VALUES,
						 esdm_sched_entropy_bits));
	if (max_ent < esdm_security_strength()) {
		pr_devel(
			"Scheduler entropy source will never provide %u bits of entropy required for fully seeding the DRNG all by itself\n",
			esdm_security_strength());
	}
}

void __init esdm_sched_es_init(bool highres_timer)
{
	/* Set a minimum number of scheduler events that must be collected */
	sched_entropy = max_t(u32, ESDM_SCHED_ENTROPY_BITS * ESDM_ES_MIN_OVERSAMPLING_FACTOR, sched_entropy);

	BUILD_BUG_ON(ESDM_ES_MIN_OVERSAMPLING_FACTOR > ESDM_ES_OVERSAMPLING_FACTOR);

	if (highres_timer) {
		esdm_sched_entropy_bits = sched_entropy;
	} else {
		u32 new_entropy = sched_entropy / ESDM_ES_MIN_OVERSAMPLING_FACTOR * ESDM_ES_OVERSAMPLING_FACTOR;

		esdm_sched_entropy_bits = (sched_entropy < new_entropy) ?
						  new_entropy :
						  sched_entropy;
		pr_warn("operating without high-resolution timer and applying oversampling factor %u\n",
			ESDM_ES_OVERSAMPLING_FACTOR);
	}

	esdm_sched_check_compression_state();
}

static u32 esdm_sched_avail_pool_size(void)
{
	u32 max_pool = esdm_get_digestsize(),
	    max_size = min_t(u32, max_pool, ESDM_DATA_NUM_VALUES);
	int cpu;

	for_each_online_cpu (cpu)
		max_size += max_pool;

	return max_size;
}

/* Return entropy of unused scheduler events present in all per-CPU pools. */
static u32 esdm_sched_avail_entropy(u32 __unused)
{
	u32 events = 0;
	int cpu;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(esdm_int_es_sched))
		return 0;

	for_each_online_cpu (cpu) {
		events += min_t(u32, ESDM_DATA_NUM_VALUES,
				atomic_read_u32(per_cpu_ptr(
					&esdm_sched_array_events, cpu)));
	}

	/* Consider oversampling rate */
	return esdm_reduce_by_osr(
		esdm_data_to_entropy(events, esdm_sched_entropy_bits));
}

/*
 * Reset all per-CPU pools - reset entropy estimator but leave the pool data
 * that may or may not have entropy unchanged.
 */
static void esdm_sched_reset(void)
{
	int cpu;

	/* Trigger GCD calculation anew. */
	esdm_gcd_set(0);

	for_each_online_cpu (cpu)
		atomic_set(per_cpu_ptr(&esdm_sched_array_events, cpu), 0);
}

static u32 esdm_sched_pool_hash_one(struct shash_desc *shash, const struct esdm_hash_cb *hash_cb, int cpu)
{
	u32 found_events;

	/* Obtain entropy statement like for the entropy pool */
	found_events = atomic_xchg_relaxed(
		per_cpu_ptr(&esdm_sched_array_events, cpu), 0);

	/* Cap to maximum amount of data we can hold in array */
	found_events = min_t(u32, found_events, ESDM_DATA_NUM_VALUES);

	if (hash_cb->hash_update(shash, (u8 *)per_cpu_ptr(esdm_sched_array, cpu), ESDM_DATA_ARRAY_SIZE * sizeof(u32)))
		found_events = 0;

	return found_events;
}

/*
 * Hash all per-CPU arrays and return the digest to be used as seed data for
 * seeding a DRNG. The caller must guarantee backtracking resistance.
 * The function will only copy as much data as entropy is available into the
 * caller-provided output buffer.
 *
 * This function handles the translation from the number of received scheduler
 * events into an entropy statement. The conversion depends on
 * ESDM_SCHED_ENTROPY_BITS which defines how many scheduler events must be
 * received to obtain 256 bits of entropy. With this value, the function
 * esdm_data_to_entropy converts a given data size (received scheduler events,
 * requested amount of data, etc.) into an entropy statement.
 * esdm_entropy_to_data does the reverse.
 *
 * @eb: entropy buffer to store entropy
 * @requested_bits: Requested amount of entropy
 * @fully_seeded: indicator whether ESDM is fully seeded
 */
static void esdm_sched_pool_hash(struct entropy_buf *eb, u32 requested_bits)
{
	SHASH_DESC_ON_STACK(shash, NULL);
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;
	u8 digest[ESDM_MAX_DIGESTSIZE];
	u32 found_events, collected_events = 0, collected_ent_bits,
			  requested_events, returned_ent_bits;
	int ret, cpu;
	void *hash;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(esdm_int_es_sched)) {
		eb->e_bits = 0;
		return;
	}

	hash = esdm_sched_hash_state;
	if (!hash)
		goto out;

	/* The hash state of filled with all per-CPU pool hashes. */
	ret = hash_cb->hash_init(shash, hash);
	if (ret)
		goto err;

	/* Cap to maximum entropy that can ever be generated with given hash */
	esdm_cap_requested(hash_cb->hash_digestsize(hash) << 3, requested_bits);
	requested_events = esdm_entropy_to_data(
		requested_bits + esdm_compress_osr(), esdm_sched_entropy_bits);

	/*
	 * Harvest entropy from each per-CPU hash state - even though we may
	 * have collected sufficient entropy, we will hash all per-CPU pools.
	 */
	for_each_online_cpu (cpu) {
		u32 unused_events = 0;

		found_events = esdm_sched_pool_hash_one(shash, hash_cb, cpu);

		collected_events += found_events;
		if (collected_events > requested_events) {
			unused_events = collected_events - requested_events;
			atomic_add_return_relaxed(
				unused_events,
				per_cpu_ptr(&esdm_sched_array_events, cpu));
			collected_events = requested_events;
		}
		pr_debug(
			"%u scheduler-based events used from entropy array of CPU %d, %u scheduler-based events remain unused\n",
			found_events - unused_events, cpu, unused_events);
	}

	ret = hash_cb->hash_final(shash, digest);
	if (ret)
		goto err;

	collected_ent_bits =
		esdm_data_to_entropy(collected_events, esdm_sched_entropy_bits);
	/* Apply oversampling: discount requested oversampling rate */
	returned_ent_bits = esdm_reduce_by_osr(collected_ent_bits);

	pr_debug(
		"obtained %u bits by collecting %u bits of entropy from scheduler-based noise source\n",
		returned_ent_bits, collected_ent_bits);

	/* insert gathered entropy as additional input, HMAC-DRBG will insert this into his state before generating output! */
	ret = esdm_drbg_cb->drbg_seed(esdm_sched_drbg_state, digest, hash_cb->hash_digestsize(hash));
	if (ret) {
		pr_warn("unable to seed drbg in scheduler-based noise source\n");
		goto err;
	}

	ret = esdm_drbg_cb->drbg_generate(esdm_sched_drbg_state, eb->e, returned_ent_bits >> 3);
	if (ret) {
		pr_warn("unable to generate drbg output in scheduler-based noise source\n");
		goto err;
	}

	/* clear fractions of a byte */
	eb->e_bits = returned_ent_bits & (u32)~0x7;

out:
	hash_cb->hash_desc_zero(shash);
	memzero_explicit(digest, sizeof(digest));
	return;

err:
	eb->e_bits = 0;
	goto out;
}

/*
 * Concatenate full 32 bit word at the end of time array even when current
 * ptr is not aligned to sizeof(data).
 */
static void esdm_sched_array_add_u32(u32 data)
{
	/* Increment pointer by number of slots taken for input value */
	u32 pre_ptr, mask,
		ptr = this_cpu_add_return(esdm_sched_array_ptr,
					  ESDM_DATA_SLOTS_PER_UINT);
	unsigned int pre_array;

	esdm_data_split_u32(&ptr, &pre_ptr, &mask);

	/* MSB of data go into previous unit */
	pre_array = esdm_data_idx2array(pre_ptr);
	/* zeroization of slot to ensure the following OR adds the data */
	this_cpu_and(esdm_sched_array[pre_array], ~(0xffffffff & ~mask));
	this_cpu_or(esdm_sched_array[pre_array], data & ~mask);

	/*
	 * Continuous compression is not allowed for scheduler noise source,
	 * so do not call esdm_sched_array_to_hash here.
	 */

	/* LSB of data go into current unit */
	this_cpu_write(esdm_sched_array[esdm_data_idx2array(ptr)], data & mask);
}

/* Concatenate data of max ESDM_DATA_SLOTSIZE_MASK at the end of time array */
static void esdm_sched_array_add_slot(u32 data)
{
	/* Get slot */
	u32 ptr =
		this_cpu_inc_return(esdm_sched_array_ptr) & ESDM_DATA_WORD_MASK;
	unsigned int array = esdm_data_idx2array(ptr);
	unsigned int slot = esdm_data_idx2slot(ptr);

	/* zeroization of slot to ensure the following OR adds the data */
	this_cpu_and(esdm_sched_array[array],
		     ~(esdm_data_slot_val(0xffffffff & ESDM_DATA_SLOTSIZE_MASK,
					  slot)));
	/* Store data into slot */
	this_cpu_or(esdm_sched_array[array], esdm_data_slot_val(data, slot));

	/*
	 * Continuous compression is not allowed for scheduler noise source,
	 * so do not call esdm_sched_array_to_hash here.
	 */
}

static void esdm_time_process_common(u32 time, void (*add_time)(u32 data))
{
	enum esdm_health_res health_test;

	if (esdm_raw_sched_hires_entropy_store(time))
		return;

	health_test = esdm_health_test(time, esdm_int_es_sched);
	if (health_test > esdm_health_fail_use)
		return;

	if (health_test == esdm_health_pass)
		atomic_inc_return(this_cpu_ptr(&esdm_sched_array_events));

	add_time(time);
}

/* Batching up of entropy in per-CPU array */
static void esdm_sched_time_process(void)
{
	u32 now_time = random_get_entropy();

	if (unlikely(!esdm_gcd_tested())) {
		/* When GCD is unknown, we process the full time stamp */
		esdm_time_process_common(now_time, esdm_sched_array_add_u32);
		esdm_gcd_add_value(now_time);
	} else {
		/* GCD is known and applied */
		esdm_time_process_common((now_time / esdm_gcd_get()) &
						 ESDM_DATA_SLOTSIZE_MASK,
					 esdm_sched_array_add_slot);
	}

	esdm_sched_perf_time(now_time);
}

static void esdm_sched_randomness(const struct task_struct *p, int cpu)
{
	if (esdm_highres_timer()) {
		esdm_sched_time_process();
	} else {
		u32 tmp = cpu;

		tmp ^= esdm_raw_sched_pid_entropy_store(p->pid) ? 0 :
								  (u32)p->pid;
		tmp ^= esdm_raw_sched_starttime_entropy_store(p->start_time) ?
			       0 :
			       (u32)p->start_time;
		tmp ^= esdm_raw_sched_nvcsw_entropy_store(p->nvcsw) ?
			       0 :
			       (u32)p->nvcsw;

		esdm_sched_time_process();
		esdm_sched_array_add_u32(tmp);
	}
}

static void esdm_sched_es_state(unsigned char *buf, size_t buflen)
{
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;

	snprintf(buf, buflen,
		 " Hash for operating entropy pool: %s\n"
		 " DRBG for operating entropy pool: %s\n"
		 " Available entropy: %u\n"
		 " per-CPU scheduler event collection size: %u\n"
		 " Standards compliance: %s\n"
		 " High-resolution timer: %s\n",
		 esdm_drbg_cb->drbg_name(),
		 hash_cb->hash_name(),
		 esdm_sched_avail_entropy(0),
		 ESDM_DATA_NUM_VALUES,
		 esdm_sp80090b_compliant(esdm_int_es_sched) ? "SP800-90B " : "",
		 esdm_highres_timer() ? "true" : "false");
}

static void esdm_sched_set_entropy_rate(u32 rate)
{
	esdm_sched_entropy_bits = max_t(u32, ESDM_SCHED_ENTROPY_BITS * ESDM_ES_MIN_OVERSAMPLING_FACTOR, rate);
}

struct esdm_es_cb esdm_es_sched = {
	.name = "Scheduler",
	.get_ent = esdm_sched_pool_hash,
	.curr_entropy = esdm_sched_avail_entropy,
	.max_entropy = esdm_sched_avail_pool_size,
	.state = esdm_sched_es_state,
	.reset = esdm_sched_reset,
	.set_entropy_rate = esdm_sched_set_entropy_rate,
};

/************************** Registration with Kernel **************************/

int __init esdm_es_sched_module_init(void)
{
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;
	void *tmp_hash_state;
	int ret;

	tmp_hash_state = hash_cb->hash_alloc();
	if (IS_ERR(tmp_hash_state)) {
		pr_warn("could not allocate new ESDM pool hash (%ld)\n",
			PTR_ERR(tmp_hash_state));
		return PTR_ERR(tmp_hash_state);
	}

	esdm_sched_hash_state = tmp_hash_state;
	ret = esdm_sched_register(esdm_sched_randomness);
	if (ret) {
		pr_warn("could not register for ESDM sched events\n");
		esdm_sched_hash_state = NULL;
		hash_cb->hash_dealloc(tmp_hash_state);
		return ret;
	}

	/* switch to XDRBG, if upstream in the kernel */
	esdm_sched_drbg_state = esdm_drbg_cb->drbg_alloc();
	if (!esdm_sched_drbg_state) {
		esdm_sched_hash_state = NULL;
		hash_cb->hash_dealloc(tmp_hash_state);
		pr_warn("could not alloc DRBG for post-processing\n");
		return EACCES;
	}

	pr_info("ESDM Scheduler ES registered, Hash: %s, DRBG: %s\n", hash_cb->hash_name(), esdm_drbg_cb->drbg_name());

	return ret;
}

void esdm_es_sched_module_exit(void)
{
	const struct esdm_hash_cb *hash_cb = esdm_kcapi_hash_cb;

	esdm_sched_unregister(esdm_sched_randomness);

	hash_cb->hash_dealloc(esdm_sched_hash_state);
	esdm_sched_hash_state = NULL;

	esdm_drbg_cb->drbg_dealloc(esdm_sched_drbg_state);
	esdm_sched_drbg_state = NULL;

	pr_info("ESDM Scheduler ES unregistered\n");
}
