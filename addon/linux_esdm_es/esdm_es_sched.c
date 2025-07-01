// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Scheduler-based data collection
 *
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/ptrace.h>
#include <crypto/drbg.h>
#include <linux/esdm_sched.h>
#include <linux/module.h>
#include <linux/random.h>

#include "esdm_es_mgr_cb.h"
#include "esdm_es_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_drbg_kcapi.h"
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
#define CONFIG_ESDM_SCHED_ENTROPY_RATE 768

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

static void *esdm_sched_drbg_state = NULL;
static const char esdm_sched_drbg_domain_separation[] = "ESDM_SCH_DRBG";

/*
 * Number of scheduler-based context switches to be recorded to assume that
 * DRNG security strength bits of entropy are received.
 * Note: a value below the DRNG security strength should not be defined as this
 *	 may imply the DRNG can never be fully seeded in case other noise
 *	 sources are unavailable.
 */
#define ESDM_SCHED_ENTROPY_BITS ESDM_UINT32_C(CONFIG_ESDM_SCHED_ENTROPY_RATE)

/* Number of events required for ESDM_DRNG_SECURITY_STRENGTH_BITS entropy */
static u32 esdm_sched_entropy_bits = ESDM_SCHED_ENTROPY_BITS;

static u32 sched_entropy __read_mostly = ESDM_SCHED_ENTROPY_BITS;
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
static DEFINE_PER_CPU(struct drbg_string, esdm_sched_seed_data);

void __init esdm_sched_es_init(bool highres_timer)
{
	/* Set a minimum number of scheduler events that must be collected */
	sched_entropy = max_t(u32, ESDM_SCHED_ENTROPY_BITS, sched_entropy);

	if (highres_timer) {
		esdm_sched_entropy_bits = sched_entropy;
	} else {
		u32 new_entropy = sched_entropy * ESDM_ES_OVERSAMPLING_FACTOR;

		esdm_sched_entropy_bits = (sched_entropy < new_entropy) ?
						  new_entropy :
						  sched_entropy;
		pr_warn("operating without high-resolution timer and applying oversampling factor %u\n",
			ESDM_ES_OVERSAMPLING_FACTOR);
	}

	/* One pool should hold sufficient entropy for a single request from user-space */
	u32 max_ent = esdm_data_to_entropy(ESDM_DATA_NUM_VALUES,
					   esdm_sched_entropy_bits);
	if (max_ent < esdm_security_strength()) {
		pr_devel(
			"Scheduler entropy source will never provide %u bits of entropy required for fully seeding the DRNG all by itself\n",
			esdm_security_strength());
	}
}

static u32 esdm_sched_avail_pool_size(void)
{
	u32 max_pool = ESDM_DATA_NUM_VALUES, max_size = 0;
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
static void esdm_sched_pool_extract(struct entropy_buf *eb, u32 requested_bits)
{
	u32 found_events, collected_events = 0, collected_ent_bits,
			  requested_events, returned_ent_bits;
	LIST_HEAD(seedlist);
	int ret, cpu;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(esdm_int_es_sched)) {
		eb->e_bits = 0;
		return;
	}

	/* Cap to maximum entropy that can ever be generated with given DRBG
	 * without reseeding */
	esdm_cap_requested(
		esdm_drbg_cb->drbg_sec_strength(esdm_sched_drbg_state),
		requested_bits);
	requested_events = esdm_entropy_to_data(
		requested_bits + esdm_compress_osr(), esdm_sched_entropy_bits);

	/*
	 * Harvest entropy from each per-CPU hash state - even though we may
	 * have collected sufficient entropy, we will hash all per-CPU pools.
	 */
	for_each_online_cpu (cpu) {
		struct drbg_string *seed_string;
		u32 unused_events = 0;

		/* Obtain entropy statement like for the entropy pool */
		found_events = atomic_xchg_relaxed(
			per_cpu_ptr(&esdm_sched_array_events, cpu), 0);

		/* Cap to maximum amount of data we can hold in array */
		found_events = min_t(u32, found_events, ESDM_DATA_NUM_VALUES);

		seed_string = per_cpu_ptr(&esdm_sched_seed_data, cpu);
		drbg_string_fill(seed_string,
				 (u8 *)per_cpu_ptr(&esdm_sched_array_events,
						   cpu),
				 ESDM_DATA_NUM_VALUES * sizeof(u32));
		list_add_tail(&seed_string->list, &seedlist);

		collected_events += found_events;
		if (collected_events > requested_events) {
			unused_events = collected_events - requested_events;
			atomic_add_return_relaxed(
				unused_events,
				per_cpu_ptr(&esdm_sched_array_events, cpu));
			collected_events = requested_events;
			requested_events = 0;
		} else {
			requested_events -= collected_events;
		}
		pr_debug(
			"%u scheduler-based events used from entropy array of CPU %d, %u scheduler-based events remain unused\n",
			found_events - unused_events, cpu, unused_events);
	}

	collected_ent_bits =
		esdm_data_to_entropy(collected_events, esdm_sched_entropy_bits);
	/* Apply oversampling: discount requested oversampling rate */
	returned_ent_bits = esdm_reduce_by_osr(collected_ent_bits);

	pr_debug(
		"obtained %u bits by collecting %u bits of entropy from scheduler-based noise source\n",
		returned_ent_bits, collected_ent_bits);

	/* insert gathered entropy as additional input, HMAC-DRBG will insert this
	 * into his state before generating output! */
	ret = esdm_drbg_cb->drbg_seed(esdm_sched_drbg_state, &seedlist);
	if (ret) {
		pr_warn("unable to seed drbg in scheduler-based noise source\n");
		goto err;
	}

	ret = esdm_drbg_cb->drbg_generate(
		esdm_sched_drbg_state, eb->e, returned_ent_bits >> 3,
		(u8 *)esdm_sched_drbg_domain_separation,
		sizeof(esdm_sched_drbg_domain_separation) - 1);
	if (ret != returned_ent_bits >> 3) {
		pr_warn("unable to generate drbg output in scheduler-based noise source\n");
		goto err;
	}
	eb->e_bits = returned_ent_bits;

out:
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
	snprintf(buf, buflen,
		 " DRBG for operating entropy pool: %s\n"
		 " Available entropy: %u\n"
		 " per-CPU scheduler event collection size: %u\n"
		 " Standards compliance: %s\n"
#ifdef CONFIG_CRYPTO_FIPS
		 " FIPS mode enabled: %i\n"
#endif /* CONFIG_CRYPTO_FIPS */
		 " High-resolution timer: %s\n",
		 esdm_drbg_cb->drbg_name(),
		 esdm_sched_avail_entropy(0),
		 ESDM_DATA_NUM_VALUES,
		 esdm_sp80090b_compliant(esdm_int_es_sched) ? "SP800-90B" : "",
		 fips_enabled,
		 esdm_highres_timer() ? "true" : "false");
}

static void esdm_sched_set_entropy_rate(u32 rate)
{
	esdm_sched_entropy_bits = max_t(u32, ESDM_SCHED_ENTROPY_BITS, rate);
}

struct esdm_es_cb esdm_es_sched = {
	.name = "Scheduler",
	.get_ent = esdm_sched_pool_extract,
	.curr_entropy = esdm_sched_avail_entropy,
	.max_entropy = esdm_sched_avail_pool_size,
	.state = esdm_sched_es_state,
	.reset = esdm_sched_reset,
	.set_entropy_rate = esdm_sched_set_entropy_rate,
};

/************************** Registration with Kernel **************************/

int __init esdm_es_sched_module_init(void)
{
	int ret;

	/* switch to XDRBG, if upstream in the kernel */
	esdm_sched_drbg_state = esdm_drbg_cb->drbg_alloc(
		(u8 *)esdm_sched_drbg_domain_separation,
		sizeof(esdm_sched_drbg_domain_separation) - 1);
	if (!esdm_sched_drbg_state) {
		pr_warn("could not alloc DRBG for post-processing\n");
		return -EINVAL;
	}

	/* register scheduler hook */
	ret = esdm_sched_register(esdm_sched_randomness);
	if (ret) {
		pr_warn("Unable to register ESDM scheduler ES\n");
		esdm_drbg_cb->drbg_dealloc(esdm_sched_drbg_state);
		esdm_sched_drbg_state = NULL;
		return -EINVAL;
	}

	pr_info("ESDM Scheduler ES registered, DRBG: %s\n",
		esdm_drbg_cb->drbg_name());

	return 0;
}

void esdm_es_sched_module_exit(void)
{
	pr_warn("Unloading the ESDM Scheduler ES works only on a best effort basis for "
		"development purposes!\n");

	/* we cannot really guarantee, that this is enough on SMP systems without
	 * adding global locks, which are hindering performance 99% of the time.
	 * -> ONLY UNLOAD FOR DEBUGGING and DEVELOPMENT PURPOSES <- */
	preempt_disable();
	esdm_sched_unregister(esdm_sched_randomness);
	preempt_enable();

	if (esdm_sched_drbg_state) {
		esdm_drbg_cb->drbg_dealloc(esdm_sched_drbg_state);
		esdm_sched_drbg_state = NULL;
	} else {
		pr_warn("ESDM Scheduler ES DRBG state was never registered!\n");
	}

	pr_info("ESDM Scheduler ES unregistered\n");
}
