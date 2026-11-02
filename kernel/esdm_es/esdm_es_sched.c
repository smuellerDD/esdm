// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Scheduler-based data collection
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/ptrace.h>
#include "esdm_drbg_string.h"
#include <linux/esdm_sched.h>
#include <linux/module.h>
#include <linux/random.h>

#include "esdm_es_mgr_cb.h"
#include "esdm_es_drbg.h"
#include "esdm_es_sched.h"
#include "esdm_es_ring.h"
#include "esdm_es_timer_common.h"
#include "esdm_drbg_kcapi.h"
#include "esdm_health.h"
#include "esdm_testing.h"

static const char esdm_sched_drbg_domain_separation[] = "ESDM_SCH_DRBG";

/*
 * Number of scheduler-based context switches to be recorded to assume that
 * DRNG security strength bits of entropy are received.
 * Note: a value below the DRNG security strength should not be defined as this
 *	 may imply the DRNG can never be fully seeded in case other noise
 *	 sources are unavailable.
 */
#define ESDM_SCHED_ENTROPY_BITS CONFIG_ESDM_SCHED_ENTROPY_RATE

static u32 sched_entropy __read_mostly = ESDM_SCHED_ENTROPY_BITS;
#ifdef CONFIG_ESDM_RUNTIME_ES_CONFIG
module_param(sched_entropy, uint, 0444);
MODULE_PARM_DESC(
	sched_entropy,
	"How many scheduler-based context switches must be collected for obtaining 256 bits of entropy\n");
#endif

/* Per-CPU ring buffer holding concatenated scheduler entropy events */
static DEFINE_PER_CPU(struct esdm_es_ring_cpu, esdm_sched_ring_cpu);
static struct esdm_es_ring esdm_sched_ring =
	ESDM_ES_RING_INIT(esdm_sched_ring, esdm_sched_ring_cpu, "scheduler");

/* DRBG post-processing description for the scheduler entropy source */
static struct esdm_es_drbg esdm_sched_drbg = {
	.ring = &esdm_sched_ring,
	.domain_separation = esdm_sched_drbg_domain_separation,
	.domain_separation_len = sizeof(esdm_sched_drbg_domain_separation) - 1,
	.es = esdm_int_es_sched,
	.entropy_bits = ESDM_SCHED_ENTROPY_BITS,
	.name = "scheduler",
};

void __init esdm_sched_es_init(bool highres_timer)
{
	/* reseeding possible with current array size? */
	BUILD_BUG_ON(ESDM_ES_MAX_REQUEST_EVENTS >= ESDM_DATA_NUM_VALUES);
	BUILD_BUG_ON(ESDM_DATA_NUM_VALUES & ESDM_DATA_NUM_VALUES_MASK);

	/* Set a minimum number of scheduler events that must be collected */
	sched_entropy = max_t(u32, ESDM_SCHED_ENTROPY_BITS, sched_entropy);

	esdm_sched_drbg.entropy_bits = sched_entropy;

	/* One pool should hold sufficient entropy for a single request from
	 * user-space */
	u32 max_ent = esdm_data_to_entropy(ESDM_DATA_NUM_VALUES,
					   esdm_sched_drbg.entropy_bits);
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
static u32 esdm_sched_avail_entropy(u32 entropy_rate)
{
	return esdm_es_drbg_avail_entropy(&esdm_sched_drbg, entropy_rate);
}

/*
 * Reset all per-CPU pools - reset entropy estimator and pool data
 * also called on halt/shutdown and vmfork
 */
static void esdm_sched_reset(void)
{
	/* Trigger GCD calculation anew. */
	esdm_gcd_set(0);

	esdm_es_ring_reset(&esdm_sched_ring);

	/* keep DRBG state, as it will not output anything, until a reseed
	 * as the counters were set to zero */
}

static void esdm_sched_pool_extract(struct entropy_buf *eb, u32 requested_bits,
				    u32 entropy_rate)
{
	esdm_es_drbg_pool_extract(&esdm_sched_drbg, eb, requested_bits,
				  entropy_rate);
}

static void esdm_sched_randomness(const struct task_struct *p, int cpu)
{
	unsigned long flags;

	/*
	 * The hook runs from try_to_wake_up() after it dropped p->pi_lock, i.e.
	 * with only preemption disabled. An interrupt waking up a task nests
	 * a second call on this CPU, but the per-CPU ring write pointer, the
	 * last timestamp and the stuck test assume a single producer per CPU:
	 * with the nested call between the outer call's load and store of wp,
	 * the outer one moves wp back behind the events the nested one added.
	 * If the consumer released those in the meantime, wp ends behind rp
	 * and the ring presents almost ESDM_DATA_NUM_VALUES stale events as
	 * new ones. Keep interrupts off for the update. The interrupt ES does
	 * not need this, it runs in hard interrupt context with interrupts
	 * disabled already.
	 */
	local_irq_save(flags);
	esdm_time_process(&esdm_sched_ring, esdm_int_es_sched,
			  esdm_raw_sched_hires_entropy_store,
			  esdm_sched_perf_time);
	local_irq_restore(flags);
}

/*
 * The state of the entropy source as a JSON object. The inserted strings are
 * compile-time constants of this module and the DRBG name, none of which
 * contains a character JSON would require to be escaped.
 */
static void esdm_sched_es_state_json(unsigned char *buf, size_t buflen,
				     u32 entropy_rate)
{
	snprintf(buf, buflen,
		 "{"
		 "\"drbg_for_operating_entropy_pool\":\"%s\","
		 "\"available_entropy\":%u,"
		 "\"per_cpu_scheduler_event_collection_size\":%u,"
		 "\"standards_compliance\":\"%s\","
#ifdef CONFIG_CRYPTO_FIPS
		 "\"fips_mode_enabled\":%i,"
#endif /* CONFIG_CRYPTO_FIPS */
		 "\"high_resolution_timer\":%s"
		 "}",
		 esdm_drbg_cb->drbg_name(),
		 esdm_sched_avail_entropy(entropy_rate), ESDM_DATA_NUM_VALUES,
		 esdm_sp80090b_compliant(esdm_int_es_sched) ? "SP800-90B" : "",
#ifdef CONFIG_CRYPTO_FIPS
		 fips_enabled,
#endif /* CONFIG_CRYPTO_FIPS */
		 esdm_highres_timer() ? "true" : "false");
}

struct esdm_es_cb esdm_es_sched = {
	.name = "Scheduler",
	.get_ent = esdm_sched_pool_extract,
	.curr_entropy = esdm_sched_avail_entropy,
	.max_entropy = esdm_sched_avail_pool_size,
	.state_json = esdm_sched_es_state_json,
	.reset = esdm_sched_reset,
};

/************************** Registration with Kernel **************************/

int __init esdm_es_sched_module_init(void)
{
	void *drbg_state;
	int ret;

	if (!esdm_highres_timer()) {
		pr_warn("Not registering sched. hook (missing highres timer)!\n");
		return -EINVAL;
	}

	if (esdm_es_ring_alloc(&esdm_sched_ring))
		return -ENOMEM;

	/*
	 * As for the IRQ ES, the DRBG is published only once everything else
	 * succeeded, so an error path never frees a DRBG in use.
	 */
	drbg_state = esdm_drbg_cb->drbg_alloc(
		(u8 *)esdm_sched_drbg_domain_separation,
		sizeof(esdm_sched_drbg_domain_separation) - 1);
	/* drbg_alloc() reports failure via ERR_PTR, never NULL. */
	if (IS_ERR_OR_NULL(drbg_state)) {
		pr_warn("could not alloc DRBG for post-processing\n");
		ret = drbg_state ? PTR_ERR(drbg_state) : -ENOMEM;
		goto free_mem;
	}

	/* register scheduler hook */
	ret = esdm_sched_register(esdm_sched_randomness);
	if (ret) {
		pr_warn("Unable to register ESDM scheduler ES\n");
		esdm_drbg_cb->drbg_dealloc(drbg_state);
		goto free_mem;
	}

	/* Pairs with smp_load_acquire() in esdm_es_drbg_pool_extract() */
	smp_store_release(&esdm_sched_drbg.drbg_state, drbg_state);

	pr_info("ESDM Scheduler ES registered, DRBG: %s\n",
		esdm_drbg_cb->drbg_name());

	return 0;

free_mem:
	esdm_es_ring_free(&esdm_sched_ring);
	return ret;
}

void esdm_es_sched_module_exit(void)
{
	pr_warn("Unloading the ESDM Scheduler ES works only on a best effort basis for "
		"development purposes!\n");

	/*
	 * The hook calls the callback with interrupts / preemption disabled,
	 * an RCU read-side critical section, so synchronize_rcu() waits for
	 * all in-flight callbacks before the ring and DRBG are freed. Newer
	 * hook patches do this in esdm_sched_unregister() already, kernels
	 * built with an older one do not. Both sleep, so no atomic section
	 * around them.
	 */
	esdm_sched_unregister(esdm_sched_randomness);
	synchronize_rcu();

	if (esdm_sched_drbg.drbg_state) {
		esdm_drbg_cb->drbg_dealloc(esdm_sched_drbg.drbg_state);
		esdm_sched_drbg.drbg_state = NULL;
	} else {
		pr_warn("ESDM Scheduler ES DRBG state was never registered!\n");
	}

	esdm_sched_reset();

	esdm_es_ring_free(&esdm_sched_ring);

	pr_info("ESDM Scheduler ES unregistered\n");
}
