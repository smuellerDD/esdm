// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Interrupt data collection
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/irq_regs.h>
#include <asm/ptrace.h>
#include <crypto/drbg.h>
#include <linux/esdm_irq.h>
#include <linux/module.h>
#include <linux/random.h>

#include "esdm_es_mgr_cb.h"
#include "esdm_es_drbg.h"
#include "esdm_es_irq.h"
#include "esdm_es_ring.h"
#include "esdm_es_timer_common.h"
#include "esdm_drbg_kcapi.h"
#include "esdm_health.h"
#include "esdm_testing.h"

static const char esdm_irq_drbg_domain_separation[] = "ESDM_IRQ_DRBG";
/*
 * Number of interrupts to be recorded to assume that DRNG security strength
 * bits of entropy are received.
 * Note: a value below the DRNG security strength should not be defined as this
 *	 may imply the DRNG can never be fully seeded in case other noise
 *	 sources are unavailable.
 */
#define ESDM_IRQ_ENTROPY_BITS CONFIG_ESDM_IRQ_ENTROPY_RATE

static u32 irq_entropy __read_mostly = ESDM_IRQ_ENTROPY_BITS;
#ifdef CONFIG_ESDM_RUNTIME_ES_CONFIG
module_param(irq_entropy, uint, 0444);
MODULE_PARM_DESC(
	irq_entropy,
	"How many interrupts must be collected for obtaining 256 bits of entropy\n");
#endif

/* Per-CPU ring buffer holding concatenated IRQ entropy events */
static DEFINE_PER_CPU(struct esdm_es_ring_cpu, esdm_irq_ring_cpu);
static struct esdm_es_ring esdm_irq_ring = {
	.cpu = &esdm_irq_ring_cpu,
	.name = "interrupt",
};

/* DRBG post-processing description for the interrupt entropy source */
static struct esdm_es_drbg esdm_irq_drbg = {
	.ring = &esdm_irq_ring,
	.domain_separation = esdm_irq_drbg_domain_separation,
	.domain_separation_len = sizeof(esdm_irq_drbg_domain_separation) - 1,
	.es = esdm_int_es_irq,
	.entropy_bits = ESDM_IRQ_ENTROPY_BITS,
	.name = "interrupt",
};

void __init esdm_irq_es_init(bool highres_timer)
{
	/* 25 is arbitrary, but will never the less be far to
	 * large for the current event array size */
	BUG_ON(ESDM_ES_OSR <= 0 || ESDM_ES_OSR > 25);

	/* reseeding possible with current array size? */
	BUG_ON(ESDM_ES_OSR * (256 + 64) * 2 > ESDM_DATA_NUM_VALUES);

	/* Set a minimum number of interrupts that must be collected */
	irq_entropy = max_t(u32, ESDM_IRQ_ENTROPY_BITS, irq_entropy);

	esdm_irq_drbg.entropy_bits = irq_entropy;

	/* One pool should hold sufficient entropy for a single request from user-space */
	u32 max_ent = esdm_data_to_entropy(ESDM_DATA_NUM_VALUES,
					   esdm_irq_drbg.entropy_bits);
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
	/* Trigger GCD calculation anew. */
	esdm_gcd_set(0);

	esdm_es_ring_reset(&esdm_irq_ring);

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
	return esdm_es_drbg_avail_entropy(&esdm_irq_drbg);
}

static void esdm_irq_pool_extract(struct entropy_buf *eb, u32 requested_bits)
{
	esdm_es_drbg_pool_extract(&esdm_irq_drbg, eb, requested_bits);
}

/* Hot code path - Callback for interrupt handler */
static void esdm_add_interrupt_randomness(int irq)
{
	esdm_time_process(&esdm_irq_ring, esdm_int_es_irq,
			  esdm_raw_hires_entropy_store, esdm_irq_perf_time);
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

/*
 * Same properties as esdm_irq_es_state(), rendered as a JSON object. The
 * inserted strings are compile-time constants of this module and the DRBG
 * name, none of which contains a character JSON would require to be escaped.
 */
static void esdm_irq_es_state_json(unsigned char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 "{"
		 "\"drbg_for_operating_entropy_pool\":\"%s\","
		 "\"available_entropy\":%u,"
		 "\"per_cpu_interrupt_collection_size\":%u,"
		 "\"standards_compliance\":\"%s\","
#ifdef CONFIG_CRYPTO_FIPS
		 "\"fips_mode_enabled\":%i,"
#endif /* CONFIG_CRYPTO_FIPS */
		 "\"high_resolution_timer\":%s"
		 "}",
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
	esdm_irq_drbg.entropy_bits = max_t(u32, ESDM_IRQ_ENTROPY_BITS, rate);
}

struct esdm_es_cb esdm_es_irq = {
	.name = "IRQ",
	.get_ent = esdm_irq_pool_extract,
	.curr_entropy = esdm_irq_avail_entropy,
	.max_entropy = esdm_irq_avail_pool_size,
	.state = esdm_irq_es_state,
	.state_json = esdm_irq_es_state_json,
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
	esdm_irq_drbg.drbg_state = esdm_drbg_cb->drbg_alloc(
		(u8 *)esdm_irq_drbg_domain_separation,
		sizeof(esdm_irq_drbg_domain_separation) - 1);
	/*
	 * drbg_alloc() reports failure via ERR_PTR, never NULL. Testing for
	 * NULL would store an error pointer as the live DRBG state and later
	 * dereference / kfree it. Normalize to NULL so the teardown and the
	 * NULL-guarded sec_strength/is_initialized helpers stay safe.
	 */
	if (IS_ERR_OR_NULL(esdm_irq_drbg.drbg_state)) {
		esdm_irq_drbg.drbg_state = NULL;
		pr_warn("could not alloc DRBG for post-processing\n");
		goto err;
	}

	if (esdm_es_ring_alloc(&esdm_irq_ring))
		goto err;

	ret = esdm_irq_register(esdm_add_interrupt_randomness);
	if (ret) {
		pr_warn("cannot register ESDM IRQ ES\n");
		goto free_arrays;
	}

	pr_info("ESDM IRQ ES registered, DRBG: %s\n",
		esdm_drbg_cb->drbg_name());
	return;

free_arrays:
	esdm_es_ring_free(&esdm_irq_ring);

err:
	if (esdm_irq_drbg.drbg_state) {
		esdm_drbg_cb->drbg_dealloc(esdm_irq_drbg.drbg_state);
		esdm_irq_drbg.drbg_state = NULL;
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
	if (atomic_read(&esdm_es_irq_init_state) == esdm_es_init_unused)
		return;

	/*
	 * The deferred setup work may still be queued or sleeping in
	 * wait_for_random_bytes(). Wait for it to finish before tearing down
	 * (and before the module text/state it touches is freed); otherwise
	 * the work runs against freed state. This also covers the
	 * still-registering early return below, which would otherwise leave the
	 * work pending. cancel_work_sync tolerates a never-queued work item.
	 */
	cancel_work_sync(&esdm_es_irq_set_callback);

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

	if (esdm_irq_drbg.drbg_state) {
		esdm_drbg_cb->drbg_dealloc(esdm_irq_drbg.drbg_state);
		esdm_irq_drbg.drbg_state = NULL;
	} else {
		pr_warn("ESDM IRQ ES DRBG state was never registered!\n");
	}

	esdm_irq_reset();

	esdm_es_ring_free(&esdm_irq_ring);

	pr_info("ESDM IRQ ES unregistered\n");

	atomic_set(&esdm_es_irq_init_state, esdm_es_init_unused);
}
