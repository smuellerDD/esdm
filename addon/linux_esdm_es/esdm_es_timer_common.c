// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Interrupt data collection
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/gcd.h>
#include <linux/module.h>
#include <linux/random.h>

#include "esdm_es_irq.h"
#include "esdm_es_ring.h"
#include "esdm_es_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_health.h"

/* Is high-resolution timer present? */
static bool esdm_highres_timer_val = false;

/* Number of time stamps analyzed to calculate a GCD */
#define ESDM_GCD_WINDOW_SIZE 100
static u64 esdm_gcd_history[ESDM_GCD_WINDOW_SIZE];
static atomic_t esdm_gcd_history_ptr = ATOMIC_INIT(-1);

/* The common divisor for all timestamps */
static u64 esdm_gcd_timer = 0;

bool esdm_gcd_tested(void)
{
	return (READ_ONCE(esdm_gcd_timer) != 0);
}

u64 esdm_gcd_get(void)
{
	return READ_ONCE(esdm_gcd_timer);
}

/* Set the GCD for use in IRQ ES - if 0, the GCD calculation is restarted. */
void esdm_gcd_set(u64 running_gcd)
{
	WRITE_ONCE(esdm_gcd_timer, running_gcd);
	/* Ensure that update to global variable esdm_gcd_timer is visible */
	mb();
}

static void esdm_gcd_set_check(u64 running_gcd)
{
	if (!esdm_gcd_tested()) {
		esdm_gcd_set(running_gcd);
		pr_debug("Setting GCD to %llu\n", running_gcd);
	}
}

u64 esdm_gcd_analyze(u64 *history, size_t nelem)
{
	u64 running_gcd = 0;
	size_t i;

	/* Now perform the analysis on the accumulated time data. */
	for (i = 0; i < nelem; i++) {
		/*
		 * NOTE: this would be the place to add more analysis on the
		 * appropriateness of the timer like checking the presence
		 * of sufficient variations in the timer.
		 */

		/*
		 * This calculates the gcd of all the time values. that is
		 * gcd(time_1, time_2, ..., time_nelem)
		 *
		 * Some timers increment by a fixed (non-1) amount each step.
		 * This code checks for such increments, and allows the library
		 * to output the number of such changes have occurred.
		 */
		running_gcd = (u64)gcd(history[i], running_gcd);

		/* Zeroize data */
		history[i] = 0;
	}

	return running_gcd;
}

void esdm_gcd_add_value(u64 time)
{
	u64 ptr = (u64)atomic_inc_return_relaxed(&esdm_gcd_history_ptr);

	if (ptr < ESDM_GCD_WINDOW_SIZE) {
		esdm_gcd_history[ptr] = time;
	} else if (ptr == ESDM_GCD_WINDOW_SIZE) {
		u64 gcd = esdm_gcd_analyze(esdm_gcd_history,
					   ESDM_GCD_WINDOW_SIZE);

		if (!gcd)
			gcd = 1;

		/*
		 * Ensure that we have variations in the time stamp below the
		 * given value. This is just a safety measure to prevent the GCD
		 * becoming too large.
		 */
		if (gcd >= 1000) {
			pr_warn("calculated GCD is larger than expected: %llu\n",
				gcd);
			gcd = 1000;
		}

		/*  Adjust all deltas by the observed (small) common factor. */
		esdm_gcd_set_check(gcd);
		atomic_set(&esdm_gcd_history_ptr, 0);
	}
}

static void esdm_time_process_common(struct esdm_es_ring *ring,
				     enum esdm_internal_es es,
				     bool (*raw_hires_store)(u64 value),
				     u64 time)
{
	enum esdm_health_res health_test;
	u64 *last_timestamp = &this_cpu_ptr(ring->cpu)->last_timestamp;
	u64 delta = time - *last_timestamp;

	if (*last_timestamp == 0) {
		*last_timestamp = time;
		return;
	}

	*last_timestamp = time;

	if (raw_hires_store(delta))
		return;

	health_test = esdm_health_test(time, es);
	if (health_test > esdm_health_fail_use)
		return;

	if (health_test == esdm_health_pass)
		esdm_es_ring_add(ring, time);
}

/*
 * Batching up of entropy in a per-CPU ring before injecting into the entropy
 * pool. Shared hot path for the interrupt and scheduler entropy sources.
 */
void esdm_time_process(struct esdm_es_ring *ring, enum esdm_internal_es es,
		       bool (*raw_hires_store)(u64 value),
		       bool (*perf_time)(u64 start))
{
	u64 now_time = random_get_entropy();
	/*
	 * Snapshot the GCD once: a concurrent esdm_gcd_set(0) on another CPU
	 * (reset / health failure / vmgenid notifier) between a separate
	 * "tested" check and the divide would otherwise turn the divisor into 0
	 * and oops in the hot path.
	 */
	u64 gcd = esdm_gcd_get();

	if (unlikely(!gcd)) {
		/* When GCD is unknown, we process the full time stamp */
		esdm_time_process_common(ring, es, raw_hires_store, now_time);
		esdm_gcd_add_value(now_time);
	} else {
		/* GCD is known and applied */
		esdm_time_process_common(ring, es, raw_hires_store,
					 now_time / gcd);
	}

	perf_time(now_time);
}

/* Return boolean whether ESDM identified presence of high-resolution timer */
bool esdm_highres_timer(void)
{
	return esdm_highres_timer_val;
}

int __init esdm_init_time_source(void)
{
	static const u64 ESDM_DATA_WORD_MASK = 0xFFFFFFFF;

	/* check if the lower 32 bit of the timestamp
	 * already sufficiently change */
	if ((random_get_entropy() & ESDM_DATA_WORD_MASK) ||
	    (random_get_entropy() & ESDM_DATA_WORD_MASK)) {
		/*
		 * As the highres timer is identified here, previous interrupts
		 * obtained during boot time are treated like a lowres-timer
		 * would have been present.
		 */
		esdm_highres_timer_val = true;
	} else {
		esdm_health_disable();
		esdm_highres_timer_val = false;
	}

#ifdef ESDM_ES_IRQ
	esdm_irq_es_init(esdm_highres_timer_val);
#endif /* ESDM_ES_IRQ */
#ifdef ESDM_ES_SCHED
	esdm_sched_es_init(esdm_highres_timer_val);
#endif /* ESDM_ES_SCHED */

	/* Ensure that changes to global variables are visible */
	mb();

	return 0;
}
