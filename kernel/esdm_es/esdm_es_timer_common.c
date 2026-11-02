// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Interrupt data collection
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bitops.h>
#include <linux/irq_work.h>
#include <linux/math64.h>
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
/*
 * A GCD of at least this value means the time stamps lack variations in their
 * low bits: no high-resolution timer.
 */
#define ESDM_GCD_MAX 1000
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

/*
 * The GCD is calculated in the hot path, i.e. from the scheduler hook which may
 * run with the workqueue pool->lock held. A printk there risks the deadlock
 * described for the health-test messages, so defer the warning about a capped
 * GCD to an irq_work as well.
 */
static u64 esdm_gcd_capped;

static void esdm_gcd_warn_func(struct irq_work *work)
{
	pr_warn("calculated GCD is larger than expected: %llu - no high-resolution timer, no entropy credited\n",
		READ_ONCE(esdm_gcd_capped));
}

static struct irq_work esdm_gcd_warn_work = IRQ_WORK_INIT(esdm_gcd_warn_func);

static void esdm_gcd_set_check(u64 running_gcd)
{
	if (!esdm_gcd_tested())
		esdm_gcd_set(running_gcd);
}

/*
 * Binary GCD as lib/math/gcd.c, but on u64: gcd() takes unsigned long and
 * would truncate the time stamps on 32-bit kernels.
 */
static u64 esdm_gcd64(u64 a, u64 b)
{
	u64 r = a | b;

	if (!a || !b)
		return r;

	b >>= __ffs64(b);
	if (b == 1)
		return r & -r;

	for (;;) {
		a >>= __ffs64(a);
		if (a == 1)
			return r & -r;
		if (a == b)
			return a << __ffs64(r);
		if (a < b)
			swap(a, b);
		a -= b;
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
		running_gcd = esdm_gcd64(history[i], running_gcd);

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
		 * given value. Otherwise the timer is too coarse to deliver
		 * entropy: stop crediting any, also after a later GCD
		 * recalculation.
		 */
		if (gcd >= ESDM_GCD_MAX) {
			WRITE_ONCE(esdm_highres_timer_val, false);
			WRITE_ONCE(esdm_gcd_capped, gcd);
			irq_work_queue(&esdm_gcd_warn_work);
			gcd = ESDM_GCD_MAX;
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
					 div64_u64(now_time, gcd));
	}

	perf_time(now_time);
}

/* Drain a pending GCD warning, called once the hooks are unregistered. */
void esdm_time_source_exit(void)
{
	irq_work_sync(&esdm_gcd_warn_work);
}

/* Return boolean whether ESDM identified presence of high-resolution timer */
bool esdm_highres_timer(void)
{
	return READ_ONCE(esdm_highres_timer_val);
}

/*
 * Number of back-to-back time stamps taken to detect a high-resolution timer
 * and how many of them must differ from their predecessor.
 */
#define ESDM_HIGHRES_TRIAL_SAMPLES 1024
#define ESDM_HIGHRES_MIN_CHANGES (ESDM_HIGHRES_TRIAL_SAMPLES / 64)

static bool __init esdm_highres_timer_detect(void)
{
	unsigned long last = random_get_entropy(), now;
	unsigned int i, changes = 0;

	/*
	 * A non-zero time stamp does not imply a high-resolution timer: since
	 * Linux 5.18 random_get_entropy() falls back to the raw clocksource
	 * counter on systems without a cycle counter, which may be jiffies.
	 * Like try_to_generate_entropy() in drivers/char/random.c, read the
	 * timer back-to-back and count how often it changed. A jiffies-based
	 * counter changes once or twice at most during the loop, a cycle
	 * counter or a fine-grained clocksource every few reads at least. On
	 * older kernels random_get_entropy() returns 0 without a cycle counter,
	 * which never changes either.
	 */
	for (i = 0; i < ESDM_HIGHRES_TRIAL_SAMPLES; i++) {
		now = random_get_entropy();
		if (now != last)
			changes++;
		last = now;
	}

	pr_debug("time stamp changed %u times in %u back-to-back reads\n",
		 changes, ESDM_HIGHRES_TRIAL_SAMPLES);

	return changes >= ESDM_HIGHRES_MIN_CHANGES;
}

int __init esdm_init_time_source(void)
{
	if (esdm_highres_timer_detect()) {
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
