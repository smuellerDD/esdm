// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: Interrupt data collection
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/gcd.h>
#include <linux/module.h>

#include "esdm_es_irq.h"
#include "esdm_es_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_health.h"

/* Is high-resolution timer present? */
static bool esdm_highres_timer_val = false;

/* Number of time stamps analyzed to calculate a GCD */
#define ESDM_GCD_WINDOW_SIZE	100
static u32 esdm_gcd_history[ESDM_GCD_WINDOW_SIZE];
static atomic_t esdm_gcd_history_ptr = ATOMIC_INIT(-1);

/* The common divisor for all timestamps */
static u32 esdm_gcd_timer = 0;

bool esdm_gcd_tested(void)
{
	return (esdm_gcd_timer != 0);
}

u32 esdm_gcd_get(void)
{
	return esdm_gcd_timer;
}

/* Set the GCD for use in IRQ ES - if 0, the GCD calculation is restarted. */
void esdm_gcd_set(u32 running_gcd)
{
	esdm_gcd_timer = running_gcd;
	/* Ensure that update to global variable esdm_gcd_timer is visible */
	mb();
}

static void esdm_gcd_set_check(u32 running_gcd)
{
	if (!esdm_gcd_tested()) {
		esdm_gcd_set(running_gcd);
		pr_debug("Setting GCD to %u\n", running_gcd);
	}
}

u32 esdm_gcd_analyze(u32 *history, size_t nelem)
{
	u32 running_gcd = 0;
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
		running_gcd = (u32)gcd(history[i], running_gcd);

		/* Zeroize data */
		history[i] = 0;
	}

	return running_gcd;
}

void esdm_gcd_add_value(u32 time)
{
	u32 ptr = (u32)atomic_inc_return_relaxed(&esdm_gcd_history_ptr);

	if (ptr < ESDM_GCD_WINDOW_SIZE) {
		esdm_gcd_history[ptr] = time;
	} else if (ptr == ESDM_GCD_WINDOW_SIZE) {
		u32 gcd = esdm_gcd_analyze(esdm_gcd_history,
					   ESDM_GCD_WINDOW_SIZE);

		if (!gcd)
			gcd = 1;

		/*
		 * Ensure that we have variations in the time stamp below the
		 * given value. This is just a safety measure to prevent the GCD
		 * becoming too large.
		 */
		if (gcd >= 1000) {
			pr_warn("calculated GCD is larger than expected: %u\n",
				gcd);
			gcd = 1000;
		}

		/*  Adjust all deltas by the observed (small) common factor. */
		esdm_gcd_set_check(gcd);
		atomic_set(&esdm_gcd_history_ptr, 0);
	}
}

/* Return boolean whether ESDM identified presence of high-resolution timer */
bool esdm_highres_timer(void)
{
	return esdm_highres_timer_val;
}

int __init esdm_init_time_source(void)
{
	if ((random_get_entropy() & ESDM_DATA_SLOTSIZE_MASK) ||
	    (random_get_entropy() & ESDM_DATA_SLOTSIZE_MASK)) {
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

	esdm_irq_es_init(esdm_highres_timer_val);
	esdm_sched_es_init(esdm_highres_timer_val);

	/* Ensure that changes to global variables are visible */
	mb();

	return 0;
}
