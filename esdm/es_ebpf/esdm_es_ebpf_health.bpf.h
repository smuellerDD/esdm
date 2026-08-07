/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM eBPF-based entropy sources: SP800-90B health tests in eBPF
 *
 * Port of the health tests of the ESDM Linux kernel add-on
 * (addon/linux_esdm_es/esdm_health.c) into eBPF program code:
 *
 * - Stuck test: the first, second and third derivative of the event time
 *   stamp must be non-zero.
 * - Repetition Count Test (RCT) per SP800-90B section 4.4.1 with an alpha of
 *   2^-30 (FIPS 140-2 IG 9.8), counting stuck time stamps.
 * - Adaptive Proportion Test (APT) per SP800-90B section 4.4.2 on the
 *   ESDM_APT_LSB least significant bits of the time stamp with a window size
 *   of 512 events.
 * - SP800-90B section 4.3 startup test: 1024 samples (two APT windows) must
 *   pass before the entropy source may deliver entropy.
 *
 * In deviation from the add-on which maintains the RCT/APT state globally
 * with atomic operations, all health state is maintained per CPU: the eBPF
 * programs run with migration disabled, so the state is lock-free without
 * atomics. Each CPU therefore executes its own independent instance of the
 * health tests on its own event sequence - including the startup test -
 * which is statistically at least as strict as the global variant.
 *
 * The test cutoff values are computed by user space from the configured
 * entropy rate and are passed via the read-only configuration.
 *
 * This header must be included via esdm_es_ebpf_common.bpf.h only.
 *
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
 * Health test logic derived from esdm_health.c,
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_EBPF_HEALTH_BPF_H
#define _ESDM_ES_EBPF_HEALTH_BPF_H

/* Reset the health test state to its initial (startup) values */
static __always_inline void
esdm_ebpf_health_reset(struct esdm_ebpf_percpu_state *state)
{
	state->stuck_last_time = 0;
	state->stuck_last_delta = 0;
	state->stuck_last_delta2 = 0;
	state->rct_count = 0;
	state->apt_count = 0;
	state->apt_base = 0;
	state->apt_base_set = 0;
	state->apt_trigger = ESDM_EBPF_APT_WINDOW_SIZE;
	state->startup_blocks = ESDM_EBPF_STARTUP_BLOCKS;
	state->startup_done = 0;
	state->health_failures = 0;
	state->permanent_failure = 0;
	state->health_test = 0;
}

/*
 * May the events of this CPU be collected? With the SP800-90B health tests
 * enabled the startup test must have completed - and as every failure
 * restarts it, this covers the failure case too: no event collected between
 * a failure and the completion of the new startup test, and therefore no
 * health state that would have to travel to user space with the events.
 */
static __always_inline __u32
esdm_ebpf_health_ok(const struct esdm_ebpf_percpu_state *state)
{
	return !esdm_ebpf_cfg.health_enabled || state->startup_done;
}

/* SP800-90B startup test progress: one APT window completed */
static __always_inline void
esdm_ebpf_sp80090b_startup(struct esdm_ebpf_percpu_state *state)
{
	if (!state->startup_done && state->startup_blocks &&
	    --state->startup_blocks == 0)
		state->startup_done = 1;
}

/*
 * Handle failure of the SP800-90B startup or runtime testing: restart the
 * startup test, which stops this CPU from collecting until it passes again.
 * The failure is recorded in the per-CPU state, from which user space picks it
 * up and invalidates the collected entropy.
 */
static __always_inline void
esdm_ebpf_sp80090b_failure(struct esdm_ebpf_percpu_state *state, __u32 test)
{
	state->health_failures++;
	state->health_test = test;
	state->startup_blocks = ESDM_EBPF_STARTUP_BLOCKS;
	state->startup_done = 0;
}

static __always_inline void
esdm_ebpf_sp80090b_permanent_failure(struct esdm_ebpf_percpu_state *state,
				     __u32 test)
{
	state->health_failures++;
	state->health_test = test;
	state->permanent_failure = 1;
	state->startup_blocks = ESDM_EBPF_STARTUP_BLOCKS;
	state->startup_done = 0;

	/* Reset RCT and APT */
	state->rct_count = 0;
	state->apt_count = 0;
	state->apt_base = 0;
	state->apt_trigger = ESDM_EBPF_APT_WINDOW_SIZE;
}

/*
 * Adaptive Proportion Test per SP800-90B section 4.4.2. The function does
 * not decide about the fate of the time stamp: an APT failure can only
 * happen at the same time as a stuck test failure which already decides how
 * the time stamp is handled.
 */
static __always_inline void
esdm_ebpf_apt_insert(struct esdm_ebpf_percpu_state *state, __u64 now_time)
{
	__u32 now_masked = (__u32)now_time & ESDM_EBPF_APT_WORD_MASK;

	/* Initialization of APT */
	if (!state->apt_base_set) {
		state->apt_base = now_masked;
		state->apt_base_set = 1;
		return;
	}

	if (now_masked == state->apt_base) {
		__u32 apt_val = ++state->apt_count;

		if (apt_val >= esdm_ebpf_cfg.apt_cutoff_permanent)
			esdm_ebpf_sp80090b_permanent_failure(
				state, esdm_ebpf_health_test_apt);
		else if (apt_val >= esdm_ebpf_cfg.apt_cutoff)
			esdm_ebpf_sp80090b_failure(state,
						   esdm_ebpf_health_test_apt);
	}

	if (state->apt_trigger && --state->apt_trigger == 0) {
		state->apt_trigger = ESDM_EBPF_APT_WINDOW_SIZE;
		state->apt_count = 0;
		state->apt_base = now_masked;
		esdm_ebpf_sp80090b_startup(state);
	}
}

/*
 * Repetition Count Test per SP800-90B section 4.4.1, counting the stuck
 * values with an alpha of 2^-30 (FIPS 140-2 IG 9.8).
 */
static __always_inline void esdm_ebpf_rct(struct esdm_ebpf_percpu_state *state,
					  __u32 stuck)
{
	if (stuck) {
		__u32 rct_count = ++state->rct_count;

		if (rct_count > esdm_ebpf_cfg.rct_cutoff_permanent)
			esdm_ebpf_sp80090b_permanent_failure(
				state, esdm_ebpf_health_test_rct);
		else if (rct_count > esdm_ebpf_cfg.rct_cutoff)
			esdm_ebpf_sp80090b_failure(state,
						   esdm_ebpf_health_test_rct);
	} else {
		state->rct_count = 0;
	}
}

/*
 * Stuck test: the first, second and third derivative of the event time
 * stamp must be non-zero. The unsigned subtractions yield the correct value
 * in the wraparound case.
 *
 * @return 0 time stamp not stuck, 1 time stamp stuck
 */
static __always_inline __u32
esdm_ebpf_timestamp_stuck(struct esdm_ebpf_percpu_state *state, __u64 now_time)
{
	__u64 delta = now_time - state->stuck_last_time;
	__u64 delta2 = delta - state->stuck_last_delta;
	__u64 delta3 = delta2 - state->stuck_last_delta2;

	state->stuck_last_time = now_time;
	state->stuck_last_delta = delta;
	state->stuck_last_delta2 = delta2;

	if (!delta || !delta2 || !delta3)
		return 1;

	return 0;
}

/*
 * Perform the health test on a raw event time stamp.
 *
 * @return 0 time stamp passed and shall be used,
 *	   1 time stamp failed and shall be dropped
 */
static __always_inline __u32
esdm_ebpf_health_test(struct esdm_ebpf_percpu_state *state, __u64 now_time)
{
	__u32 stuck;

	if (!esdm_ebpf_cfg.health_enabled)
		return 0;

	esdm_ebpf_apt_insert(state, now_time);

	stuck = esdm_ebpf_timestamp_stuck(state, now_time);
	esdm_ebpf_rct(state, stuck);

	/* SP800-90B disallows using a failing health test time stamp */
	return stuck;
}

#endif /* _ESDM_ES_EBPF_HEALTH_BPF_H */
