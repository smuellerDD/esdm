/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM eBPF-based entropy sources: common eBPF program logic
 *
 * Maps and event collection logic shared by the scheduler and interrupt
 * eBPF entropy source programs. Each program includes this header exactly
 * once and thereby obtains its own private set of maps.
 *
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
 */

#ifndef _ESDM_ES_EBPF_COMMON_BPF_H
#define _ESDM_ES_EBPF_COMMON_BPF_H

/*
 * The programs never dereference kernel data structures (only the event
 * timing is collected, no tracepoint arguments are accessed), so no
 * vmlinux.h / CO-RE machinery is required - the stable UAPI headers
 * suffice and keep the programs kernel-version independent by design.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <bpf/bpf_helpers.h>

#include "esdm_es_ebpf_shared.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct esdm_ebpf_percpu_state);
} esdm_ebpf_state SEC(".maps");

/*
 * Collection buffer. The programs deposit one record per event here and user
 * space reads them when it wants entropy, so this is what buffers the events
 * in between - user space sizes it for that before the program is loaded, the
 * size here being the fallback for a loader that does not.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} esdm_ebpf_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct esdm_ebpf_status);
} esdm_ebpf_status_map SEC(".maps");

/*
 * Zero source of the ring buffer zeroization. An array map value is
 * zero-initialized by the kernel and nothing ever writes to this one, so it
 * stays a block of zeros for the lifetime of the program.
 */
struct esdm_ebpf_wipe_buf {
	__u8 zeros[ESDM_EBPF_WIPE_CHUNK];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct esdm_ebpf_wipe_buf);
} esdm_ebpf_wipe_src SEC(".maps");

/* Per-CPU flush timers (max_entries resized to the CPU count by user space) */
struct esdm_ebpf_timer_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct esdm_ebpf_timer_elem);
} esdm_ebpf_timers SEC(".maps");

/*
 * Filled by user space before the program is loaded. The explicit initializer
 * makes this a definition rather than a tentative one, which under -fcommon
 * would become a common symbol outside the ".rodata" section the skeleton
 * exposes and the verifier constant-folds. "volatile" keeps the compiler from
 * folding the reads against the zero initializer, "const" places the object in
 * the read-only section.
 */
const volatile struct esdm_ebpf_config esdm_ebpf_cfg = { 0 };

#include "esdm_es_ebpf_health.bpf.h"

/* Window of raw time stamps analyzed to derive the timer granularity (GCD) */
#define ESDM_EBPF_GCD_WINDOW 100
/* Upper bound of the accepted GCD, mirrors the ESDM kernel add-on */
#define ESDM_EBPF_GCD_MAX 1000

/*
 * Greatest common divisor via bounded Euclid. The u64 worst case (consecutive
 * Fibonacci numbers) converges in under 92 iterations; the fixed bound keeps
 * the loop acceptable to the eBPF verifier.
 */
static __always_inline __u64 esdm_ebpf_gcd64(__u64 a, __u64 b)
{
	int i;

	for (i = 0; i < 128 && b; i++) {
		__u64 t = b;

		b = a % b;
		a = t;
	}

	return a;
}

static __always_inline void
esdm_ebpf_gcd_reset(struct esdm_ebpf_percpu_state *state)
{
	state->gcd_val = 0;
	state->gcd_running = 0;
	state->gcd_count = 0;
}

/*
 * Divide out the common granularity of the time source, mirroring the GCD
 * handling of the kernel add-on (esdm_es_timer_common.c). Coarse clock sources
 * increment in fixed steps, leaving the low-order time stamp bits constant and
 * thus entropy-free. The GCD of the first ESDM_EBPF_GCD_WINDOW raw time stamps
 * of a CPU estimates that step; later time stamps are divided by it so the
 * low-order bits vary. Until it is known, the raw time stamp is used.
 */
static __always_inline __u64
esdm_ebpf_gcd_process(struct esdm_ebpf_percpu_state *state, __u64 ts)
{
	__u64 g = state->gcd_val;

	if (g)
		return ts / g;

	/* Learning phase: fold the raw time stamp into the running GCD */
	state->gcd_running = esdm_ebpf_gcd64(ts, state->gcd_running);

	if (++state->gcd_count >= ESDM_EBPF_GCD_WINDOW) {
		g = state->gcd_running;
		/* Clamp as the kernel add-on does: never 0, never too coarse */
		if (!g)
			g = 1;
		else if (g >= ESDM_EBPF_GCD_MAX)
			g = ESDM_EBPF_GCD_MAX;
		state->gcd_val = g;
	}

	return ts;
}

/*
 * Hand the collected deltas of this CPU over. The record goes out with exactly
 * the length its deltas occupy, so a partial batch costs no more than it holds.
 * Whether it made it through changes nothing: the buffer starts over either
 * way, so no delta is accounted twice. A full ring buffer means user space is
 * not keeping up and the deltas are dropped, which costs nothing - the events
 * behind them are no worse.
 */
static __always_inline void
esdm_ebpf_submit_batch(struct esdm_ebpf_percpu_state *state)
{
	__u32 events = state->pos;

	/* Bound for the verifier; the store in the collection keeps it true */
	if (events > ESDM_EBPF_BATCH_EVENTS)
		events = ESDM_EBPF_BATCH_EVENTS;

	state->rec.type = esdm_ebpf_rec_event;
	state->rec.cpu = bpf_get_smp_processor_id();
	state->rec.reset_gen = state->reset_gen;
	state->rec.events = events;

	/*
	 * Count only what made it in: the difference to what user space has
	 * fetched is what is still waiting in the ring buffer, and dropped
	 * deltas are not.
	 */
	if (!bpf_ringbuf_output(&esdm_ebpf_rb, &state->rec,
				ESDM_EBPF_EVENT_REC_LEN(events), 0))
		state->events += events;

	/*
	 * The deltas have left the collection buffer, so the record sitting in
	 * it is one the entropy source has no further use for: it is erased
	 * rather than left to be overwritten by the next batch, which would
	 * keep raw samples around for as long as the CPU stays quiet.
	 */
	__builtin_memset(&state->rec, 0, sizeof(state->rec));
	state->pos = 0;
}

#ifdef ESDM_ES_EBPF_TESTING
/*
 * Hand one raw delta over - measurement mode only. A full ring buffer drops
 * it, which costs a sample and nothing else: every delta stands on its own.
 */
static __always_inline void
esdm_ebpf_submit_raw(struct esdm_ebpf_percpu_state *state, __u64 delta)
{
	struct esdm_ebpf_raw_rec rec;

	(void)state;

	rec.type = esdm_ebpf_rec_raw;
	rec.cpu = bpf_get_smp_processor_id();
	rec.delta = delta;

	bpf_ringbuf_output(&esdm_ebpf_rb, &rec, sizeof(rec), 0);
}
#endif /* ESDM_ES_EBPF_TESTING */

/*
 * Flush timer callback: submit a partially filled collection buffer once the
 * CPU has been idle for the configured deadline. This prevents the collected
 * data of quiet CPUs from lingering unaccounted in the collection buffer.
 *
 * The timer normally fires on the CPU that armed it; after a (rare) hrtimer
 * migration it flushes the state of the CPU it runs on, which is harmless as
 * the entropy accounting is strictly based on delivered event counts.
 */
static int esdm_ebpf_timer_cb(void *map, __u32 *key,
			      struct esdm_ebpf_timer_elem *elem)
{
	struct esdm_ebpf_percpu_state *state;
	__u32 zero = 0;
	__u64 now, idle_ns;

	(void)map;
	(void)key;

	state = bpf_map_lookup_elem(&esdm_ebpf_state, &zero);
	if (!state)
		return 0;

	/* Do not touch the state while an event is being processed */
	if (state->in_progress) {
		bpf_timer_start(&elem->timer, esdm_ebpf_cfg.flush_deadline_ns,
				0);
		return 0;
	}
	state->in_progress = 1;

	if (state->pos) {
		now = bpf_ktime_get_ns();
		idle_ns = now - state->last_event_ns;

		if (idle_ns >= esdm_ebpf_cfg.flush_deadline_ns)
			esdm_ebpf_submit_batch(state);
		else
			bpf_timer_start(
				&elem->timer,
				esdm_ebpf_cfg.flush_deadline_ns - idle_ns, 0);
	}

	state->in_progress = 0;
	return 0;
}

/* Arm the flush timer of the current CPU, initializing it on first use */
static __always_inline void
esdm_ebpf_timer_arm(struct esdm_ebpf_percpu_state *state)
{
	struct esdm_ebpf_timer_elem *elem;
	__u32 cpu = bpf_get_smp_processor_id();
	long ret;

	elem = bpf_map_lookup_elem(&esdm_ebpf_timers, &cpu);
	if (!elem)
		return;

	if (!state->timer_inited) {
		/* -EBUSY: already initialized (e.g. after a reset) */
		ret = bpf_timer_init(&elem->timer, &esdm_ebpf_timers,
				     CLOCK_MONOTONIC);
		if (ret && ret != -EBUSY)
			return;
		if (bpf_timer_set_callback(&elem->timer, esdm_ebpf_timer_cb))
			return;
		state->timer_inited = 1;
	}

	bpf_timer_start(&elem->timer, esdm_ebpf_cfg.flush_deadline_ns, 0);
}

/*
 * Process one event: health test the event time stamp and collect the time
 * since the previous event of this CPU in the per-CPU buffer, which is handed
 * to the ring buffer once it is full - or, for a CPU that falls quiet with a
 * partially filled one, by the flush timer.
 *
 * The health tests see every event, so they assess a gapless sequence, but
 * only the events they vouch for are collected. A buffer that is already full
 * drops the event, as does a full ring buffer: both mean user space is not
 * keeping up, and what is already collected is no worse than what would
 * replace it.
 *
 * The in_progress flag guards against same-CPU nesting: e.g. for the
 * interrupt entropy source a hardirq may preempt the program running in
 * softirq context on the same CPU. Nested contexts on one CPU are strictly
 * stacked, so a plain flag without atomics is sufficient - the nested event
 * is simply skipped.
 */
static __always_inline void esdm_ebpf_collect(void)
{
	struct esdm_ebpf_percpu_state *state;
	struct esdm_ebpf_status *status;
	__u64 now_ns, ts, gcd_known;
	__u32 zero = 0;

	state = bpf_map_lookup_elem(&esdm_ebpf_state, &zero);
	if (!state)
		return;

	if (state->in_progress)
		return;
	state->in_progress = 1;

	/*
	 * Lazily (re)initialize the per-CPU state: user space bumps the reset
	 * generation on load and on reset of the entropy source which
	 * restarts the health tests including the SP800-90B startup test and
	 * discards the collection buffer.
	 */
	status = bpf_map_lookup_elem(&esdm_ebpf_status_map, &zero);
	if (status && state->reset_gen != status->reset_gen) {
		state->last_ts = 0;
		state->pos = 0;
		/* Discard the collected record rather than only forget it */
		__builtin_memset(&state->rec, 0, sizeof(state->rec));
		esdm_ebpf_gcd_reset(state);
		esdm_ebpf_health_reset(state);
		state->reset_gen = status->reset_gen;
	}

	now_ns = bpf_ktime_get_ns();
	/*
	 * Strip the common timer granularity before storing / health testing.
	 * The divisor is learned from the first ESDM_EBPF_GCD_WINDOW time stamps
	 * and only applied afterwards, so remember whether it was already known
	 * for this one - the delta below may not span that change of scale.
	 */
	gcd_known = state->gcd_val;
	ts = esdm_ebpf_gcd_process(state, now_ns);


	if (esdm_ebpf_health_test(state, ts)) {
		/* SP800-90B disallows using a failing time stamp */
		state->in_progress = 0;
		return;
	}

	/*
	 * Collect the time between events rather than the time stamps: the
	 * entropy is in the spacing, the high-order bits are predictable. It is
	 * also what the SP800-90B assessment of the raw samples measures
	 * (iter_deltas() of esdm_ebpf_raw.py), so what is credited here is what
	 * was assessed there. The unsigned subtraction handles a wraparound.
	 *
	 * Two time stamps form no delta and only set the predecessor up: the
	 * first one a CPU sees, and the first one after the timer granularity
	 * became known, whose predecessor is on the undivided scale. The kernel
	 * add-on does the same (esdm_time_process_common()).
	 *
	 * Only deltas the health tests vouch for are collected, so the record
	 * carries no health state and user space may credit all of it.
	 */
	if (gcd_known && state->last_ts) {
		__u64 delta = ts - state->last_ts;

#ifdef ESDM_ES_EBPF_TESTING
		/*
		 * Raw measurement mode: hand the unconditioned delta over as
		 * its own record. It is the very value the collection below
		 * uses, so what is measured is what is collected.
		 */
		if (esdm_ebpf_cfg.raw_sampling)
			esdm_ebpf_submit_raw(state, delta);
#endif /* ESDM_ES_EBPF_TESTING */

		if (esdm_ebpf_health_ok(state) &&
		    state->pos < ESDM_EBPF_BATCH_EVENTS) {
			state->rec.delta[state->pos &
					 (ESDM_EBPF_BATCH_EVENTS - 1)] = delta;
			state->pos++;
			state->last_event_ns = now_ns;

			if (state->pos >= ESDM_EBPF_BATCH_EVENTS)
				esdm_ebpf_submit_batch(state);
			else if (state->pos == 1)
				esdm_ebpf_timer_arm(state);
		}
	}

	if (gcd_known)
		state->last_ts = ts;

	state->in_progress = 0;
}

/*
 * Zeroize the ring buffer: write filler records of zeros over the event records
 * it holds. The raw time deltas are the samples of an SP800-90B noise source
 * and none may outlive the entropy source, so user space runs this program
 * (BPF_PROG_RUN) on unload - draining the ring buffer in between to make room -
 * until the filler has covered it once. It is the one buffer user space cannot
 * clear itself, its data pages being mapped read-only, so only the producer
 * side can overwrite them.
 *
 * @return number of ring buffer bytes written, which tells user space how much
 *	   of the ring buffer is covered.
 */
SEC("syscall")
int esdm_ebpf_wipe(void *ctx)
{
	struct esdm_ebpf_wipe_buf *zeros;
	__u32 key = 0;
	int i, written = 0;

	(void)ctx;

	zeros = bpf_map_lookup_elem(&esdm_ebpf_wipe_src, &key);
	if (!zeros)
		return 0;

	for (i = 0; i < ESDM_EBPF_WIPE_RECORDS; i++) {
		/* A ring buffer with no room left ends this invocation */
		if (bpf_ringbuf_output(&esdm_ebpf_rb, zeros->zeros,
				       sizeof(zeros->zeros), 0))
			break;

		written += (int)(sizeof(zeros->zeros) +
				 ESDM_EBPF_RB_REC_OVERHEAD);
	}

	return written;
}

#endif /* _ESDM_ES_EBPF_COMMON_BPF_H */
