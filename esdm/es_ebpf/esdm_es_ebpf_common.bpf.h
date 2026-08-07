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

/* Per-CPU collection and health test state */
struct esdm_ebpf_percpu_state {
	__u8 data[ESDM_EBPF_BATCH_EVENTS];
	__u32 pos; /* next byte in ->data */
	__u32 in_progress; /* same-CPU nesting guard */
	__u64 seq; /* batch sequence number */
	__u64 last_event_ns; /* monotonic time of last event */
	__u32 reset_gen; /* observed reset generation */

	/* Stuck test state */
	__u64 stuck_last_time;
	__u64 stuck_last_delta;
	__u64 stuck_last_delta2;

	/* Repetition Count Test state */
	__u32 rct_count;

	/* Adaptive Proportion Test state */
	__u32 apt_count;
	__u32 apt_base;
	__u32 apt_base_set;
	__u32 apt_trigger;

	/* SP800-90B startup test state */
	__u32 startup_blocks;
	__u32 startup_done;

	/* Failure bits to report with the next batch record */
	__u32 health_pending;

	/* Flush timer of this CPU initialized? */
	__u32 timer_inited;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct esdm_ebpf_percpu_state);
} esdm_ebpf_state SEC(".maps");

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

/* CPU cycle counter perf events, filled by user space (one per CPU) */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} esdm_ebpf_perf SEC(".maps");

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

/* Filled by user space before the program is loaded */
const volatile struct esdm_ebpf_config esdm_ebpf_cfg;

#include "esdm_es_ebpf_health.bpf.h"

/*
 * Obtain the event time stamp with the best available mechanism: the CPU
 * cycle counter read through the perf subsystem where available (higher
 * resolution, especially in virtualized environments with coarse
 * clocksources), otherwise the nanosecond monotonic clock whose value is
 * passed in by the caller.
 */
static __always_inline __u64 esdm_ebpf_timestamp(__u64 now_ns)
{
	if (esdm_ebpf_cfg.use_perf_counter) {
		__u64 cycles = bpf_perf_event_read(&esdm_ebpf_perf,
						   BPF_F_CURRENT_CPU);

		/* On error (negative value), fall back to the clock */
		if ((__s64)cycles >= 0)
			return cycles;
	}

	return now_ns;
}

static __always_inline void
esdm_ebpf_submit_batch(struct esdm_ebpf_percpu_state *state)
{
	struct esdm_ebpf_batch_rec *rec;

	rec = bpf_ringbuf_reserve(&esdm_ebpf_rb, sizeof(*rec), 0);
	if (!rec) {
		__u32 zero = 0;
		struct esdm_ebpf_status *status =
			bpf_map_lookup_elem(&esdm_ebpf_status_map, &zero);

		/*
		 * Consumer cannot keep up - conservatively discard the
		 * collected data so that no event is ever accounted twice.
		 */
		if (status)
			__sync_fetch_and_add(&status->batches_dropped, 1);
		state->pos = 0;
		state->seq++;
		return;
	}

	rec->type = esdm_ebpf_rec_batch;
	rec->cpu = bpf_get_smp_processor_id();
	rec->seq = state->seq;
	rec->events = state->pos;
	rec->health = state->health_pending |
		      (state->startup_done ? ESDM_EBPF_HEALTH_STARTUP_DONE : 0);
	state->health_pending = 0;
	__builtin_memcpy(rec->data, state->data, sizeof(rec->data));

	bpf_ringbuf_submit(rec, 0);

	state->pos = 0;
	state->seq++;
}

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
 * Process one event: fold the 8 LSBs of the event timestamp into the per-CPU
 * collection buffer and submit a batch record once the buffer is full.
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
	__u64 now_ns, ts;
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
		state->pos = 0;
		esdm_ebpf_health_reset(state);
		state->reset_gen = status->reset_gen;
	}

	now_ns = bpf_ktime_get_ns();
	ts = esdm_ebpf_timestamp(now_ns);

#ifdef ESDM_ES_EBPF_TESTING
	/* Raw measurement mode: emit the unconditioned time stamp */
	if (esdm_ebpf_cfg.raw_sampling) {
		struct esdm_ebpf_raw_rec *raw_rec =
			bpf_ringbuf_reserve(&esdm_ebpf_rb, sizeof(*raw_rec), 0);

		if (raw_rec) {
			raw_rec->type = esdm_ebpf_rec_raw;
			raw_rec->cpu = bpf_get_smp_processor_id();
			raw_rec->ts = ts;
			bpf_ringbuf_submit(raw_rec, 0);
		}
	}
#endif /* ESDM_ES_EBPF_TESTING */

	if (esdm_ebpf_health_test(state, ts)) {
		/* SP800-90B disallows using a failing time stamp */
		state->in_progress = 0;
		return;
	}

	state->data[state->pos & (ESDM_EBPF_BATCH_EVENTS - 1)] = (__u8)ts;
	state->pos++;
	state->last_event_ns = now_ns;

	if (state->pos >= ESDM_EBPF_BATCH_EVENTS)
		esdm_ebpf_submit_batch(state);
	else if (esdm_ebpf_cfg.flush_timer_enabled && state->pos == 1)
		esdm_ebpf_timer_arm(state);

	state->in_progress = 0;
}

#endif /* _ESDM_ES_EBPF_COMMON_BPF_H */
