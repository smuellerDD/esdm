/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM eBPF-based entropy sources: definitions shared between the eBPF
 * programs and user space.
 *
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
 */

#ifndef _ESDM_ES_EBPF_SHARED_H
#define _ESDM_ES_EBPF_SHARED_H

#include <linux/types.h>

/* SP800-90B section 4.4.2: APT window size */
#define ESDM_EBPF_APT_WINDOW_SIZE 512
/*
 * The APT is performed on the time stamp reduced modulo ESDM_EBPF_APT_LSB,
 * i.e. on its four low-order bits (ESDM_EBPF_APT_WORD_MASK == 0xf). This
 * matches the ESDM kernel add-on (esdm_health.c) verbatim.
 */
#define ESDM_EBPF_APT_LSB 16
#define ESDM_EBPF_APT_WORD_MASK (ESDM_EBPF_APT_LSB - 1)

/* SP800-90B section 4.3: startup test samples */
#define ESDM_EBPF_STARTUP_SAMPLES 1024
#define ESDM_EBPF_STARTUP_BLOCKS                                               \
	((ESDM_EBPF_STARTUP_SAMPLES + ESDM_EBPF_APT_WINDOW_SIZE - 1) /         \
	 ESDM_EBPF_APT_WINDOW_SIZE)

/* Record types submitted through the ring buffer */
enum esdm_ebpf_rec_type {
	/*
	 * Filler of the ring buffer zeroization: the type a record consisting
	 * of zeros carries, so the wipe leaves nothing behind that would have
	 * to be recognized by anything else than its emptiness.
	 */
	esdm_ebpf_rec_wipe = 0,
	esdm_ebpf_rec_event = 1, /* struct esdm_ebpf_event_rec */
	/*
	 * This is the on-disk record type of the raw collections
	 * esdm-ebpf-collect writes, so REC_TYPE_RAW of
	 * addon/es_ebpf_testing/esdm_ebpf_raw.py has to move with it - a parser
	 * that disagrees skips every record of a collection rather than
	 * reporting anything wrong with it.
	 */
	esdm_ebpf_rec_raw = 2, /* struct esdm_ebpf_raw_rec (testing only) */
};

/*
 * Deltas one CPU collects before handing them over. The programs flush the
 * buffer when it is full and, for a CPU that falls quiet with a partially
 * filled one, after the idle deadline of the flush timer - so a collected
 * delta never lingers unaccounted.
 *
 * Must be a power of two.
 */
#define ESDM_EBPF_BATCH_EVENTS 64

/*
 * The deltas one CPU collected: the time between each event and its
 * predecessor on that CPU. The spacing of the events is where the entropy is,
 * the time stamps themselves are largely predictable, and the delta is also
 * the signal the SP800-90B assessment of the raw samples measures - so the
 * ESDM server credits exactly what was assessed.
 *
 * A delta is carried in full, so the conditioning hash sees the whole
 * measurement instead of a truncation of it.
 *
 * The record carries no health state: only events that passed the health
 * tests are collected at all, so everything delivered here may be used and
 * credited. It does carry the number of deltas it holds - a batch handed over
 * by the flush timer is only partially filled, and the record is submitted
 * with exactly the length those deltas occupy rather than always at its full
 * size.
 */
struct esdm_ebpf_event_rec {
	__u32 type; /* esdm_ebpf_rec_event */
	__u32 cpu; /* CPU the deltas were observed on */
	__u32 reset_gen; /* reset generation they were observed under */
	__u32 events; /* valid entries in ->delta */
	__u64 delta[ESDM_EBPF_BATCH_EVENTS];
};

/* Length of a record carrying n deltas */
#define ESDM_EBPF_EVENT_REC_LEN(n)                                             \
	(__builtin_offsetof(struct esdm_ebpf_event_rec, delta) +                \
	 (n) * sizeof(__u64))

/* Header the ring buffer places in front of every record */
#define ESDM_EBPF_RB_REC_OVERHEAD 8

/*
 * Zeroization of the ring buffer (esdm_ebpf_wipe): payload of one filler record
 * and the number of them one invocation of the wipe program writes. The filler
 * is written until it has wrapped the whole ring buffer, so every byte is
 * overwritten - by the zeros of a payload or by the record header in front of
 * one. The chunk makes that affordable: an event record covers half a kilobyte,
 * so wiping four megabytes one of them at a time would cost thousands.
 */
#define ESDM_EBPF_WIPE_CHUNK 4096
#define ESDM_EBPF_WIPE_RECORDS 16

/* Name of the wipe program, by which user space locates it in the object */
#define ESDM_EBPF_WIPE_PROG_NAME "esdm_ebpf_wipe"

enum esdm_ebpf_health_test {
	esdm_ebpf_health_test_rct = 1,
	esdm_ebpf_health_test_apt = 2,
};

/*
 * Per-CPU state of the eBPF programs, in a per-CPU array map that user space
 * reads whole. The first fields are read from here rather than reported through
 * the ring buffer - the count of deposited events and the SP800-90B health
 * state - so they are seen immediately instead of behind however many events
 * are still buffered. The rest is private to the programs and only lives here
 * because user space has to know the map value's size to read it.
 */
struct esdm_ebpf_percpu_state {
	/* Read by user space */
	__u64 events; /* events this CPU put into the ring buffer */
	__u32 startup_done; /* SP800-90B startup test completed */
	__u32 health_failures; /* SP800-90B health test failures observed */
	__u32 permanent_failure; /* sticky SP800-90B permanent failure */
	__u32 health_test; /* enum esdm_ebpf_health_test of the last failure */

	__u32 in_progress; /* same-CPU nesting guard */
	__u32 reset_gen; /* observed reset generation */
	__u64 last_ts; /* predecessor of the next delta, 0 if there is none */

	/*
	 * The record this CPU is filling. It is assembled in place rather than
	 * copied into a reserved ring buffer record, which lets it be handed
	 * over at exactly the length its deltas occupy.
	 */
	struct esdm_ebpf_event_rec rec;
	__u32 pos; /* next entry in rec.delta */
	__u32 timer_inited; /* flush timer of this CPU set up? */
	__u64 last_event_ns; /* monotonic time of the last collected event */

	/* GCD (timer granularity) removal state */
	__u64 gcd_val; /* computed divisor, 0 while still learning */
	__u64 gcd_running; /* running GCD of the collected raw time stamps */
	__u32 gcd_count; /* number of samples folded into gcd_running */

	/* Stuck test state */
	__u32 rct_count; /* Repetition Count Test */
	__u64 stuck_last_time;
	__u64 stuck_last_delta;
	__u64 stuck_last_delta2;

	/* Adaptive Proportion Test state */
	__u32 apt_count;
	__u32 apt_base;
	__u32 apt_base_set;
	__u32 apt_trigger;

	/* SP800-90B startup test state */
	__u32 startup_blocks;

	__u32 reserved; /* explicit padding, always 0 */
};

/*
 * User space indexes the per-CPU values as an array, which the map layout only
 * matches when they need no padding between them.
 */
_Static_assert(sizeof(struct esdm_ebpf_percpu_state) % sizeof(__u64) == 0,
	       "per-CPU state must be a multiple of the map value alignment");

/*
 * One raw, unconditioned time delta - measurement mode only.
 *
 * The delta is formed between two events the CPU observed back to back, so
 * every record stands on its own: one the ring buffer had no room for costs a
 * sample but cannot distort the ones that arrive. Hence no sequence number to
 * reconcile - user space reads the deltas as they come.
 */
struct esdm_ebpf_raw_rec {
	__u32 type; /* esdm_ebpf_rec_raw */
	__u32 cpu; /* CPU the events were observed on */
	__u64 delta; /* time since the previous event of that CPU */
};

/*
 * Configuration of the eBPF programs. Written by user space into the
 * read-only data section of the eBPF object before it is loaded.
 */
struct esdm_ebpf_config {
	__u32 health_enabled; /* SP800-90B health tests requested */
	__u32 rct_cutoff; /* RCT intermittent failure cutoff */
	__u32 rct_cutoff_permanent; /* RCT permanent failure cutoff */
	__u32 apt_cutoff; /* APT intermittent failure cutoff */
	__u32 apt_cutoff_permanent; /* APT permanent failure cutoff */
	__u32 raw_sampling; /* emit esdm_ebpf_rec_raw records */
	__u64 flush_deadline_ns; /* idle flush deadline for partial batches */
};

/*
 * Global state of one eBPF entropy source in a single-entry array map. It only
 * carries what user space tells the programs - what they report back lives in
 * the per-CPU state above.
 */
struct esdm_ebpf_status {
	__u32 reset_gen; /* incremented by user space on reset */
};

#endif /* _ESDM_ES_EBPF_SHARED_H */
