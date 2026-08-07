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

/*
 * Number of folded event timestamps collected per CPU before a batch record
 * is submitted to the ring buffer. Must be a power of two.
 */
#define ESDM_EBPF_BATCH_EVENTS 64

/* SP800-90B section 4.4.2: APT window size */
#define ESDM_EBPF_APT_WINDOW_SIZE 512
/* LSB of the time stamp processed by the APT */
#define ESDM_EBPF_APT_LSB 16
#define ESDM_EBPF_APT_WORD_MASK (ESDM_EBPF_APT_LSB - 1)

/* SP800-90B section 4.3: startup test samples */
#define ESDM_EBPF_STARTUP_SAMPLES 1024
#define ESDM_EBPF_STARTUP_BLOCKS                                               \
	((ESDM_EBPF_STARTUP_SAMPLES + ESDM_EBPF_APT_WINDOW_SIZE - 1) /         \
	 ESDM_EBPF_APT_WINDOW_SIZE)

/* Record types submitted through the ring buffer */
enum esdm_ebpf_rec_type {
	esdm_ebpf_rec_batch = 1, /* struct esdm_ebpf_batch_rec */
	esdm_ebpf_rec_health = 2, /* struct esdm_ebpf_health_rec */
	esdm_ebpf_rec_raw = 3, /* struct esdm_ebpf_raw_rec (testing only) */
};

/* Health state bits reported in esdm_ebpf_batch_rec.health */
#define ESDM_EBPF_HEALTH_STARTUP_DONE 0x00000001
#define ESDM_EBPF_HEALTH_RCT_FAILURE 0x00000002
#define ESDM_EBPF_HEALTH_APT_FAILURE 0x00000004
#define ESDM_EBPF_HEALTH_PERM_FAILURE 0x00000008

/*
 * Batch of folded event timestamps of one CPU. The 8 LSBs of each health
 * tested raw event timestamp form one byte of ->data.
 */
struct esdm_ebpf_batch_rec {
	__u32 type; /* esdm_ebpf_rec_batch */
	__u32 cpu;
	__u64 seq; /* per-CPU batch sequence number */
	__u32 events; /* valid bytes in ->data */
	__u32 health; /* ESDM_EBPF_HEALTH_* state snapshot */
	__u8 data[ESDM_EBPF_BATCH_EVENTS];
};

/* Health test events */
enum esdm_ebpf_health_event {
	esdm_ebpf_health_startup_done = 1,
	esdm_ebpf_health_intermittent_failure = 2,
	esdm_ebpf_health_permanent_failure = 3,
};

enum esdm_ebpf_health_test {
	esdm_ebpf_health_test_rct = 1,
	esdm_ebpf_health_test_apt = 2,
};

struct esdm_ebpf_health_rec {
	__u32 type; /* esdm_ebpf_rec_health */
	__u32 cpu;
	__u32 event; /* enum esdm_ebpf_health_event */
	__u32 test; /* enum esdm_ebpf_health_test */
};

/* Raw, unconditioned event timestamp - measurement mode only */
struct esdm_ebpf_raw_rec {
	__u32 type; /* esdm_ebpf_rec_raw */
	__u32 cpu;
	__u64 ts;
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
	__u32 use_perf_counter; /* read CPU cycle counter via perf */
	__u32 flush_timer_enabled; /* use bpf_timer to flush partial batches */
	__u32 raw_sampling; /* emit esdm_ebpf_rec_raw records */
	__u64 flush_deadline_ns; /* idle flush deadline for partial batches */
};

/*
 * Global state of one eBPF entropy source, shared between the eBPF program
 * and user space via a single-entry array map.
 */
struct esdm_ebpf_status {
	__u64 batches_dropped; /* ring buffer reservation failures */
	__u32 permanent_failure; /* sticky SP800-90B permanent failure */
	__u32 reset_gen; /* incremented by user space on reset */
};

#endif /* _ESDM_ES_EBPF_SHARED_H */
