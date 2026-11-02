/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM Slow Entropy Source: shared per-CPU event ring buffer
 *
 * The interrupt and scheduler entropy sources both batch timestamp-derived
 * events into a lock-free per-CPU ring buffer before the internal DRBG
 * compresses them. This holds that ring and the shared single-producer /
 * single-consumer pointer handling; entropy accounting and DRBG
 * post-processing stay in each source.
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_RING_H
#define _ESDM_ES_RING_H

#include <asm/barrier.h>
#include "esdm_drbg_string.h"
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "esdm_es_timer_common.h"

/* Per-CPU ring buffer of concatenated entropy events. */
struct esdm_es_ring_cpu {
	/* ring storage: ESDM_DATA_NUM_VALUES u64 event slots */
	u64 *array;
	/* previous timestamp for delta calculation */
	u64 last_timestamp;
	/* ring read pointer (consumer side) */
	u32 rp;
	/* ring write pointer (producer side) */
	u32 wp;
	/*
	 * Read pointer computed during list building but not yet published.
	 * Publishing rp frees the slots for the producer, so it must happen only
	 * after the DRBG consumed the referenced ring data - otherwise the
	 * producer may overwrite a region mid-hash. Extraction is serialized
	 * (single caller), so a plain field suffices; the publication itself is
	 * serialized with esdm_es_ring_reset() by the ring lock.
	 */
	u32 rp_pending;
	/* two seed buffers, in case wp < rp, one if wp > rp */
	struct drbg_string seed_data_0;
	struct drbg_string seed_data_1;
};

/*
 * One entropy-source ring. @cpu points at the source's per-CPU slots, the
 * pending mask records which CPUs contributed to the in-flight extraction and
 * @name is used only for debug output.
 *
 * Besides the consumer, esdm_es_ring_reset() moves the read pointers, from any
 * context (health failure in the hot path, reboot/PM/vmgenid notifiers). @lock
 * serializes it with esdm_es_ring_release(), and @gen, bumped by every reset,
 * tells the release whether a reset invalidated the staged extraction
 * (snapshot in @rp_pending_gen). The producers do not take the lock.
 */
struct esdm_es_ring {
	struct esdm_es_ring_cpu __percpu *cpu;
	cpumask_t rp_pending_mask;
	raw_spinlock_t lock;
	u32 gen;
	u32 rp_pending_gen;
	const char *name;
};

#define ESDM_ES_RING_INIT(_ring, _cpu, _name)				\
	{								\
		.cpu = &(_cpu),						\
		.lock = __RAW_SPIN_LOCK_UNLOCKED((_ring).lock),		\
		.name = (_name),					\
	}

/* Allocate / free the per-CPU ring storage for all possible CPUs. */
int esdm_es_ring_alloc(struct esdm_es_ring *ring);
void esdm_es_ring_free(struct esdm_es_ring *ring);

/* Discard all collected events and invalidate an in-flight extraction. */
void esdm_es_ring_reset(struct esdm_es_ring *ring);

/*
 * Reset generation of the ring. Two equal snapshots taken around a sequence of
 * extractions mean no reset happened in between.
 */
u32 esdm_es_ring_gen(struct esdm_es_ring *ring);

/* Number of unused events currently held across all online CPUs. */
u32 esdm_es_ring_avail_events(struct esdm_es_ring *ring);

/*
 * Consumer: walk online CPUs pulling up to @requested_events events into
 * @seedlist as drbg_string chunks (handling ring wrap) and stage the per-CPU
 * read pointers. Returns the number of events collected. The staged read
 * pointers must be published with esdm_es_ring_release() once the DRBG has
 * absorbed the seed list.
 */
u32 esdm_es_ring_collect(struct esdm_es_ring *ring, u32 requested_events,
			 struct list_head *seedlist);

/*
 * Publish the read pointers staged by the last esdm_es_ring_collect(). Returns
 * false if a reset happened since then: the staged pointers are dropped and
 * the caller must discard (not credit) what it derived from the collected
 * events.
 */
bool esdm_es_ring_release(struct esdm_es_ring *ring);

/*
 * Drop the read pointers staged by the last esdm_es_ring_collect() without
 * publishing them, the collected events stay in the ring. Only for a caller
 * that did not use the collected events at all.
 */
void esdm_es_ring_discard(struct esdm_es_ring *ring);

/*
 * Producer: append one event to the current CPU's ring (hot path). The caller
 * must keep it from being reentered on the same CPU, e.g. by running with
 * interrupts disabled.
 */
static inline void esdm_es_ring_add(struct esdm_es_ring *ring, u64 data)
{
	struct esdm_es_ring_cpu *rc = this_cpu_ptr(ring->cpu);
	u64 *array = READ_ONCE(rc->array);
	u32 w_pos = smp_load_acquire(&rc->wp);
	u32 r_pos = READ_ONCE(rc->rp);

	/* full? */
	if (((w_pos + 1) & ESDM_DATA_NUM_VALUES_MASK) == r_pos)
		return;

	array[w_pos] = data;
	smp_store_release(&rc->wp, (w_pos + 1) & ESDM_DATA_NUM_VALUES_MASK);
}

#endif /* _ESDM_ES_RING_H */
