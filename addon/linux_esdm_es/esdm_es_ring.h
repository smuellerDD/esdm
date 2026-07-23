/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM Slow Entropy Source: shared per-CPU event ring buffer
 *
 * The interrupt and scheduler entropy sources both batch timestamp-derived
 * events into a lock-free per-CPU ring buffer before the internal DRBG
 * compresses them into seed material. This abstraction holds that ring and
 * the single-producer / single-consumer pointer handling that both sources
 * share; the entropy accounting and DRBG post-processing stay in each source.
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_RING_H
#define _ESDM_ES_RING_H

#include <asm/barrier.h>
#include <crypto/drbg.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
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
	 * Publishing rp marks the slots free for the producer, so it must only
	 * happen after the DRBG consumed the referenced ring data - otherwise
	 * the producer may overwrite a region mid-hash and the event written
	 * into the "freed" slot is absorbed now and consumed again later.
	 * Extraction is serialized (single caller), so a plain field suffices.
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
 */
struct esdm_es_ring {
	struct esdm_es_ring_cpu __percpu *cpu;
	cpumask_t rp_pending_mask;
	const char *name;
};

/* Allocate / free the per-CPU ring storage for all possible CPUs. */
int esdm_es_ring_alloc(struct esdm_es_ring *ring);
void esdm_es_ring_free(struct esdm_es_ring *ring);

/* Reset all per-CPU pointers and zeroize the collected events. */
void esdm_es_ring_reset(struct esdm_es_ring *ring);

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

/* Publish the read pointers staged by the last esdm_es_ring_collect(). */
void esdm_es_ring_release(struct esdm_es_ring *ring);

/* Producer: append one event to the current CPU's ring (hot path). */
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
