// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: shared per-CPU event ring buffer
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/string.h>

#include "esdm_es_ring.h"

int esdm_es_ring_alloc(struct esdm_es_ring *ring)
{
	int cpu;

	for_each_possible_cpu (cpu) {
		/*
		 * The per-CPU event array is sizeable (ESDM_DATA_NUM_VALUES
		 * u64s, 32 KiB by default) and holds no DMA/hardware-visible
		 * data, so allow a vmalloc() fallback instead of demanding a
		 * physically contiguous high-order allocation.
		 */
		u64 *array = kvzalloc(ESDM_DATA_NUM_VALUES * sizeof(u64),
				      GFP_KERNEL);

		if (!array)
			goto free;

		per_cpu_ptr(ring->cpu, cpu)->array = array;
	}

	return 0;

free:
	esdm_es_ring_free(ring);
	return -ENOMEM;
}

void esdm_es_ring_free(struct esdm_es_ring *ring)
{
	int cpu;

	for_each_possible_cpu (cpu) {
		struct esdm_es_ring_cpu *rc = per_cpu_ptr(ring->cpu, cpu);

		kvfree_sensitive(rc->array, ESDM_DATA_NUM_VALUES * sizeof(u64));
		rc->array = NULL;
	}
}

void esdm_es_ring_reset(struct esdm_es_ring *ring)
{
	unsigned long flags;
	int cpu;

	raw_spin_lock_irqsave(&ring->lock, flags);
	ring->gen++;

	/*
	 * Iterate the possible mask, not the online mask: the per-CPU arrays
	 * exist for every possible CPU, and an offline one would otherwise keep
	 * its events and pointers. Reset invalidates ALL prior entropy (VM fork
	 * via the vmgenid notifier, SP800-90B failure), so pre-reset events must
	 * not survive a later CPU online and be credited as fresh.
	 *
	 * Discard by moving rp up to wp, i.e. act as a consumer: wp belongs to
	 * the lock-free producer, zeroing it (or the slots) races with a
	 * producer that then publishes its old wp + 1 and makes stale or
	 * zeroed slots count as events. What can survive is the event each
	 * producer stores concurrently with the reset, i.e. at most one per CPU
	 * of this ring. The discarded slots are not zeroized, just like
	 * consumed ones.
	 */
	for_each_possible_cpu (cpu) {
		struct esdm_es_ring_cpu *rc = per_cpu_ptr(ring->cpu, cpu);

		smp_store_release(&rc->rp, READ_ONCE(rc->wp));
		WRITE_ONCE(rc->last_timestamp, 0);
	}

	raw_spin_unlock_irqrestore(&ring->lock, flags);
}

u32 esdm_es_ring_gen(struct esdm_es_ring *ring)
{
	unsigned long flags;
	u32 gen;

	raw_spin_lock_irqsave(&ring->lock, flags);
	gen = ring->gen;
	raw_spin_unlock_irqrestore(&ring->lock, flags);

	return gen;
}

u32 esdm_es_ring_avail_events(struct esdm_es_ring *ring)
{
	u32 events = 0;
	int cpu;

	for_each_online_cpu (cpu) {
		struct esdm_es_ring_cpu *rc = per_cpu_ptr(ring->cpu, cpu);
		u32 r_pos = READ_ONCE(rc->rp);
		u32 w_pos = READ_ONCE(rc->wp);

		events += (w_pos >= r_pos) ?
				  w_pos - r_pos :
				  ESDM_DATA_NUM_VALUES - r_pos + w_pos;
	}

	return events;
}

u32 esdm_es_ring_collect(struct esdm_es_ring *ring, u32 requested_events,
			 struct list_head *seedlist)
{
	unsigned long flags;
	u32 collected_events = 0;
	int cpu;

	/* the lock orders the read pointer loads below after a prior reset */
	raw_spin_lock_irqsave(&ring->lock, flags);
	ring->rp_pending_gen = ring->gen;
	raw_spin_unlock_irqrestore(&ring->lock, flags);

	for_each_online_cpu (cpu) {
		struct esdm_es_ring_cpu *rc = per_cpu_ptr(ring->cpu, cpu);
		u32 found_events, used_events, r_pos, w_pos;

		if (collected_events >= requested_events)
			break;

		/*
		 * Acquire the producer's write pointer so the array reads below
		 * are ordered after the producer's data store that precedes its
		 * smp_store_release(wp); a plain READ_ONCE could observe the
		 * advanced wp but stale slot data on weak-memory architectures.
		 */
		w_pos = smp_load_acquire(&rc->wp);
		r_pos = smp_load_acquire(&rc->rp);

		found_events = (w_pos >= r_pos) ?
				       w_pos - r_pos :
				       ESDM_DATA_NUM_VALUES - r_pos + w_pos;

		/* Cap to maximum amount of data we can hold in array */
		found_events = min_t(u32, found_events, ESDM_DATA_NUM_VALUES);

		if (!found_events)
			continue;

		used_events = min_t(u32, requested_events - collected_events,
				    found_events);
		collected_events += used_events;

		/* can use a consecutive block as seed chunk */
		if (w_pos > r_pos) {
			drbg_string_fill(&rc->seed_data_0,
					 (u8 *)(rc->array + r_pos),
					 used_events * sizeof(u64));
			list_add_tail(&rc->seed_data_0.list, seedlist);
		} else { /* need to skip parts in the 'middle' of the array */
			/*
			 * Hash only what rp_pending accounts for, else the
			 * events past it are hashed and credited again later.
			 */
			u32 used_at_end = min_t(u32, ESDM_DATA_NUM_VALUES - r_pos,
						used_events);

			drbg_string_fill(&rc->seed_data_0,
					 (u8 *)(rc->array + r_pos),
					 used_at_end * sizeof(u64));
			list_add_tail(&rc->seed_data_0.list, seedlist);

			if (used_at_end < used_events) {
				drbg_string_fill(&rc->seed_data_1,
						 (u8 *)rc->array,
						 (used_events - used_at_end) *
							 sizeof(u64));
				list_add_tail(&rc->seed_data_1.list, seedlist);
			}
		}

		rc->rp_pending =
			(r_pos + used_events) & ESDM_DATA_NUM_VALUES_MASK;
		cpumask_set_cpu(cpu, &ring->rp_pending_mask);

		pr_debug(
			"%u %s-based events used from entropy array of CPU %d, %u %s-based events remain unused\n",
			used_events, ring->name, cpu, found_events - used_events,
			ring->name);
	}

	return collected_events;
}

bool esdm_es_ring_release(struct esdm_es_ring *ring)
{
	unsigned long flags;
	bool valid;
	int cpu;

	raw_spin_lock_irqsave(&ring->lock, flags);

	/*
	 * A reset since the collection already moved rp past the staged
	 * positions, publishing rp_pending would move it back and hand out the
	 * discarded events again.
	 */
	valid = ring->gen == ring->rp_pending_gen;
	if (valid) {
		for_each_cpu (cpu, &ring->rp_pending_mask) {
			struct esdm_es_ring_cpu *rc =
				per_cpu_ptr(ring->cpu, cpu);

			smp_store_release(&rc->rp, rc->rp_pending);
		}
	}

	raw_spin_unlock_irqrestore(&ring->lock, flags);

	cpumask_clear(&ring->rp_pending_mask);

	return valid;
}

void esdm_es_ring_discard(struct esdm_es_ring *ring)
{
	/*
	 * A CPU left in the mask would have the next release publish this
	 * collection's rp_pending for it, which moves rp backwards over a
	 * reset in between.
	 */
	cpumask_clear(&ring->rp_pending_mask);
}
