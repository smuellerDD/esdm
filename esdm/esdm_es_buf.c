/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "helper.h"
#include "math_helper.h"
#include "memset_secure.h"

/* Pairs with the release store of esdm_es_buf_alloc() */
static bool esdm_es_buf_published(struct esdm_es_buf *buf)
{
	return atomic_load_explicit(&buf->ready, memory_order_acquire);
}

/*
 * The age is counted in whole seconds, so a block may retire up to a second
 * early. It has to outlive the monitor interval even then, or a block would be
 * retired before the round that could serve it and the cache refilled for
 * nothing.
 */
_Static_assert(ESDM_ES_BUF_MAX_AGE == 0 ||
		       (ESDM_ES_BUF_MAX_AGE - 1) * 1000000000ULL >
			       ESDM_ES_MONITOR_INTERVAL_NS,
	       "es_buf_max_age must exceed the ES monitor interval");

/* Has the block of @slot been kept longer than the cache allows? */
static bool esdm_es_buf_expired(struct esdm_es_buf *buf, unsigned int slot,
				long long now)
{
	return buf->max_age && now - buf->fills[slot].created >=
					       (long long)buf->max_age;
}

/* Wipe the block of a slot the caller claimed, and hand the slot back */
static void esdm_es_buf_scrub(struct esdm_es_buf *buf, unsigned int slot)
{
	memset_secure(&buf->blocks[slot], 0, sizeof(buf->blocks[slot]));
	atomic_thread_fence(memory_order_seq_cst);
	atomic_store(&buf->states[slot], esdm_es_buf_empty);
}

static uint32_t esdm_es_buf_rate(struct esdm_es_buf *buf)
{
	return buf->rate ? buf->rate() : 0;
}

int esdm_es_buf_alloc(struct esdm_es_buf *buf, unsigned int num_blocks,
		      const char *name, esdm_es_buf_rate_t rate,
		      esdm_es_buf_cap_t cap)
{
	_Atomic enum esdm_es_buf_state *states;
	struct esdm_es_buf_fill_info *fills;
	struct entropy_es *blocks;

	if (!buf || !name)
		return -EINVAL;

	/* num_blocks must be a power of two and at least 4 (monitor_wakeup
	 * heuristic divides by 4 to schedule re-fills). */
	if (num_blocks < 4 || (num_blocks & (num_blocks - 1)) != 0)
		return -EINVAL;

	blocks = calloc(num_blocks, sizeof(*blocks));
	states = calloc(num_blocks, sizeof(*states));
	fills = calloc(num_blocks, sizeof(*fills));
	if (!blocks || !states || !fills) {
		free(blocks);
		free((void *)states);
		free(fills);
		return -ENOMEM;
	}

	/*
	 * Consumers may already ask an unallocated cache, e.g. when a source
	 * comes up on the monitor thread while a seeding runs. They see it
	 * only once ready is set, after everything else.
	 */
	buf->blocks = blocks;
	buf->states = states;
	buf->fills = fills;
	buf->rate = rate;
	buf->cap = cap;
	buf->num_blocks = num_blocks;
	buf->mask = num_blocks - 1;
	buf->name = name;
	buf->max_age = ESDM_ES_BUF_MAX_AGE;
	atomic_store(&buf->idx, -1);
	/* The generation the zeroed fill records of a new cache belong to */
	atomic_store(&buf->gen, 0);
	atomic_store(&buf->monitor_initialized, false);
	atomic_store_explicit(&buf->ready, true, memory_order_release);

	return 0;
}

void esdm_es_buf_free(struct esdm_es_buf *buf)
{
	if (!buf)
		return;

	atomic_store(&buf->ready, false);

	if (buf->blocks) {
		memset_secure(buf->blocks,
			      0,
			      buf->num_blocks * sizeof(*buf->blocks));
		free(buf->blocks);
		buf->blocks = NULL;
	}
	if (buf->states) {
		free((void *)buf->states);
		buf->states = NULL;
	}
	free(buf->fills);
	buf->fills = NULL;
	buf->num_blocks = 0;
	buf->mask = 0;
	atomic_store(&buf->monitor_initialized, false);
}

void esdm_es_buf_reset(struct esdm_es_buf *buf)
{
	unsigned int i;

	if (!buf || !esdm_es_buf_published(buf))
		return;

	/*
	 * Discard cached entropy without racing the lock-free consumers in
	 * esdm_es_buf_try_get(). A plain memset + plain state store would tear
	 * the state machine and could scribble over a block a consumer is
	 * mid-memcpy on. Instead cooperate with the same protocol: only a slot
	 * we can claim out of the "filled" state via CAS is ours to scrub. A
	 * slot that is "filling" (owned by the monitor) or "reading" (owned by
	 * a consumer that already won the CAS) is left to its owner, which
	 * completes the transition and scrubs the block itself. "empty" slots
	 * are already clear.
	 *
	 * The block being filled was collected before this reset just as the
	 * filled ones were, so it must not be published either: the new
	 * generation, announced before the slots are swept, has the monitor
	 * discard it once the fill returns. The monitor may be past that check
	 * already, about to mark the slot filled when this sweep has passed it
	 * by: it looks at the generation again once it has, and takes back
	 * what it published. A consumer that gets to the block in between
	 * finds it filled under an older generation than the current one and
	 * discards it in turn (esdm_es_buf_try_get()), so no block collected
	 * before a reset is served once the reset announced itself.
	 */
	atomic_fetch_add(&buf->gen, 1);

	for (i = 0; i < buf->num_blocks; i++) {
		enum esdm_es_buf_state expected = esdm_es_buf_filled;

		if (!atomic_compare_exchange_strong(&buf->states[i], &expected,
						    esdm_es_buf_reading))
			continue;

		memset_secure(&buf->blocks[i], 0, sizeof(buf->blocks[i]));

		atomic_thread_fence(memory_order_seq_cst);
		atomic_store(&buf->states[i], esdm_es_buf_empty);
	}

	atomic_store(&buf->monitor_initialized, false);
}

static int esdm_es_buf_fill_round(struct esdm_es_buf *buf,
				  uint32_t requested_bits,
				  esdm_es_buf_fill_t fill,
				  esdm_es_buf_ready_t ready, void *ctx,
				  uint64_t deadline_ns)
{
	uint32_t rate;
	unsigned int i;
	bool filled_any;

	if (!buf || !esdm_es_buf_published(buf) || !fill)
		return -EINVAL;

	/* skip first run to be responsive on RPC interface
	 * fast on ESDM startup */
	if (!atomic_load(&buf->monitor_initialized)) {
		atomic_store(&buf->monitor_initialized, true);
		return 0;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "%s ES block filling started\n", buf->name);

	/*
	 * Retire what was kept too long, so that the round below fills it
	 * anew. A slot a consumer claimed meanwhile is the consumer's, which
	 * checks the age itself.
	 */
	if (buf->max_age) {
		long long now = esdm_monotonic_now();

		for (i = 0; i < buf->num_blocks; i++) {
			enum esdm_es_buf_state filled = esdm_es_buf_filled;

			if (!esdm_es_buf_expired(buf, i, now) ||
			    !atomic_compare_exchange_strong(
				    &buf->states[i], &filled,
				    esdm_es_buf_reading))
				continue;

			esdm_es_buf_scrub(buf, i);
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
				    "%s ES monitor: retired slot %u after %u s\n",
				    buf->name, i, buf->max_age);
		}
	}

	/*
	 * Pass after pass until one finds no empty slot: the slots consumed
	 * behind a pass are refilled in this round rather than in the next, so
	 * a fill keeps up with a drain for as long as it lasts.
	 */
again:
	filled_any = false;
	for (i = 0; i < buf->num_blocks && esdm_es_mgr_running() &&
		    esdm_monotonic_now_ns() < deadline_ns;
	     i++) {
		enum esdm_es_buf_state expected = esdm_es_buf_empty;
		unsigned int gen;

		if (!atomic_compare_exchange_strong(&buf->states[i], &expected,
						    esdm_es_buf_filling))
			continue;

		/* Asked for empty slots only, as it may cost a kernel call */
		if (ready && !ready(ctx)) {
			atomic_store(&buf->states[i], esdm_es_buf_empty);
			goto out;
		}
		filled_any = true;

		gen = atomic_load(&buf->gen);
		rate = esdm_es_buf_rate(buf);
		buf->fills[i].created = esdm_monotonic_now();
		fill(&buf->blocks[i], requested_bits, ctx);

		atomic_thread_fence(memory_order_seq_cst);

		/* A reset while the fill ran discards what it collected */
		if (atomic_load(&buf->gen) != gen) {
			memset_secure(&buf->blocks[i], 0,
				      sizeof(buf->blocks[i]));
			atomic_thread_fence(memory_order_seq_cst);
			atomic_store(&buf->states[i], esdm_es_buf_empty);

			esdm_logger(
				LOGGER_DEBUG, LOGGER_C_ES,
				"%s ES monitor: discarded slot %u filled across a reset\n",
				buf->name, i);
			continue;
		}

		/*
		 * A rate raised during the fill may have applied to it. One
		 * raised and lowered again while it ran is beyond what two
		 * samples tell: the cap of esdm_es_buf_credit() takes care of
		 * that one.
		 */
		buf->fills[i].rate = max_uint32(rate, esdm_es_buf_rate(buf));
		buf->fills[i].bits = requested_bits;
		buf->fills[i].gen = gen;
		atomic_store(&buf->states[i], esdm_es_buf_filled);

		/*
		 * A reset that came after the check above swept past the slot
		 * while it was still being filled, see esdm_es_buf_reset():
		 * take the block back, unless a consumer was faster - which
		 * then discards it.
		 */
		if (atomic_load(&buf->gen) != gen) {
			enum esdm_es_buf_state filled = esdm_es_buf_filled;

			if (atomic_compare_exchange_strong(
				    &buf->states[i], &filled,
				    esdm_es_buf_reading)) {
				memset_secure(&buf->blocks[i], 0,
					      sizeof(buf->blocks[i]));
				atomic_thread_fence(memory_order_seq_cst);
				atomic_store(&buf->states[i],
					     esdm_es_buf_empty);
			}

			esdm_logger(
				LOGGER_DEBUG, LOGGER_C_ES,
				"%s ES monitor: discarded slot %u filled across a reset\n",
				buf->name, i);
			continue;
		}

		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"%s ES monitor: filled slot %u with %u bits of entropy\n",
			buf->name, i, requested_bits);
	}

	if (filled_any)
		goto again;

out:
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "%s ES block filling completed\n", buf->name);

	esdm_es_add_entropy();

	return 0;
}

int esdm_es_buf_monitor(struct esdm_es_buf *buf, uint32_t requested_bits,
			esdm_es_buf_fill_t fill, void *ctx)
{
	return esdm_es_buf_fill_round(buf, requested_bits, fill, NULL, ctx,
				      UINT64_MAX);
}

int esdm_es_buf_monitor_until(struct esdm_es_buf *buf, uint32_t requested_bits,
			      esdm_es_buf_fill_t fill, void *ctx,
			      uint64_t deadline_ns)
{
	return esdm_es_buf_fill_round(buf, requested_bits, fill, NULL, ctx,
				      deadline_ns);
}

int esdm_es_buf_monitor_ready(struct esdm_es_buf *buf, uint32_t requested_bits,
			      esdm_es_buf_fill_t fill,
			      esdm_es_buf_ready_t ready, void *ctx)
{
	return esdm_es_buf_fill_round(buf, requested_bits, fill, ready, ctx,
				      UINT64_MAX);
}

/*
 * The entropy of a block at the rate configured now: one filled at a higher
 * rate was credited for more than the source is assessed to deliver.
 *
 * The rate the fill was credited at is known only from samples before and
 * after it. A rate raised and lowered again while the fill ran escapes both,
 * and the block carries the entropy of the raised one. For a source whose
 * credit follows from its rate alone, the cap is what a block of the same
 * size is credited with now, which bounds that block too. The credit of the
 * others depends on more than the rate - what the kernel collected meanwhile,
 * say - so a cap computed from the rate would cut what they deliver in
 * general; they go without one.
 */
static uint32_t esdm_es_buf_credit(struct esdm_es_buf *buf, unsigned int slot)
{
	const struct esdm_es_buf_fill_info *fill = &buf->fills[slot];
	uint32_t rate = esdm_es_buf_rate(buf),
		 credit = buf->blocks[slot].e_bits;

	if (buf->rate && rate < fill->rate)
		credit = (uint32_t)((uint64_t)credit * rate / fill->rate);

	if (buf->cap)
		credit = min_uint32(credit, buf->cap(fill->bits));

	return credit;
}

bool esdm_es_buf_try_get(struct esdm_es_buf *buf, struct entropy_es *eb_es,
			 uint32_t requested_bits, bool credited)
{
	unsigned int slot, probe;

	if (!buf || !esdm_es_buf_published(buf) || !eb_es)
		return false;

	/*
	 * The cache is filled at esdm_get_seed_entropy_osr(false, true) bits
	 * per block by the ES monitor. Requests larger than that cannot be
	 * served from a single cached block; tell the caller to take its
	 * synchronous path instead.
	 */
	if (requested_bits > esdm_get_seed_entropy_osr(false, true))
		return false;

	/*
	 * Advance the round-robin slot index, keeping it bounded in [0, mask]
	 * at all times. A plain increment lets the signed counter grow until it
	 * overflows INT_MAX (signed integer overflow is undefined behavior),
	 * relying on wraparound semantics. As num_blocks is a power of two, the
	 * masked value is reproduced by this CAS loop without ever letting the
	 * stored counter leave the valid range. This path runs once per reseed,
	 * so the compare-and-swap retry cost is negligible.
	 */
	{
		int old_idx = atomic_load(&buf->idx);
		int new_idx;

		do {
			new_idx = (int)(((unsigned int)old_idx + 1) & buf->mask);
		} while (!atomic_compare_exchange_weak(&buf->idx, &old_idx,
						       new_idx));
		slot = (unsigned int)new_idx;
	}

	/*
	 * The first filled slot from there on: the monitor refills the slots
	 * in its own order, so the one in turn may still be empty while others
	 * are filled - and a miss sends the reseed to the synchronous
	 * collection.
	 */
	for (probe = 0; probe < buf->num_blocks; probe++) {
		enum esdm_es_buf_state expected = esdm_es_buf_filled;

		if (atomic_compare_exchange_strong(
			    &buf->states[(slot + probe) & buf->mask], &expected,
			    esdm_es_buf_reading))
			break;
	}

	if (probe == buf->num_blocks) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "%s ES monitor: buffer exhausted\n", buf->name);
		esdm_es_mgr_monitor_wakeup();
		return false;
	}
	slot = (slot + probe) & buf->mask;

	/*
	 * A block filled before a reset that announced itself in the meantime:
	 * the reset missed it while it was still being filled, and the monitor
	 * has not taken it back yet. It carries what the reset discards.
	 */
	if (buf->fills[slot].gen != atomic_load(&buf->gen)) {
		memset_secure(&buf->blocks[slot], 0, sizeof(buf->blocks[slot]));

		atomic_thread_fence(memory_order_seq_cst);
		atomic_store(&buf->states[slot], esdm_es_buf_empty);

		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "%s ES monitor: buffer slot %u predates a reset\n",
			    buf->name, slot);
		esdm_es_mgr_monitor_wakeup();
		return false;
	}

	/* Kept longer than the cache allows: retired, see esdm_es_buf.h */
	if (esdm_es_buf_expired(buf, slot, esdm_monotonic_now())) {
		esdm_es_buf_scrub(buf, slot);

		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "%s ES monitor: buffer slot %u retired after %u s\n",
			    buf->name, slot, buf->max_age);
		esdm_es_mgr_monitor_wakeup();
		return false;
	}

	/*
	 * A source that is credited fills no block without entropy unless the
	 * fill failed - the device, TPM or token returned an error, or the
	 * kernel had nothing to hand out at the time. Such a block is no hit:
	 * the synchronous path asks the source anew and gets the entropy of
	 * one that has recovered or collected since, where serving the block
	 * would credit it with nothing for as many reseeds as the cache holds
	 * failed fills. The slot is scrubbed and handed back to the monitor.
	 * The blocks of an uncredited source are served without entropy: one
	 * filled while the source was still credited - before a reinit that
	 * failed, say - would be counted with what it no longer has.
	 */
	if (credited && !buf->blocks[slot].e_bits) {
		memset_secure(&buf->blocks[slot], 0, sizeof(buf->blocks[slot]));

		atomic_thread_fence(memory_order_seq_cst);
		atomic_store(&buf->states[slot], esdm_es_buf_empty);

		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "%s ES monitor: buffer slot %u holds a failed fill\n",
			    buf->name, slot);
		esdm_es_mgr_monitor_wakeup();
		return false;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "%s ES monitor: used slot %u\n", buf->name, slot);

	memcpy(eb_es->e, buf->blocks[slot].e, ESDM_DRNG_INIT_SEED_SIZE_BYTES);
	eb_es->e_bits = credited ? esdm_es_buf_credit(buf, slot) : 0;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from %s ES cache\n",
		    eb_es->e_bits, buf->name);

	memset_secure(&buf->blocks[slot], 0, sizeof(buf->blocks[slot]));

	atomic_thread_fence(memory_order_seq_cst);
	atomic_store(&buf->states[slot], esdm_es_buf_empty);

	if (!(slot % (buf->num_blocks / 4)) && slot)
		esdm_es_mgr_monitor_wakeup();

	return true;
}
