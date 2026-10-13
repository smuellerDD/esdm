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

#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"

int esdm_es_buf_alloc(struct esdm_es_buf *buf, unsigned int num_blocks,
		      const char *name)
{
	if (!buf || !name)
		return -EINVAL;

	/* num_blocks must be a power of two and at least 4 (monitor_wakeup
	 * heuristic divides by 4 to schedule re-fills). */
	if (num_blocks < 4 || (num_blocks & (num_blocks - 1)) != 0)
		return -EINVAL;

	memset(buf, 0, sizeof(*buf));

	buf->blocks = calloc(num_blocks, sizeof(*buf->blocks));
	if (!buf->blocks)
		return -ENOMEM;

	buf->states = calloc(num_blocks, sizeof(*buf->states));
	if (!buf->states) {
		free(buf->blocks);
		buf->blocks = NULL;
		return -ENOMEM;
	}

	buf->num_blocks = num_blocks;
	buf->mask = num_blocks - 1;
	buf->name = name;
	atomic_store(&buf->idx, -1);
	atomic_store(&buf->monitor_initialized, false);

	return 0;
}

void esdm_es_buf_free(struct esdm_es_buf *buf)
{
	if (!buf)
		return;

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
	buf->num_blocks = 0;
	buf->mask = 0;
	atomic_store(&buf->monitor_initialized, false);
}

void esdm_es_buf_reset(struct esdm_es_buf *buf)
{
	unsigned int i;

	if (!buf || !buf->blocks)
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
	 * discard it once the fill returns.
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
	unsigned int i;

	if (!buf || !buf->blocks || !fill)
		return -EINVAL;

	/* skip first run to be responsive on RPC interface
	 * fast on ESDM startup */
	if (!atomic_load(&buf->monitor_initialized)) {
		atomic_store(&buf->monitor_initialized, true);
		return 0;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "%s ES block filling started\n", buf->name);

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
			break;
		}

		gen = atomic_load(&buf->gen);
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

		atomic_store(&buf->states[i], esdm_es_buf_filled);

		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"%s ES monitor: filled slot %u with %u bits of entropy\n",
			buf->name, i, requested_bits);
	}

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

bool esdm_es_buf_try_get(struct esdm_es_buf *buf, struct entropy_es *eb_es,
			 uint32_t requested_bits, bool credited)
{
	unsigned int slot;

	if (!buf || !buf->blocks || !eb_es)
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

	enum esdm_es_buf_state expected = esdm_es_buf_filled;

	if (!atomic_compare_exchange_strong(&buf->states[slot], &expected,
					    esdm_es_buf_reading)) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "%s ES monitor: buffer slot %u exhausted\n",
			    buf->name, slot);
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
	eb_es->e_bits = credited ? buf->blocks[slot].e_bits : 0;

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
