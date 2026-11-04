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

#ifndef _ESDM_ES_BUF_H
#define _ESDM_ES_BUF_H

#include <stdint.h>

#include <stdatomic.h>
#include <stdbool.h>
#include "esdm_es_mgr_cb.h"

enum esdm_es_buf_state {
	esdm_es_buf_empty,
	esdm_es_buf_filling,
	esdm_es_buf_filled,
	esdm_es_buf_reading,
};

/*
 * Callback invoked by the monitor to populate a single block. The callback
 * must set eb_es->e_bits to 0 on failure, which esdm_es_buf_try_get() takes
 * for a miss while the source is credited.
 */
typedef void (*esdm_es_buf_fill_t)(struct entropy_es *eb_es,
				   uint32_t requested_bits, void *ctx);

/*
 * Optional predicate the monitor asks before each slot it fills: false ends
 * the round with the remaining slots left empty. For a source whose fill
 * drains a pool that refills slowly, the kernel add-on ES, whose later fills
 * would otherwise each take the few bits trickled in since.
 */
typedef bool (*esdm_es_buf_ready_t)(void *ctx);

/* The configured entropy rate of the source, see esdm_es_buf_alloc() */
typedef uint32_t (*esdm_es_buf_rate_t)(void);

/*
 * The entropy the source credits a block of requested_bits with at present,
 * see esdm_es_buf_alloc()
 */
typedef uint32_t (*esdm_es_buf_cap_t)(uint32_t requested_bits);

/* What the monitor recorded about the fill of one block */
struct esdm_es_buf_fill_info {
	/* The entropy rate the block was filled at */
	uint32_t rate;
	/* The bits it was filled for */
	uint32_t bits;
	/* The reset generation (struct esdm_es_buf.gen) the fill began in */
	unsigned int gen;
	/* When the fill began, esdm_monotonic_now() seconds */
	long long created;
};

struct esdm_es_buf {
	struct entropy_es *blocks;
	_Atomic enum esdm_es_buf_state *states;
	struct esdm_es_buf_fill_info *fills;
	esdm_es_buf_rate_t rate;
	esdm_es_buf_cap_t cap;
	unsigned int num_blocks;
	unsigned int mask;
	atomic_int idx;
	atomic_bool monitor_initialized;
	/*
	 * Bumped by esdm_es_buf_reset(): a fill that began under an older
	 * generation is discarded instead of being published, or instead of
	 * being served should it have been published all the same.
	 */
	atomic_uint gen;
	/* Set by esdm_es_buf_alloc() once the cache can be used */
	atomic_bool ready;
	/*
	 * Seconds a filled block is kept, 0 for as long as it is not used -
	 * ESDM_ES_BUF_MAX_AGE as esdm_es_buf_alloc() sets it
	 */
	unsigned int max_age;
	const char *name;
};

/*
 * Allocate the block cache. num_blocks must be a power of two and >= 4.
 * name is used for log messages and must remain valid for the lifetime of
 * the cache.
 *
 * rate returns the configured entropy rate of the source, which its fills
 * credit in proportion to. A block is credited at most in proportion to the
 * rate at the time it is served, so lowering a rate takes effect on the next
 * reseed rather than once the cache is drained. NULL disables that.
 *
 * cap, for a source whose credit follows from its rate alone, returns what
 * the source credits a block of the given size with at present - its rate
 * applied to the bits, nothing while it is failing its self test. No block is
 * served with more, which covers a rate that was raised and lowered again
 * while the block was filled. NULL for a source whose credit depends on more
 * than its rate, as a cap computed from the rate would cut its credit.
 */
int esdm_es_buf_alloc(struct esdm_es_buf *buf, unsigned int num_blocks,
		      const char *name, esdm_es_buf_rate_t rate,
		      esdm_es_buf_cap_t cap);

/* Release all resources and zero-out cached entropy. */
void esdm_es_buf_free(struct esdm_es_buf *buf);

/*
 * A block is retired - wiped and its slot given back to the monitor - once it
 * is older than buf->max_age seconds, counted from the start of its fill:
 * entropy collected long before the reseed it is used for would otherwise be
 * kept in memory, and credited, for as long as nobody asks for it. The monitor
 * retires the expired blocks before each round of fills, esdm_es_buf_try_get()
 * one it is about to serve.
 *
 * Reset all slots to empty and clear cached entropy, including the block the
 * monitor is filling at the time, which it discards once done. Allowed to be
 * called on an unallocated buf (it then is a no-op).
 */
void esdm_es_buf_reset(struct esdm_es_buf *buf);

/*
 * To be invoked from the ES manager monitor. Iterates over all empty slots
 * and fills them via the supplied callback. The first call after a (re-)init
 * is skipped to keep ESDM startup responsive.
 *
 * Returns 0 on success.
 */
int esdm_es_buf_monitor(struct esdm_es_buf *buf, uint32_t requested_bits,
			esdm_es_buf_fill_t fill, void *ctx);

/* As esdm_es_buf_monitor(), consulting @ready before each fill */
int esdm_es_buf_monitor_ready(struct esdm_es_buf *buf, uint32_t requested_bits,
			      esdm_es_buf_fill_t fill,
			      esdm_es_buf_ready_t ready, void *ctx);

/*
 * As esdm_es_buf_monitor(), but no slot is begun after @deadline_ns, in
 * esdm_monotonic_now_ns() time: a slow source holds up a pass only so long.
 */
int esdm_es_buf_monitor_until(struct esdm_es_buf *buf, uint32_t requested_bits,
			      esdm_es_buf_fill_t fill, void *ctx,
			      uint64_t deadline_ns);

/*
 * Try to obtain a pre-filled block from the cache. On hit, eb_es is populated
 * and the function returns true. On miss (or when requested_bits exceeds what
 * a single cached block carries), the caller must fall back to its
 * synchronous path.
 *
 * credited tells whether the source is credited with entropy at present. If
 * it is, a block without entropy is one whose fill failed and counts as a
 * miss - the synchronous path may well serve by now. If it is not, a hit
 * carries no entropy, whatever the block was filled with.
 */
bool esdm_es_buf_try_get(struct esdm_es_buf *buf, struct entropy_es *eb_es,
			 uint32_t requested_bits, bool credited);

#endif /* _ESDM_ES_BUF_H */
