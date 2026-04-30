/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 *
 * Asynchronous entropy source block cache. The producer (ES monitor) fills
 * empty slots in the background while the consumer can pull pre-filled blocks
 * from the cache without blocking on the underlying noise source.
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

#include "atomic.h"
#include "atomic_bool.h"
#include "bool.h"
#include "esdm_es_mgr_cb.h"

enum esdm_es_buf_state {
	esdm_es_buf_empty,
	esdm_es_buf_filling,
	esdm_es_buf_filled,
	esdm_es_buf_reading,
};

/*
 * Callback invoked by the monitor to populate a single block. The callback
 * must set eb_es->e_bits to 0 on failure.
 */
typedef void (*esdm_es_buf_fill_t)(struct entropy_es *eb_es,
				   uint32_t requested_bits, void *ctx);

struct esdm_es_buf {
	struct entropy_es *blocks;
	volatile enum esdm_es_buf_state *states;
	unsigned int num_blocks;
	unsigned int mask;
	atomic_t idx;
	atomic_bool_t monitor_initialized;
	const char *name;
};

/*
 * Allocate the block cache. num_blocks must be a power of two and >= 4.
 * name is used for log messages and must remain valid for the lifetime of
 * the cache.
 */
int esdm_es_buf_alloc(struct esdm_es_buf *buf, unsigned int num_blocks,
		      const char *name);

/* Release all resources and zero-out cached entropy. */
void esdm_es_buf_free(struct esdm_es_buf *buf);

/*
 * Reset all slots to empty and clear cached entropy. Allowed to be called on
 * an unallocated buf (it then is a no-op).
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

/*
 * Try to obtain a pre-filled block from the cache. On hit, eb_es is populated
 * and the function returns true. On miss (or when requested_bits exceeds what
 * a single cached block carries), the caller must fall back to its
 * synchronous path.
 */
bool esdm_es_buf_try_get(struct esdm_es_buf *buf, struct entropy_es *eb_es,
			 uint32_t requested_bits);

#endif /* _ESDM_ES_BUF_H */
