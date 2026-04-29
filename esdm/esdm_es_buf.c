/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

#include "esdm_es_buf.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
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
	atomic_set(&buf->idx, -1);
	atomic_bool_set_false(&buf->monitor_initialized);

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
	atomic_bool_set_false(&buf->monitor_initialized);
}

void esdm_es_buf_reset(struct esdm_es_buf *buf)
{
	unsigned int i;

	if (!buf || !buf->blocks)
		return;

	memset_secure(buf->blocks, 0, buf->num_blocks * sizeof(*buf->blocks));
	for (i = 0; i < buf->num_blocks; i++)
		buf->states[i] = esdm_es_buf_empty;

	atomic_bool_set_false(&buf->monitor_initialized);
}

int esdm_es_buf_monitor(struct esdm_es_buf *buf, uint32_t requested_bits,
			esdm_es_buf_fill_t fill, void *ctx)
{
	unsigned int i;

	if (!buf || !buf->blocks || !fill)
		return -EINVAL;

	/* skip first run to be responsive on RPC interface
	 * fast on ESDM startup */
	if (!atomic_bool_read(&buf->monitor_initialized)) {
		atomic_bool_set_true(&buf->monitor_initialized);
		return 0;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "%s ES block filling started\n", buf->name);

	for (i = 0; i < buf->num_blocks && esdm_es_mgr_running(); i++) {
		if (__sync_val_compare_and_swap(&buf->states[i],
						esdm_es_buf_empty,
						esdm_es_buf_filling) !=
		    esdm_es_buf_empty)
			continue;

		fill(&buf->blocks[i], requested_bits, ctx);

		__sync_synchronize();
		__sync_lock_test_and_set(&buf->states[i], esdm_es_buf_filled);

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

bool esdm_es_buf_try_get(struct esdm_es_buf *buf, struct entropy_es *eb_es)
{
	unsigned int slot;

	if (!buf || !buf->blocks || !eb_es)
		return false;

	slot = ((unsigned int)atomic_inc(&buf->idx)) & buf->mask;

	if (__sync_val_compare_and_swap(&buf->states[slot],
					esdm_es_buf_filled,
					esdm_es_buf_reading) !=
	    esdm_es_buf_filled) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "%s ES monitor: buffer slot %u exhausted\n",
			    buf->name, slot);
		esdm_es_mgr_monitor_wakeup();
		return false;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "%s ES monitor: used slot %u\n", buf->name, slot);

	memcpy(eb_es->e, buf->blocks[slot].e, ESDM_DRNG_INIT_SEED_SIZE_BYTES);
	eb_es->e_bits = buf->blocks[slot].e_bits;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from %s ES cache\n",
		    eb_es->e_bits, buf->name);

	memset_secure(&buf->blocks[slot], 0, sizeof(buf->blocks[slot]));

	__sync_synchronize();
	__sync_lock_test_and_set(&buf->states[slot], esdm_es_buf_empty);

	if (!(slot % (buf->num_blocks / 4)) && slot)
		esdm_es_mgr_monitor_wakeup();

	return true;
}
