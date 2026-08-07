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

/*
 * Tests for esdm/esdm_es_buf.c - the per-entropy-source block cache that the
 * ES monitor fills asynchronously and a reseed drains.
 *
 * The cache is a lock-free state machine: every slot moves empty -> filling ->
 * filled -> reading -> empty, each transition a compare-and-exchange deciding
 * who owns the block. The tests drive it directly and assert on the slot
 * states, so a transition that stops being exclusive - two owners, or a slot
 * drained twice - is caught rather than left to a rare production race.
 *
 * esdm_es_buf.c is compiled into this test along with stubs for the ES manager
 * entry points, which is what makes the cases below reachable: the monitor's
 * cooperative abort needs a manager that stops running mid-loop, and the wakeup
 * accounting has to be observed rather than inferred.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_test.h"
#include "esdm_definitions.h"
#include "esdm_es_buf.h"

/******************************************************************************
 * Stubs for the ES manager entry points esdm_es_buf.c calls
 ******************************************************************************/

static bool stub_running = true;
static unsigned int stub_running_budget; /* 0 = unlimited */
static unsigned int stub_running_calls;
static unsigned int stub_wakeups;
static unsigned int stub_add_entropy;

bool esdm_es_mgr_running(void);
void esdm_es_mgr_monitor_wakeup(void);
void esdm_es_add_entropy(void);
uint32_t esdm_get_digestsize(void);
int esdm_es_oversampling(void);

bool esdm_es_mgr_running(void)
{
	stub_running_calls++;
	if (stub_running_budget && stub_running_calls > stub_running_budget)
		return false;
	return stub_running;
}

void esdm_es_mgr_monitor_wakeup(void)
{
	stub_wakeups++;
}

void esdm_es_add_entropy(void)
{
	stub_add_entropy++;
}

uint32_t esdm_get_digestsize(void)
{
	return ESDM_FULL_SEED_ENTROPY_BITS;
}

int esdm_es_oversampling(void)
{
	return 0;
}

/* The number of bits a single cached block is filled with */
#define BLOCK_BITS ESDM_FULL_SEED_ENTROPY_BITS

static void stubs_reset(void)
{
	stub_running = true;
	stub_running_budget = 0;
	stub_running_calls = 0;
	stub_wakeups = 0;
	stub_add_entropy = 0;
}

/******************************************************************************
 * Fill callback recording what the monitor asked for
 ******************************************************************************/

struct fill_record {
	unsigned int calls;
	uint32_t last_requested_bits;
	void *last_ctx;
	uint8_t next_marker;
};

static void fill_cb(struct entropy_es *eb_es, uint32_t requested_bits,
		    void *ctx)
{
	struct fill_record *rec = ctx;

	rec->calls++;
	rec->last_requested_bits = requested_bits;
	rec->last_ctx = ctx;

	/* Stamp each block so its identity survives into the consumer */
	memset(eb_es->e, rec->next_marker, sizeof(eb_es->e));
	eb_es->e_bits = requested_bits;
	rec->next_marker++;
}

static void fill_cb_failing(struct entropy_es *eb_es, uint32_t requested_bits,
			    void *ctx)
{
	struct fill_record *rec = ctx;

	(void)requested_bits;
	rec->calls++;

	/* The contract for a failed fill: no entropy claimed */
	memset(eb_es->e, 0, sizeof(eb_es->e));
	eb_es->e_bits = 0;
}

static bool block_is_zero(const struct entropy_es *block)
{
	static const uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES] = { 0 };

	return block->e_bits == 0 && !memcmp(block->e, zero, sizeof(zero));
}

static unsigned int count_state(const struct esdm_es_buf *buf,
				enum esdm_es_buf_state state)
{
	unsigned int i, count = 0;

	for (i = 0; i < buf->num_blocks; i++) {
		if (atomic_load(&buf->states[i]) == state)
			count++;
	}

	return count;
}

/******************************************************************************
 * Allocation
 ******************************************************************************/

static void test_alloc_validation(void)
{
	struct esdm_es_buf buf;
	static const unsigned int bad[] = { 0, 1, 2, 3, 5, 6, 7, 9, 12, 100 };
	unsigned int i;

	CHECK_EQ(esdm_es_buf_alloc(NULL, 8, "test"), -EINVAL);

	memset(&buf, 0, sizeof(buf));
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, NULL), -EINVAL);

	/*
	 * The block count has to be a power of two of at least four: the round
	 * robin index is masked rather than divided, and the monitor wakeup
	 * heuristic divides it by four.
	 */
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		memset(&buf, 0, sizeof(buf));
		if (esdm_es_buf_alloc(&buf, bad[i], "test") != -EINVAL) {
			CHECK(0, "a block count of %u was accepted", bad[i]);
			esdm_es_buf_free(&buf);
		}
	}
}

static void test_alloc_state(void)
{
	static const unsigned int good[] = { 4, 8, 16, 64, 128 };
	unsigned int i;

	for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
		struct esdm_es_buf buf;
		unsigned int j;

		memset(&buf, 0xff, sizeof(buf));
		CHECK_EQ(esdm_es_buf_alloc(&buf, good[i], "test"), 0);

		CHECK_EQ(buf.num_blocks, good[i]);
		CHECK_EQ(buf.mask, good[i] - 1);
		CHECK_STR_EQ(buf.name, "test");
		CHECK(buf.blocks != NULL, "no block array was allocated");
		CHECK(buf.states != NULL, "no state array was allocated");

		/* The first index handed out has to be slot 0 */
		CHECK_EQ(atomic_load(&buf.idx), -1);
		CHECK(!atomic_load(&buf.monitor_initialized),
		      "the cache starts out as an initialized monitor");

		/* Every slot starts empty and zeroed */
		for (j = 0; j < buf.num_blocks; j++) {
			if (atomic_load(&buf.states[j]) != esdm_es_buf_empty) {
				CHECK(0, "slot %u does not start out empty", j);
				break;
			}
			if (!block_is_zero(&buf.blocks[j])) {
				CHECK(0, "slot %u does not start out zeroed", j);
				break;
			}
		}

		esdm_es_buf_free(&buf);
	}
}

static void test_free(void)
{
	struct esdm_es_buf buf;

	/* Freeing nothing is allowed */
	esdm_es_buf_free(NULL);

	memset(&buf, 0, sizeof(buf));
	esdm_es_buf_free(&buf);

	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	esdm_es_buf_free(&buf);

	CHECK(buf.blocks == NULL, "the block array was not released");
	CHECK(buf.states == NULL, "the state array was not released");
	CHECK_EQ(buf.num_blocks, 0);
	CHECK_EQ(buf.mask, 0);

	/* And a second free must not touch the pointers again */
	esdm_es_buf_free(&buf);
	CHECK(buf.blocks == NULL, "a repeated free resurrected the cache");

	/* A released cache serves nothing and accepts no monitor run */
	CHECK(!esdm_es_buf_try_get(&buf, NULL, BLOCK_BITS),
	      "a released cache handed out a block");
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, NULL), -EINVAL);
	esdm_es_buf_reset(&buf);
}

/******************************************************************************
 * Monitor
 ******************************************************************************/

static void test_monitor_validation(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };

	CHECK_EQ(esdm_es_buf_monitor(NULL, BLOCK_BITS, fill_cb, &rec), -EINVAL);

	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, NULL, &rec), -EINVAL);
	CHECK_EQ(rec.calls, 0);
	esdm_es_buf_free(&buf);
}

static void test_monitor_first_run_skipped(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);

	/*
	 * The first monitor run after a (re-)initialization is skipped so the
	 * ESDM becomes responsive quickly instead of spending the first round
	 * filling a cache nobody is waiting for yet.
	 */
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, 0);
	CHECK_EQ(stub_add_entropy, 0);
	CHECK(atomic_load(&buf.monitor_initialized),
	      "the skipped run did not mark the monitor as initialized");
	CHECK_EQ(count_state(&buf, esdm_es_buf_empty), buf.num_blocks);

	/* The run after that does the work */
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, buf.num_blocks);
	CHECK_EQ(stub_add_entropy, 1);

	esdm_es_buf_free(&buf);
}

static void test_monitor_fills_all_slots(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	unsigned int i;

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, buf.num_blocks);
	CHECK_EQ(rec.last_requested_bits, BLOCK_BITS);
	CHECK(rec.last_ctx == &rec, "the fill callback got the wrong context");
	CHECK_EQ(count_state(&buf, esdm_es_buf_filled), buf.num_blocks);

	/* Each slot carries what the callback wrote into it */
	for (i = 0; i < buf.num_blocks; i++) {
		uint8_t expect[ESDM_DRNG_INIT_SEED_SIZE_BYTES];

		memset(expect, (uint8_t)(i + 1), sizeof(expect));
		if (memcmp(buf.blocks[i].e, expect, sizeof(expect))) {
			CHECK(0, "slot %u holds the wrong block", i);
			break;
		}
		CHECK_EQ(buf.blocks[i].e_bits, BLOCK_BITS);
	}

	/* A full cache gives the next monitor run nothing to do */
	rec.calls = 0;
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, 0);
	CHECK_EQ(count_state(&buf, esdm_es_buf_filled), buf.num_blocks);

	/* but the aux pool is told about the cache either way */
	CHECK_EQ(stub_add_entropy, 2);

	esdm_es_buf_free(&buf);
}

static void test_monitor_refills_drained_slots(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	struct entropy_es out;
	unsigned int i;

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	/* Drain three slots ... */
	for (i = 0; i < 3; i++)
		CHECK(esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
		      "draining slot %u failed", i);
	CHECK_EQ(count_state(&buf, esdm_es_buf_empty), 3);

	/* ... and exactly those are refilled */
	rec.calls = 0;
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, 3);
	CHECK_EQ(count_state(&buf, esdm_es_buf_filled), buf.num_blocks);

	esdm_es_buf_free(&buf);
}

static void test_monitor_aborts_on_shutdown(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	/* An ES manager that is not running at all fills nothing */
	stub_running = false;
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, 0);
	CHECK_EQ(count_state(&buf, esdm_es_buf_empty), buf.num_blocks);

	/*
	 * One that stops while the cache is being filled leaves the remaining
	 * slots empty rather than finishing the round - the loop rechecks
	 * before every slot so a shutdown is not delayed by a full refill.
	 */
	stub_running = true;
	stub_running_calls = 0;
	stub_running_budget = 3;
	rec.calls = 0;
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, 3);
	CHECK_EQ(count_state(&buf, esdm_es_buf_filled), 3);
	CHECK_EQ(count_state(&buf, esdm_es_buf_empty), buf.num_blocks - 3);

	esdm_es_buf_free(&buf);
}

static void test_monitor_skips_busy_slots(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	/*
	 * Slots owned by somebody else are not touched: a slot another thread
	 * is filling or reading belongs to that thread until it publishes the
	 * next state.
	 */
	atomic_store(&buf.states[2], esdm_es_buf_filling);
	atomic_store(&buf.states[5], esdm_es_buf_reading);

	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, buf.num_blocks - 2);
	CHECK_EQ(atomic_load(&buf.states[2]), esdm_es_buf_filling);
	CHECK_EQ(atomic_load(&buf.states[5]), esdm_es_buf_reading);
	CHECK(block_is_zero(&buf.blocks[2]),
	      "a slot owned by another filler was written to");
	CHECK(block_is_zero(&buf.blocks[5]),
	      "a slot owned by a reader was written to");

	/* Put them back so the cache can be released cleanly */
	atomic_store(&buf.states[2], esdm_es_buf_empty);
	atomic_store(&buf.states[5], esdm_es_buf_empty);
	esdm_es_buf_free(&buf);
}

/******************************************************************************
 * Consumption
 ******************************************************************************/

static void test_try_get_validation(void)
{
	struct esdm_es_buf buf;
	struct entropy_es out;

	stubs_reset();
	CHECK(!esdm_es_buf_try_get(NULL, &out, BLOCK_BITS),
	      "a missing cache handed out a block");

	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK(!esdm_es_buf_try_get(&buf, NULL, BLOCK_BITS),
	      "a missing destination was accepted");

	/*
	 * Nothing of this reached the state machine: an argument that is
	 * rejected must not consume a round robin slot or wake the monitor.
	 */
	CHECK_EQ(atomic_load(&buf.idx), -1);
	CHECK_EQ(stub_wakeups, 0);

	esdm_es_buf_free(&buf);
}

static void test_try_get_oversized_request(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	struct entropy_es out;

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	/*
	 * A request larger than one cached block carries cannot be served from
	 * the cache. The caller has to fall back to its synchronous path, and
	 * no block may be spent on the attempt.
	 */
	CHECK(!esdm_es_buf_try_get(&buf, &out, BLOCK_BITS + 1),
	      "an oversized request was served from the cache");
	CHECK_EQ(count_state(&buf, esdm_es_buf_filled), buf.num_blocks);
	CHECK_EQ(atomic_load(&buf.idx), -1);
	CHECK_EQ(stub_wakeups, 0);

	/* Exactly the block size is still served */
	CHECK(esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
	      "a request of exactly the block size was rejected");

	esdm_es_buf_free(&buf);
}

static void test_try_get_empty_cache(void)
{
	struct esdm_es_buf buf;
	struct entropy_es out;

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);

	/* A miss reports the miss and asks the monitor for a refill */
	CHECK(!esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
	      "an empty cache handed out a block");
	CHECK_EQ(stub_wakeups, 1);
	CHECK_EQ(atomic_load(&buf.idx), 0);

	CHECK(!esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
	      "an empty cache handed out a block");
	CHECK_EQ(stub_wakeups, 2);
	CHECK_EQ(atomic_load(&buf.idx), 1);

	esdm_es_buf_free(&buf);
}

static void test_try_get_round_robin(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	struct entropy_es out;
	unsigned int i;

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	/*
	 * The slots are handed out in order starting at 0, each exactly once,
	 * and the block that comes out is the one that slot was filled with.
	 */
	for (i = 0; i < buf.num_blocks; i++) {
		uint8_t expect[ESDM_DRNG_INIT_SEED_SIZE_BYTES];

		memset(&out, 0, sizeof(out));
		if (!esdm_es_buf_try_get(&buf, &out, BLOCK_BITS)) {
			CHECK(0, "the cache ran dry after %u of %u slots", i,
			      buf.num_blocks);
			break;
		}

		memset(expect, (uint8_t)(i + 1), sizeof(expect));
		if (memcmp(out.e, expect, sizeof(expect))) {
			CHECK(0, "block %u was served out of order", i);
			break;
		}
		CHECK_EQ(out.e_bits, BLOCK_BITS);

		/* The slot is scrubbed and released as it is handed over */
		CHECK_EQ(atomic_load(&buf.states[i]), esdm_es_buf_empty);
		CHECK(block_is_zero(&buf.blocks[i]),
		      "slot %u was not scrubbed after it was consumed", i);
		CHECK_EQ(atomic_load(&buf.idx), (int)i);
	}

	/* The cache is empty now and the index wraps back to the start */
	CHECK(!esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
	      "the drained cache still handed out a block");
	CHECK_EQ(atomic_load(&buf.idx), 0);

	esdm_es_buf_free(&buf);
}

static void test_try_get_wakeup_heuristic(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	struct entropy_es out;
	unsigned int i;

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	/*
	 * The monitor is nudged every quarter of the cache so a refill is
	 * already under way before the last block is spent - and not on the
	 * very first slot, which would wake it on every single wrap around.
	 */
	for (i = 0; i < buf.num_blocks; i++) {
		unsigned int before = stub_wakeups;
		bool expect_wakeup = i && !(i % (buf.num_blocks / 4));

		CHECK(esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
		      "draining slot %u failed", i);
		CHECK(stub_wakeups == before + (expect_wakeup ? 1u : 0u),
		      "slot %u: %s a monitor wakeup", i,
		      expect_wakeup ? "expected" : "did not expect");
	}

	CHECK_EQ(stub_wakeups, 3);

	esdm_es_buf_free(&buf);
}

static void test_try_get_skips_busy_slot(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	struct entropy_es out;

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	/* Slot 0 is being refilled by the monitor right now */
	atomic_store(&buf.states[0], esdm_es_buf_filling);

	/*
	 * The consumer does not wait for it and does not steal it either: it
	 * reports a miss for this round and asks for a refill.
	 */
	CHECK(!esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
	      "a slot owned by the monitor was consumed");
	CHECK_EQ(atomic_load(&buf.states[0]), esdm_es_buf_filling);
	CHECK_EQ(stub_wakeups, 1);

	/* The next round moves on to the following slot, which is available */
	CHECK(esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
	      "the following slot was not served");
	CHECK_EQ(atomic_load(&buf.states[1]), esdm_es_buf_empty);

	atomic_store(&buf.states[0], esdm_es_buf_empty);
	esdm_es_buf_free(&buf);
}

static void test_failed_fill_is_served(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	struct entropy_es out;

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb_failing, &rec),
		 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb_failing, &rec),
		 0);
	CHECK_EQ(rec.calls, buf.num_blocks);

	/*
	 * A source that could not deliver reports zero bits. The block is still
	 * cached and handed out - the caller sees the zero entropy estimate and
	 * decides what to do, rather than the cache silently retrying forever.
	 */
	memset(&out, 0xff, sizeof(out));
	CHECK(esdm_es_buf_try_get(&buf, &out, BLOCK_BITS),
	      "a block filled with zero entropy was withheld");
	CHECK_EQ(out.e_bits, 0);

	esdm_es_buf_free(&buf);
}

/******************************************************************************
 * Reset
 ******************************************************************************/

static void test_reset(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	unsigned int i;

	stubs_reset();

	/* A reset of nothing is allowed */
	esdm_es_buf_reset(NULL);
	memset(&buf, 0, sizeof(buf));
	esdm_es_buf_reset(&buf);

	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(count_state(&buf, esdm_es_buf_filled), buf.num_blocks);

	esdm_es_buf_reset(&buf);

	/* Every cached block is discarded and scrubbed */
	CHECK_EQ(count_state(&buf, esdm_es_buf_empty), buf.num_blocks);
	for (i = 0; i < buf.num_blocks; i++) {
		if (!block_is_zero(&buf.blocks[i])) {
			CHECK(0, "slot %u still holds entropy after the reset",
			      i);
			break;
		}
	}

	/*
	 * The reset also re-arms the first-run skip, so the monitor run right
	 * after it stays out of the way just like after an allocation.
	 */
	CHECK(!atomic_load(&buf.monitor_initialized),
	      "the reset did not re-arm the first run skip");
	rec.calls = 0;
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(rec.calls, 0);

	esdm_es_buf_free(&buf);
}

static void test_reset_leaves_owned_slots(void)
{
	struct esdm_es_buf buf;
	struct fill_record rec = { 0, 0, NULL, 1 };
	uint8_t expect[ESDM_DRNG_INIT_SEED_SIZE_BYTES];

	stubs_reset();
	CHECK_EQ(esdm_es_buf_alloc(&buf, 8, "test"), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);
	CHECK_EQ(esdm_es_buf_monitor(&buf, BLOCK_BITS, fill_cb, &rec), 0);

	/*
	 * A slot another thread already owns is left to that thread. Scrubbing
	 * it here would race the memcpy a consumer is in the middle of, and
	 * would tear the state machine the owner is about to advance.
	 */
	atomic_store(&buf.states[3], esdm_es_buf_reading);
	atomic_store(&buf.states[6], esdm_es_buf_filling);
	memset(expect, 4, sizeof(expect)); /* slot 3 was stamped with 3 + 1 */

	esdm_es_buf_reset(&buf);

	CHECK_EQ(atomic_load(&buf.states[3]), esdm_es_buf_reading);
	CHECK_EQ(atomic_load(&buf.states[6]), esdm_es_buf_filling);
	CHECK_MEM_EQ(buf.blocks[3].e, expect, sizeof(expect));
	CHECK_EQ(count_state(&buf, esdm_es_buf_empty), buf.num_blocks - 2);

	atomic_store(&buf.states[3], esdm_es_buf_empty);
	atomic_store(&buf.states[6], esdm_es_buf_empty);
	esdm_es_buf_free(&buf);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_alloc_validation();
	test_alloc_state();
	test_free();

	test_monitor_validation();
	test_monitor_first_run_skipped();
	test_monitor_fills_all_slots();
	test_monitor_refills_drained_slots();
	test_monitor_aborts_on_shutdown();
	test_monitor_skips_busy_slots();

	test_try_get_validation();
	test_try_get_oversized_request();
	test_try_get_empty_cache();
	test_try_get_round_robin();
	test_try_get_wakeup_heuristic();
	test_try_get_skips_busy_slot();
	test_failed_fill_is_served();

	test_reset();
	test_reset_leaves_owned_slots();

	return common_test_result("esdm_es_buf");
}
