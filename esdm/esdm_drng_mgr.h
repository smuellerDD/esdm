/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef _ESDM_DRNG_H
#define _ESDM_DRNG_H

#include <sys/types.h>
#include <time.h>

#include <stdatomic.h>
#include <stdbool.h>
#include "config.h"
#include "esdm.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "mutex.h"
#include "mutex_w.h"

extern struct thread_wait_queue esdm_init_wait;
extern mutex_w_t esdm_crypto_cb_update;
extern const struct esdm_drng_cb *esdm_default_drng_cb;
extern const struct esdm_hash_cb *esdm_default_hash_cb;

/* DRNG state handle */
struct esdm_drng {
	void *drng; /* DRNG handle */
	const struct esdm_drng_cb *drng_cb; /* DRNG callbacks */
	const struct esdm_hash_cb *hash_cb; /* Hash callbacks */
	atomic_int requests; /* Number of DRNG requests */
	atomic_int requests_since_fully_seeded; /* Number DRNG requests since
						 * last fully seeded
						 */
	/* tracks number of bits this DRNG has output since beeing fully seeded for
	 * the last time. This is used to implement AIS 20/31 Version 3.0, DRG.4.10.
	 * This requirement states, that a DRG.4 should be reseeded after at max 2**17
	 * bits were returned to consumers. This cannot be checked against the number of
	 * requests without overestimating by a large margin (alway maximum request size)
	 * and therefore reseeding way too often.
	 */
	atomic_int request_bits_since_fully_seeded;

	/*
	 * Time of last seeding in whole seconds (CLOCK_MONOTONIC), atomic so
	 * the lock-free must_reseed() fast path can read it without taking
	 * drng->lock. No consumer needs sub-second resolution.
	 */
	atomic_llong last_seeded_time;

	/*
	 * These flags have no single owning lock: they are touched both under
	 * drng->lock and from lock-free fast paths (must_reseed, force_reseed,
	 * unset_fully_seeded), so they are atomic to avoid torn reads / C11 data
	 * races, mirroring the esdm_state flags in esdm_es_mgr.c.
	 */
	atomic_bool fully_seeded; /* Is DRNG fully seeded? */
	atomic_bool force_reseed; /* Force a reseed */
	atomic_bool initiated; /* Was DRNG initiated once? (used for pr drng) */

	/*
	 * A reseed is due and has been handed to the asynchronous reseed
	 * worker. Set by the generate path instead of collecting entropy
	 * inline, cleared by the worker once it has taken the DRNG on. It also
	 * serves as the "already queued" guard: the generate path keeps seeing
	 * the reseed condition on every iteration until the worker lands, and
	 * only the thread that flips this flag wakes the worker.
	 */
	atomic_bool reseed_pending;

	/* Lock write operations on DRNG state, DRNG replacement of drng_cb */
	mutex_w_t lock; /* Non-atomic DRNG operation */
};

#define ESDM_DRNG_STATE_INIT(x, d, d_cb, h_cb)                                 \
	.drng = d, .drng_cb = d_cb, .hash_cb = h_cb,                           \
	.requests = ESDM_DRNG_RESEED_THRESH, .requests_since_fully_seeded = 0, \
	.request_bits_since_fully_seeded = 0, .last_seeded_time = 0,           \
	.fully_seeded = false, .force_reseed = true, .initiated = false,       \
	.reseed_pending = false

struct esdm_drng *esdm_drng_init_instance(void);
struct esdm_drng *esdm_drng_node_instance(void);

void esdm_reset(void);
int esdm_drng_alloc_common(struct esdm_drng *drng,
			   const struct esdm_drng_cb *crypto_cb);
int esdm_drng_mgr_reinitialize(void);
int esdm_drng_mgr_initialize(void);
void esdm_drng_mgr_finalize(void);
bool esdm_get_available(void);
void esdm_drng_reset(struct esdm_drng *drng);
void esdm_drng_seed_work(void);
void esdm_try_fully_seeded(void);
void esdm_force_fully_seeded(void);
void esdm_force_fully_seeded_all_drbgs(void);

static inline uint32_t esdm_compress_osr(void)
{
	return esdm_sp80090c_compliant() ? ESDM_OVERSAMPLE_ES_BITS : 0;
}

static inline uint32_t esdm_reduce_by_osr(uint32_t entropy_bits)
{
	uint32_t osr_bits = esdm_compress_osr();

	return (entropy_bits >= osr_bits) ? (entropy_bits - osr_bits) : 0;
}

#endif /* _ESDM_DRNG_H */
