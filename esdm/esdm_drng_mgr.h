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
	 * Number of completed seeding operations of this DRNG: it starts at
	 * zero, the initial seeding makes it one and every reseed adds one, so
	 * the number of reseeds is one less than this value.
	 */
	atomic_llong seed_generation;

	/*
	 * Time of last seeding in whole seconds (CLOCK_MONOTONIC), atomic so
	 * the lock-free must_reseed() fast path can read it without taking
	 * drng->lock. No consumer needs sub-second resolution.
	 */
	atomic_llong last_seeded_time;

	/*
	 * Wall clock time (CLOCK_REALTIME, seconds since the epoch) of the last
	 * seeding, kept next to the monotonic time above because only this one
	 * can be reported to a user.
	 */
	atomic_llong last_seeded_wtime;

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
	.request_bits_since_fully_seeded = 0, .seed_generation = 0,            \
	.last_seeded_time = 0, .last_seeded_wtime = 0, .fully_seeded = false,  \
	.force_reseed = true, .initiated = false, .reseed_pending = false

/*
 * Statistics of one DRNG instance, as handed to the callback of
 * esdm_drng_stats_foreach().
 */
struct esdm_drng_stats {
	/* Role of the DRNG: "initial", "node" or "prediction resistance" */
	const char *type;
	/* Node served by this DRNG, only set when @node_valid is true */
	uint32_t node;
	bool node_valid;
	/* Name of the DRNG implementation, NULL if it is not allocated yet */
	const char *drng_name;
	bool fully_seeded;
	bool force_reseed;
	bool reseed_pending;
	bool initiated;
	/* Generate requests left before a reseed is due, may be negative */
	int requests_until_reseed;
	/*
	 * Seconds until the reseed of this DRNG falls due, zero if it is due
	 * already.
	 */
	long long seconds_until_reseed;
	uint32_t requests_since_fully_seeded;
	uint32_t bits_since_fully_seeded;
	/* Completed seeding operations, see esdm_drng::seed_generation */
	long long seed_generation;
	/*
	 * Seconds since the last (re)seed, only set when @seeded_time_valid is
	 * true.
	 */
	long long seconds_since_reseed;
	bool seeded_time_valid;
	/*
	 * Wall clock time of the last seeding in seconds since the epoch, only
	 * set when @seeded_wtime_valid is true.
	 */
	long long seeded_wtime;
	bool seeded_wtime_valid;
};

typedef void (*esdm_drng_stats_cb_t)(const struct esdm_drng_stats *stats,
				     void *priv);

/**
 * @brief Report the statistics of every DRNG instance
 * @param [in] cb Callback receiving the statistics of one DRNG
 * @param [in] priv Opaque pointer handed to the callback
 */
void esdm_drng_stats_foreach(esdm_drng_stats_cb_t cb, void *priv);

/**
 * @brief Report the DRNGs that a system has regardless of its size
 * @param [in] cb Callback invoked once per DRNG
 * @param [in] priv Opaque pointer handed to @p cb
 */
void esdm_drng_stats_summary(esdm_drng_stats_cb_t cb, void *priv);

/**
 * @brief Report the DRNG instance serving one node
 * @param [in] node Node whose instance is reported
 * @param [in] cb Callback invoked for the instance
 * @param [in] priv Opaque pointer handed to @p cb
 * @return 0 if the instance was reported, -ENODEV if there is no such node,
 * 	-EINVAL if no callback was given
 */
int esdm_drng_stats_node(uint32_t node, esdm_drng_stats_cb_t cb, void *priv);

/**
 * @brief Report the prediction resistance DRNG instance
 * @param [in] cb Callback invoked for the instance
 * @param [in] priv Opaque pointer handed to @p cb
 */
void esdm_drng_stats_pr(esdm_drng_stats_cb_t cb, void *priv);

struct esdm_drng *esdm_drng_init_instance(void);
struct esdm_drng *esdm_drng_node_instance(void);

void esdm_reset(void);
int esdm_drng_alloc_common(struct esdm_drng *drng,
			   const struct esdm_drng_cb *crypto_cb);
int esdm_drng_mgr_reinitialize(void);
int esdm_drng_mgr_initialize(void);
void esdm_drng_mgr_finalize(void);

/**
 * @brief Is the DRNG manager shutting down?
 */
bool esdm_drng_mgr_terminating(void);

/**
 * @brief Put the asynchronous reseed worker on duty
 *
 * A reseed interval of zero seconds keeps one off duty - the requests reseed
 * themselves then, see esdm_set_reseed_max_time().
 *
 * @return true if a worker is on duty afterwards
 */
bool esdm_drng_mgr_reseed_worker_start(void);

/**
 * @brief Is the asynchronous reseed worker on duty?
 */
bool esdm_drng_mgr_reseed_worker_running(void);

/**
 * @brief Number of passes the asynchronous reseed worker completed
 */
uint64_t esdm_drng_mgr_reseed_worker_passes(void);

/**
 * @brief Seconds until the asynchronous reseed worker looks at the DRNGs again
 * @param [out] secs Seconds until the next pass, zero if it is due now, only
 * 	set when a pass is scheduled
 * @return true if a pass is scheduled, false if none is - the worker is not on
 * 	duty or has not finished its first pass yet
 */
bool esdm_drng_mgr_reseed_worker_next_pass(uint64_t *secs);

/**
 * @brief Stop the asynchronous reseed worker
 */
void esdm_drng_mgr_reseed_worker_stop(void);
bool esdm_get_available(void);
void esdm_drng_reset(struct esdm_drng *drng);

/**
 * @brief Seed the DRNGs with the entropy that arrived, unless that is running
 * @return true if a seeding was performed
 */
bool esdm_drng_seed_work_try(void);
void esdm_try_fully_seeded(void);
void esdm_force_fully_seeded(void);
void esdm_force_fully_seeded_all_drbgs(void);

static inline uint32_t esdm_compress_osr(void)
{
	return esdm_es_oversampling() ? ESDM_OVERSAMPLE_ES_BITS : 0;
}

static inline uint32_t esdm_reduce_by_osr(uint32_t entropy_bits)
{
	uint32_t osr_bits = esdm_compress_osr();

	return (entropy_bits >= osr_bits) ? (entropy_bits - osr_bits) : 0;
}

#endif /* _ESDM_DRNG_H */
