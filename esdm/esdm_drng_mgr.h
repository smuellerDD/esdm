/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include "bool.h"
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
	void *drng;				/* DRNG handle */
	const struct esdm_drng_cb *drng_cb;	/* DRNG callbacks */
	const struct esdm_hash_cb *hash_cb;	/* Hash callbacks */
	atomic_t requests;			/* Number of DRNG requests */
	atomic_t requests_since_fully_seeded;	/* Number DRNG requests since
						 * last fully seeded
						 */
	time_t last_seeded;			/* Last time it was seeded */
	bool fully_seeded;			/* Is DRNG fully seeded? */
	bool force_reseed;			/* Force a reseed */

	mutex_t hash_lock;			/* Lock hash_cb replacement */
	/* Lock write operations on DRNG state, DRNG replacement of drng_cb */
	mutex_w_t lock;				/* Non-atomic DRNG operation */
};

#define ESDM_DRNG_STATE_INIT(x, d, d_cb, h_cb) \
	.drng				= d, \
	.drng_cb			= d_cb, \
	.hash_cb			= h_cb, \
	.requests			= ATOMIC_INIT(ESDM_DRNG_RESEED_THRESH),\
	.requests_since_fully_seeded	= ATOMIC_INIT(0), \
	.last_seeded			= 0, \
	.fully_seeded			= false, \
	.force_reseed			= true, \
	.hash_lock			= MUTEX_UNLOCKED

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
void esdm_drng_inject(struct esdm_drng *drng,
		      const uint8_t *inbuf, size_t inbuflen,
		      bool fully_seeded, const char *drng_type);
void esdm_drng_seed_work(void);

static inline uint32_t esdm_compress_osr(void)
{
	return esdm_sp80090c_compliant() ?
	       ESDM_OVERSAMPLE_ES_BITS : 0;
}

static inline uint32_t esdm_reduce_by_osr(uint32_t entropy_bits)
{
	uint32_t osr_bits = esdm_compress_osr();

	return (entropy_bits >= osr_bits) ? (entropy_bits - osr_bits) : 0;
}

#endif /* _ESDM_DRNG_H */
