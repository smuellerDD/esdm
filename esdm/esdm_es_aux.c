/*
 * ESDM Slow Entropy Source: Auxiliary entropy pool
 *
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

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "build_bug_on.h"
#include "esdm.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_shm_status.h"
#include "esdm_xdrbg.h"
#include "helper.h"
#include "memset_secure.h"
#include "mutex_w.h"
#include "ret_checkers.h"
#include "selftest_kat.h"
#include "visibility.h"

/*
 * This is the auxiliary pool
 *
 * Each pool is an XDRBG-256, see esdm_xdrbg.h. The pools are told apart by
 * the additional input alpha of their XDRBG, which carries the index of the
 * pool: the data inserted into several pools never yields identical states.
 *
 * The pool aligned to 8 bytes comforts any used cipher implementation of the
 * XOF: for some accelerated implementations, we need an alignment to avoid a
 * realignment which involves memcpy(). The alignment to 8 bytes should satisfy
 * all crypto implementations.
 */

/* The additional input alpha: the name of the pool, see esdm_aux_alpha() */
#define ESDM_AUX_XDRBG_ALPHA "ESDM aux pool"
#define ESDM_AUX_XDRBG_ALPHA_LEN (sizeof(ESDM_AUX_XDRBG_ALPHA) - 1 + 2)

struct esdm_pool {
	/* XDRBG-256 of the pool, initialized for the seed by the first insert */
	struct esdm_xdrbg xdrbg;

	/* Serialize read of entropy pool and update of aux pool */
	mutex_w_t lock;

	/* tracks entropy estimate in this pool */
	atomic_int aux_entropy_bits;

	/* used for domain separation of inputs inserted into multiple pools */
	uint16_t idx;

	/* Was lock above initialized? Never reset - the lock is not destroyed */
	bool lock_initialized;
} __aligned(ESDM_KCAPI_ALIGN);

/*
 * Global array of pools, use constant number of members
 * such that compiler optimizations can take place
 * e.g. eliminate loops, when only one pool is used.
 */
static struct esdm_pool esdm_pools[ESDM_NUM_AUX_POOLS] = { 0 };

/********************************** Helper ***********************************/

/* Entropy in bits present in aux pool */
static uint32_t esdm_aux_avail_entropy_pool(struct esdm_pool *pool)
{
	/* Cap available entropy with max entropy */
	uint32_t avail_bits =
		min_uint32(esdm_get_digestsize(),
			   atomic_read_u32(&pool->aux_entropy_bits));

#ifdef ESDM_AUX_INPUT_HAS_FULL_ENTROPY
	return avail_bits;
#else
	/* Consider oversampling rate due to aux pool conditioning */
	return esdm_reduce_by_osr(avail_bits);
#endif
}

static uint32_t esdm_aux_avail_entropy(uint32_t __unused u)
{
	size_t i;
	uint32_t avail_bits = 0;

	for (i = 0; i < ESDM_NUM_AUX_POOLS; ++i)
		avail_bits += esdm_aux_avail_entropy_pool(&esdm_pools[i]);

	return avail_bits;
}

DSO_PUBLIC
uint32_t esdm_get_aux_ent(void)
{
	return esdm_aux_avail_entropy(0);
}

static void esdm_set_wakeup_bits(void)
{
#ifdef ESDM_AUX_INPUT_HAS_FULL_ENTROPY
	uint32_t digestsize = esdm_get_digestsize();
#else
	uint32_t digestsize = esdm_reduce_by_osr(esdm_get_digestsize());
#endif

	esdm_write_wakeup_bits = ESDM_NUM_AUX_POOLS * digestsize;
}

static int esdm_aux_init(void)
{
	uint16_t i;
	int ret = 0;

	/* Sanity check for at least one pool */
	BUILD_BUG_ON(ESDM_NUM_AUX_POOLS <= 0);

	/* Sanity check to not overflow the idx variable */
	BUILD_BUG_ON(ESDM_NUM_AUX_POOLS >
		     (1 << (sizeof(esdm_pools[0].idx) << 3)) - 1);

	/*
	 * Initialize the member variables of the pool as we cannot do that
	 * during compile time.
	 */
	for (i = 0; i < (uint16_t)ESDM_NUM_AUX_POOLS; ++i) {
		struct esdm_pool *pool = &esdm_pools[i];

		/*
		 * Allow this to be called multiple times: it is also the reinit
		 * callback (esdm_es_mgr_reinitialize()), where the pool still
		 * carries the previous round's XOF context and a live lock.
		 * Release the context rather than overwriting the pointer, which
		 * leaks it on every esdm_reinit(), and touch the lock only once,
		 * as re-running mutex_w_init() on an initialized mutex is
		 * undefined. The lock outlives esdm_aux_fini(), so an init after
		 * a fini takes the same path with the context already NULL.
		 */
		if (!pool->lock_initialized) {
			CKINT(mutex_w_init(&pool->lock, 0, 0));
			pool->lock_initialized = true;
		}

		/*
		 * Replace the XOF context and reset the entropy count under the
		 * pool lock as a whole: a concurrent esdm_pool_insert_aux()
		 * must neither see the context released or not yet allocated
		 * nor have the entropy it credits in between wiped out.
		 */
		mutex_w_lock(&pool->lock);
		if (pool->xdrbg.xof)
			esdm_xdrbg_zero_free(&pool->xdrbg);
		atomic_store(&pool->aux_entropy_bits, 0);
		pool->idx = i;
		ret = esdm_xdrbg_alloc(&pool->xdrbg);
		mutex_w_unlock(&pool->lock);
		CKINT(ret);
	}

	esdm_set_wakeup_bits();

	/*
	 * Announce that the aux pool needs entropy - after startup, the aux
	 * pool is empty and should wake up any waiters right away.
	 */
	esdm_shm_status_set_need_entropy();

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "Aux ES XDRBG allocated\n");

out:
	return ret;
}

static void esdm_aux_fini(void)
{
	size_t i;

	for (i = 0; i < ESDM_NUM_AUX_POOLS; ++i) {
		struct esdm_pool *pool = &esdm_pools[i];

		/* Release the context under the lock - see esdm_aux_init() */
		if (pool->lock_initialized)
			mutex_w_lock(&pool->lock);
		esdm_xdrbg_zero_free(&pool->xdrbg);
		if (pool->lock_initialized)
			mutex_w_unlock(&pool->lock);
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "Aux ES XDRBG deallocated\n");
}

/* Obtain the size of the state of the XDRBG of a pool in bits */
DSO_PUBLIC
uint32_t esdm_get_digestsize(void)
{
	return ESDM_XDRBG_V_SIZE << 3;
}

static void esdm_pool_set_entropy_pool(struct esdm_pool *pool,
				       uint32_t entropy_bits)
{
	atomic_store(&pool->aux_entropy_bits, (int)entropy_bits);
}

/*
 * Add to the entropy content of @pool, capped at @cap bits - the size of the
 * state of its XDRBG, compliant to SP800-90B section 3.1.5.1 table 1. The
 * caller holds the pool lock.
 */
static void esdm_pool_add_entropy_pool(struct esdm_pool *pool,
				       uint32_t entropy_bits, uint32_t cap)
{
	uint32_t existing = atomic_read_u32(&pool->aux_entropy_bits);

	/* Guard against overflow in the addition */
	if (entropy_bits > cap - min_uint32(existing, cap))
		entropy_bits = cap;
	else
		entropy_bits += existing;
	esdm_pool_set_entropy_pool(pool, min_uint32(entropy_bits, cap));
}

/* Set entropy content in user-space controllable aux pool */
DSO_PUBLIC
void esdm_pool_set_entropy(uint32_t entropy_bits)
{
	size_t i;

	/*
	 * this interface can only influence the first pool
	 * slot for security reasons, when entropy_bits > 0
	 *
	 * it can nevertheless reset all pools to zero
	 */
	for (i = 0; i < ESDM_NUM_AUX_POOLS; i++) {
		/*
		 * Hold the pool lock so this absolute set stays consistent with
		 * the lock-guarded read-modify-write sequences on aux_entropy_bits
		 * in esdm_aux_pool_insert_locked() and esdm_aux_get_pool(); an
		 * unlocked atomic_store() could otherwise clobber a concurrent
		 * xchg/add and corrupt the entropy accounting.
		 */
		mutex_w_lock(&esdm_pools[i].lock);
		esdm_pool_set_entropy_pool(&esdm_pools[i], entropy_bits);
		mutex_w_unlock(&esdm_pools[i].lock);
		if (entropy_bits != 0)
			break;
	}

	/*
	 * As the DRNG is newly seeded, maybe the need entropy flag can be
	 * unset?
	 */
	esdm_shm_status_set_need_entropy();

	/* notify others about newly added entropy */
	esdm_es_add_entropy();
}

/* Credit entropy to the data in the user-space controllable aux pool */
DSO_PUBLIC
void esdm_pool_add_entropy(uint32_t entropy_bits)
{
	/* As esdm_pool_set_entropy(), this interface credits the first pool */
	struct esdm_pool *pool = &esdm_pools[0];

	/* Nothing changes, so nobody is to be notified either */
	if (!entropy_bits)
		return;

	/*
	 * Read and update the count under the pool lock, so that an
	 * extraction in between does not have its bits credited once more.
	 * esdm_get_aux_ent() is no base for that: it reports the count less
	 * the oversampling of the pool, which would be lost with every credit.
	 */
	mutex_w_lock(&pool->lock);
	esdm_pool_add_entropy_pool(pool, entropy_bits, esdm_get_digestsize());
	mutex_w_unlock(&pool->lock);

	/*
	 * As the DRNG is newly seeded, maybe the need entropy flag can be
	 * unset?
	 */
	esdm_shm_status_set_need_entropy();

	/* notify others about newly added entropy */
	esdm_es_add_entropy();
}

static void esdm_aux_reset(void)
{
	esdm_pool_set_entropy(0);
}

/********************************** XDRBG *************************************/

/* The additional input alpha of the pool @idx: its name and its index */
static void esdm_aux_alpha(uint16_t idx,
			   uint8_t alpha[ESDM_AUX_XDRBG_ALPHA_LEN])
{
	BUILD_BUG_ON(ESDM_AUX_XDRBG_ALPHA_LEN > ESDM_XDRBG_MAX_ALPHA);

	memcpy(alpha, ESDM_AUX_XDRBG_ALPHA, sizeof(ESDM_AUX_XDRBG_ALPHA) - 1);
	alpha[ESDM_AUX_XDRBG_ALPHA_LEN - 2] = (uint8_t)idx;
	alpha[ESDM_AUX_XDRBG_ALPHA_LEN - 1] = (uint8_t)(idx >> 8);
}

/******************************** Insert data *********************************/

/* Insert data into auxiliary pool: the XDRBG absorbs it as seed */
static int esdm_aux_pool_insert_locked(struct esdm_pool *pool,
				       const uint8_t *inbuf, size_t inbuflen,
				       uint32_t entropy_bits)
{
	int ret = 0;

	/*
	 * There can never be more entropy than the size of the input buffer.
	 * Guard against overflow for large inbuflen values.
	 */
	if (inbuflen > (UINT32_MAX >> 3))
		entropy_bits = min_uint32(entropy_bits, UINT32_MAX);
	else
		entropy_bits =
			min_uint32(entropy_bits, (uint32_t)(inbuflen << 3));

	CKINT(esdm_xdrbg_insert(&pool->xdrbg, inbuf, inbuflen));

	/*
	 * Cap the available entropy to the size of the state of the XDRBG
	 * compliant to SP800-90B section 3.1.5.1 table 1.
	 */
	esdm_pool_add_entropy_pool(pool, entropy_bits, esdm_get_digestsize());

out:
	if (ret) {
		/*
		 * The XDRBG discarded a torn state, and with it what the pool
		 * was credited for - see esdm_aux_get_pool(). The next insert
		 * initializes the pool for the seed of a new instantiation.
		 */
		esdm_pool_set_entropy_pool(pool, 0);
	}
	return ret;
}

static int esdm_pool_insert_aux_unlocked(struct esdm_pool *pool,
					 const uint8_t *inbuf, size_t inbuflen,
					 uint32_t entropy_bits)
{
	int ret;

	mutex_w_lock(&pool->lock);
	ret = esdm_aux_pool_insert_locked(pool, inbuf, inbuflen, entropy_bits);
	mutex_w_unlock(&pool->lock);

	return ret;
}

DSO_PUBLIC
int esdm_pool_insert_aux(const uint8_t *inbuf, size_t inbuflen,
			 uint32_t entropy_bits)
{
	size_t i, pool_with_max_entropy_capacity = 0;
	uint32_t max_entropy_capacity = 0;
	int ret;

	/*
	 * Shortcut: if there is no entropy in the provided data, mix it into
	 * all pools just to stir all of them.
	 */
	if (!entropy_bits) {
		for (i = 0; i < ESDM_NUM_AUX_POOLS; ++i) {
			CKINT(esdm_pool_insert_aux_unlocked(
				&esdm_pools[i], inbuf, inbuflen, entropy_bits));
		}

		/*
		 * Return without any notifications as we did not add entropy or
		 * change the entropy level.
		 */
		return 0;
	}

	/*
	 * As of now, we don't do multi pool updates for security reasons, and
	 * thus cap entropy to single pool capacity.
	 */
	if (entropy_bits > esdm_get_digestsize())
		entropy_bits = esdm_get_digestsize();

	/*
	 * Now we want to find the pool to insert the entropy in. The applied
	 * strategy is to find the pool that has the maximum amount of capacity
	 * of yet unused entropy space or the pool that has sufficient capacity
	 * to take our entropy.
	 *
	 * This approach shall ensure that we can store as much entropy of our
	 * input block as possible.
	 *
	 * If all pools are full and do not have any capacity, the first pool
	 * will receive the data.
	 *
	 * This strategy implies that we only insert the data into one pool
	 * only. This may be considered inefficient (e.g. it may be nice to
	 * spread the entropy over multiple pools if none of the existing pools
	 * can take all entropy). But we deliberately do not apply this approach
	 * as implementing it correctly without loosing entropy is not trivial.
	 */
	for (i = 0; i < ESDM_NUM_AUX_POOLS; ++i) {
		uint32_t unused_ent =
			esdm_get_digestsize() -
			esdm_aux_avail_entropy_pool(&esdm_pools[i]);

		/* Find the pool with the maximum capacity. */
		if (max_entropy_capacity < unused_ent) {
			max_entropy_capacity = unused_ent;
			pool_with_max_entropy_capacity = i;
		}

		/* We found the pool that can already take all our entropy. */
		if (entropy_bits < unused_ent)
			break;
	}

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"Aux Pool %zu selected to insert %zu bytes of data with %u bits of entropy\n",
		pool_with_max_entropy_capacity, inbuflen, entropy_bits);

	/* Insert the buffer with the entropy into the selected entropy pool. */
	CKINT(esdm_pool_insert_aux_unlocked(
		&esdm_pools[pool_with_max_entropy_capacity], inbuf, inbuflen,
		entropy_bits));

	/*
	 * As the DRNG is newly seeded, maybe the need entropy flag can be
	 * unset?
	 */
	esdm_shm_status_set_need_entropy();

	/* notify others about newly added entropy */
	esdm_es_add_entropy();

out:
	return ret;
}

/************************* Get data from entropy pool *************************/

/*
 * Get auxiliary entropy pool and its entropy content for seed buffer.
 * Caller must hold esdm_pool.pool->lock.
 * @outbuf: buffer to store data in with size requested_bits
 * @requested_bits: Requested amount of entropy
 * @return: amount of entropy in outbuf in bits.
 */
static uint32_t esdm_aux_get_pool(struct esdm_pool *pool, uint8_t *outbuf,
				  uint32_t requested_bits)
{
	uint8_t alpha[ESDM_AUX_XDRBG_ALPHA_LEN];
	uint32_t collected_ent_bits, returned_ent_bits,
		unused_bits = 0, digestsize_bits, requested_bits_osr;

	if (!esdm_xdrbg_seed_initialized(&pool->xdrbg))
		return 0;

	digestsize_bits = esdm_get_digestsize();

	/* Cap to maximum entropy that can ever be generated with the XDRBG */
	esdm_cap_requested(digestsize_bits, requested_bits);

	/*
	 * Never more than fits into the caller's output buffer (struct
	 * entropy_es::e is ESDM_DRNG_INIT_SEED_SIZE_BYTES).
	 */
	requested_bits =
		min_uint32(requested_bits, ESDM_DRNG_INIT_SEED_SIZE_BITS);
#ifdef ESDM_AUX_INPUT_HAS_FULL_ENTROPY
	requested_bits_osr = requested_bits;
#else
	requested_bits_osr = requested_bits + esdm_compress_osr();
#endif

	/* Cap entropy with entropy counter from aux pool and the used digest */
	collected_ent_bits = min_uint32(
		digestsize_bits,
		(uint32_t)atomic_exchange(&pool->aux_entropy_bits, 0));

	/* We collected too much entropy and put the overflow back */
	if (collected_ent_bits > requested_bits_osr) {
		/* Amount of bits we collected too much */
		unused_bits = collected_ent_bits - requested_bits_osr;
		/* Put entropy back */
		atomic_fetch_add(&pool->aux_entropy_bits, (int)unused_bits);
		/* Fix collected entropy */
		collected_ent_bits = requested_bits_osr;
	}

	/* Apply oversampling: discount requested oversampling rate */
#ifdef ESDM_AUX_INPUT_HAS_FULL_ENTROPY
	returned_ent_bits = collected_ent_bits;
#else
	returned_ent_bits = esdm_reduce_by_osr(collected_ent_bits);
#endif

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits by collecting %u bits of entropy from aux pool, %u bits of entropy remaining\n",
		returned_ent_bits, collected_ent_bits, unused_bits);

	esdm_aux_alpha(pool->idx, alpha);
	if (esdm_xdrbg_extract(&pool->xdrbg, alpha, sizeof(alpha), outbuf,
			       requested_bits >> 3)) {
		/*
		 * The XDRBG failed part way and discarded its state: the next
		 * insert initializes the pool for the seed of a new
		 * instantiation rather than continuing on a torn state.
		 *
		 * That instantiation discards everything the pool has
		 * absorbed, so the entropy it was credited with is gone with it
		 * - the bits drained above as well as the overflow put back.
		 * Clear the counter (the caller holds pool->lock, so this is the
		 * only writer): giving the drained bits back would credit the
		 * next extraction with entropy of data that never reaches it,
		 * and the source would report it as available meanwhile.
		 */
		esdm_pool_set_entropy_pool(pool, 0);
		memset_secure(outbuf, 0, requested_bits >> 3);
		returned_ent_bits = 0;
	}

	/*
	 * The output is not truncated to collected_ent_bits, as the aux pool
	 * may contain data that is not credited with entropy, but we want to
	 * use them to stir the DRNG state.
	 */
	return returned_ent_bits;
}

static void esdm_aux_get_backtrack(struct entropy_es *eb_es,
				   uint32_t requested_bits, bool __unused u)
{
	size_t i, pool_with_max_entropy = 0;
	uint32_t max_entropy = 0;
	bool locked_pool = false;
	/*
	 * Evaluate the entropy threshold once up front. esdm_compress_osr()
	 * depends on the runtime-writable force_fips flag; recomputing it per
	 * iteration would let a concurrent flip change which pool satisfies the
	 * break condition mid-loop, so we could break holding one pool's lock
	 * while unlocking a different one afterwards (unlock of an unowned
	 * mutex plus a permanently leaked lock).
	 */
#ifdef ESDM_AUX_INPUT_HAS_FULL_ENTROPY
	const uint32_t entropy_threshold = requested_bits;
#else
	const uint32_t entropy_threshold = requested_bits + esdm_compress_osr();
#endif

	/*
	 * Now we want to find the pool to extract the entropy from. The applied
	 * strategy is to find the pool that has the maximum amount of entropy
	 * or the pool that has sufficient entropy to satisfy the request.
	 *
	 * Yet, we are only pulling data from one entropy pool (and do not)
	 * compress the data from multiple pools to satisfy the requested
	 * entropy. This approach currently is taken for efficiency reasons, but
	 * can easily be revised in the future.
	 *
	 * If all pools are empty and do not have any entropy, the first pool
	 * will be used for the request and let the actual extraction function
	 * handle the situation where there is no entropy.
	 */
	for (i = 0; i < ESDM_NUM_AUX_POOLS; ++i) {
		/* Ensure aux pool level lookup, extraction and backtracking op are atomic */
		mutex_w_lock(&esdm_pools[i].lock);

		uint32_t avail_ent =
			esdm_aux_avail_entropy_pool(&esdm_pools[i]);

		/* Find the maximum entropy */
		if (max_entropy < avail_ent) {
			max_entropy = avail_ent;
			pool_with_max_entropy = i;
		}

		/*
		 * We found the pool that can already provide all our entropy
		 * needs (including the discount for the OSR), take it.
		 */
		if (entropy_threshold <= max_entropy) {
			locked_pool = true;
			break;
		}

		mutex_w_unlock(&esdm_pools[i].lock);
	}

	if (!locked_pool)
		mutex_w_lock(&esdm_pools[pool_with_max_entropy].lock);

	/* Now we have the pool that we want to extract data from. */
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Aux Pool %zu selected to obtain data\n",
		    pool_with_max_entropy);

	eb_es->e_bits = esdm_aux_get_pool(&esdm_pools[pool_with_max_entropy],
					  eb_es->e, requested_bits);

	mutex_w_unlock(&esdm_pools[pool_with_max_entropy].lock);
}

static uint32_t esdm_aux_max_entropy(void)
{
#ifdef ESDM_AUX_INPUT_HAS_FULL_ENTROPY
	return esdm_get_digestsize() * ESDM_NUM_AUX_POOLS;
#else
	return esdm_reduce_by_osr(esdm_get_digestsize()) * ESDM_NUM_AUX_POOLS;
#endif
}

static void esdm_aux_es_state(char *buf, size_t buflen)
{
	snprintf((char *)buf, buflen,
		 " DRBG for operating entropy pool: XDRBG-256 with %s\n"
		 " Available entropy: %u\n"
		 " Maximum entropy: %u\n"
		 " Pools: %u\n"
		 " Write wakeup threshold: %u\n"
		 " Digestsize: %u\n",
		 esdm_default_xof_cb->xof_name(), esdm_aux_avail_entropy(0),
		 esdm_aux_max_entropy(), ESDM_NUM_AUX_POOLS,
		 esdm_write_wakeup_bits, esdm_get_digestsize());
}

static bool esdm_aux_active(void)
{
	return true;
}

/*
 * The auxiliary pool holds no noise source of its own: what it is, is the
 * conditioning component every other source is compressed into - whose
 * known-answer test is part of the self test of the crypto, see
 * esdm_xdrbg_selftest().
 */
static int esdm_aux_selftest(void)
{
	unsigned int i;

	BUILD_BUG_ON((ESDM_XDRBG_V_SIZE << 3) <
		     ESDM_DRNG_SECURITY_STRENGTH_BITS);

	for (i = 0; i < ESDM_NUM_AUX_POOLS; i++) {
		if (!esdm_pools[i].xdrbg.xof) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ES,
				    "Auxiliary ES: pool %u has no XDRBG\n", i);
			return -EFAULT;
		}
	}

	return 0;
}

struct esdm_es_cb esdm_es_aux = {
	.name = "Auxiliary",
	.init = esdm_aux_init,
	.fini = esdm_aux_fini,
	.monitor_es = NULL,
	.get_ent = esdm_aux_get_backtrack,
	.curr_entropy = esdm_aux_avail_entropy,
	.max_entropy = esdm_aux_max_entropy,
	.state = esdm_aux_es_state,
	.reset = esdm_aux_reset,
	.active = esdm_aux_active,
	.selftest = esdm_aux_selftest,
};
