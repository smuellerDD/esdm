/*
 * ESDM Slow Entropy Source: Auxiliary entropy pool
 *
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "helper.h"
#include "lc_sha512.h"
#include "lc_sha3.h"
#include "mutex_w.h"
#include "ret_checkers.h"
#include "visibility.h"

/*
 * This is the auxiliary pool
 *
 * The aux pool array is aligned to 8 bytes to comfort any used 
 * cipher implementations of the hash functions used to read the pool: for some
 * accelerated implementations, we need an alignment to avoid a realignment
 * which involves memcpy(). The alignment to 8 bytes should satisfy all crypto
 * implementations.
 */
struct esdm_pool {
	/* Aux pool: digest state */
	void *aux_pool;

	/* Serialize read of entropy pool and update of aux pool */
	mutex_w_t lock;

	/* tracks entropy estimate in this pool */
	atomic_t aux_entropy_bits;

	/* Digest size of used hash */
	atomic_t digestsize;

	/* used for domain separation of inputs inserted into multiple pools */
	uint16_t idx;

	/* Aux pool initialized? */
	bool initialized;
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

	/* Consider oversampling rate due to aux pool conditioning */
	return esdm_reduce_by_osr(avail_bits);
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

/* Set the digest size of the used hash in bytes */
static void esdm_set_digestsize_pool(struct esdm_pool *pool,
				     uint32_t digestsize)
{
	uint32_t ent_bits = (uint32_t)atomic_xchg(&pool->aux_entropy_bits, 0),
		 old_digestsize = esdm_get_digestsize();

	atomic_set(&pool->digestsize, (int)digestsize);

	/*
	 * Update the write wakeup threshold which must not be larger
	 * than the digest size of the current conditioning hash.
	 */
	digestsize = esdm_reduce_by_osr(digestsize << 3);

	/*
	 * In case the new digest is larger than the old one, cap the available
	 * entropy to the old message digest used to process the existing data.
	 */
	ent_bits = min_uint32(ent_bits, old_digestsize);
	atomic_add(&pool->aux_entropy_bits, (int)ent_bits);
}

static void esdm_set_wakeup_bits(void)
{
	uint32_t digestsize = esdm_reduce_by_osr(esdm_get_digestsize());

	esdm_write_wakeup_bits = ESDM_NUM_AUX_POOLS * digestsize;
}

static void esdm_set_digestsize(uint32_t digestsize)
{
	size_t i;

	for (i = 0; i < ESDM_NUM_AUX_POOLS; ++i)
		esdm_set_digestsize_pool(&esdm_pools[i], digestsize);

	esdm_set_wakeup_bits();
}

static int esdm_aux_init_pool(struct esdm_pool *pool)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb;
	int ret = 0;

	mutex_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;
	if (hash_cb->hash_alloc)
		CKINT(hash_cb->hash_alloc(&pool->aux_pool));
	pool->initialized = false;

out:
	mutex_unlock(&drng->hash_lock);
	return ret;
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
		esdm_pools[i].aux_pool = NULL;
		atomic_set(&esdm_pools[i].aux_entropy_bits, 0);
		atomic_set(&esdm_pools[i].digestsize, ESDM_MAX_DIGESTSIZE);
		esdm_pools[i].initialized = false;
		mutex_w_init(&esdm_pools[i].lock, 0, 0);
		esdm_pools[i].idx = i;
		esdm_aux_init_pool(&esdm_pools[i]);
	}

	esdm_set_wakeup_bits();

	/*
	 * Announce that the aux pool needs entropy - after startup, the aux
	 * pool is empty and should wake up any waiters right away.
	 */
	esdm_shm_status_set_need_entropy();

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "Aux ES hash allocated\n");

	return ret;
}

static void esdm_aux_fini_pool(struct esdm_pool *pool)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb;

	mutex_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;
	if (hash_cb->hash_dealloc)
		hash_cb->hash_dealloc(pool->aux_pool);
	pool->aux_pool = NULL;
	mutex_unlock(&drng->hash_lock);
}

static void esdm_aux_fini(void)
{
	size_t i;

	for (i = 0; i < ESDM_NUM_AUX_POOLS; ++i) {
		esdm_aux_fini_pool(&esdm_pools[i]);
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "Aux ES hash deallocated\n");
}

/* Obtain the digest size provided by the used hash in bits */
DSO_PUBLIC
uint32_t esdm_get_digestsize(void)
{
	if (esdm_pools[0].initialized)
		return atomic_read_u32(&esdm_pools[0].digestsize) << 3;
	else
		return ESDM_MAX_DIGESTSIZE << 3;
}

static void esdm_pool_set_entropy_pool(struct esdm_pool *pool,
				       uint32_t entropy_bits)
{
	atomic_set(&pool->aux_entropy_bits, (int)entropy_bits);
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
		esdm_pool_set_entropy_pool(&esdm_pools[i], entropy_bits);
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

static void esdm_aux_reset(void)
{
	esdm_pool_set_entropy(0);
}

/*
 * Replace old with new hash for auxiliary pool handling
 *
 * Assumption: the caller must guarantee that the new_cb is available during the
 * entire operation (e.g. it must hold the write lock against pointer updating).
 */
static int esdm_aux_switch_hash_pool(struct esdm_pool *pool,
				     struct esdm_drng *drng,
				     const struct esdm_hash_cb *new_cb,
				     const struct esdm_hash_cb *old_cb)
{
#ifndef ESDM_CRYPTO_SWITCH
	return -EOPNOTSUPP;
#endif

	struct esdm_drng *init_drng = esdm_drng_init_instance();
	void *shash = pool->aux_pool;
	void *nhash = NULL;
	uint8_t digest[ESDM_MAX_DIGESTSIZE];
	int ret;

	if (!pool->initialized)
		return 0;

	/* We only switch if the processed DRNG is the initial DRNG. */
	if (init_drng != drng)
		return 0;

	CKINT(new_cb->hash_alloc(&nhash));

	/* Get the aux pool hash with old digest ... */
	CKINT(old_cb->hash_final(shash, digest));
	/* ... re-initialize the hash with the new digest ... */
	CKINT(new_cb->hash_init(nhash));
	/*
	 * ... feed the old hash into the new state. We may feed
	 * uninitialized memory into the new state, but this is
	 * considered no issue and even good as we have some more
	 * uncertainty here.
	 */
	CKINT(new_cb->hash_update(nhash, digest, sizeof(digest)));

	/* Switch the hash state */
	pool->aux_pool = nhash;
	nhash = NULL;
	old_cb->hash_dealloc(shash);

	esdm_set_digestsize(new_cb->hash_digestsize(pool->aux_pool));

out:
	new_cb->hash_dealloc(nhash);
	memset_secure(digest, 0, sizeof(digest));
	return ret;
}

static int esdm_aux_switch_hash(struct esdm_drng *drng, int __unused u,
				const struct esdm_hash_cb *new_cb,
				const struct esdm_hash_cb *old_cb)
{
	size_t i;
	int ret;

	if (!esdm_pools[0].initialized)
		return 0;

	for (i = 0; i < ESDM_NUM_AUX_POOLS; ++i) {
		CKINT(esdm_aux_switch_hash_pool(&esdm_pools[i], drng, new_cb,
						old_cb));
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Re-initialize aux entropy pool with hash %s\n",
		    new_cb->hash_name());

out:
	return ret;
}

/* Insert data into auxiliary pool by using the hash update function. */
static int esdm_aux_pool_insert_locked(struct esdm_pool *pool,
				       const uint8_t *inbuf, size_t inbuflen,
				       uint32_t entropy_bits)
{
	struct hash_ctx *shash = (struct hash_ctx *)pool->aux_pool;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb;
	int ret;

	/* There can never be more entropy than the size of the input buffer. */
	entropy_bits = min_uint32(entropy_bits, (uint32_t)(inbuflen << 3));

	mutex_reader_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;

	if (!pool->initialized) {
		CKINT(hash_cb->hash_init(shash));
		pool->initialized = true;
	}

	/*
	 * Domain separation between pools: insert the index of the pool to
	 * prevent any chance of identical states of the pool if the caller
	 * might insert the same data into the pool.
	 *
	 * This implies that the actual data inserted into a pool is alway
	 * idx || inbuf.
	 */
	CKINT(hash_cb->hash_update(shash, (const uint8_t *)&pool->idx,
				   sizeof(pool->idx)));

	/* Insert the actual data with or without entropy into the pool */
	CKINT(hash_cb->hash_update(shash, inbuf, inbuflen));

	/*
	 * Cap the available entropy to the hash output size compliant to
	 * SP800-90B section 3.1.5.1 table 1.
	 */
	entropy_bits += atomic_read_u32(&pool->aux_entropy_bits);
	esdm_pool_set_entropy_pool(
		pool,
		min_uint32(entropy_bits, hash_cb->hash_digestsize(shash) << 3));

out:
	mutex_reader_unlock(&drng->hash_lock);
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
			CKINT(esdm_pool_insert_aux_unlocked(&esdm_pools[i],
							    inbuf, inbuflen,
							    entropy_bits));
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

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Aux Pool %zu selected to insert data\n",
		    pool_with_max_entropy_capacity);

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
	struct hash_ctx *shash = (struct hash_ctx *)pool->aux_pool;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb;
	uint32_t collected_ent_bits, returned_ent_bits,
		unused_bits = 0, digestsize, digestsize_bits,
		requested_bits_osr;
	uint8_t aux_output[ESDM_MAX_DIGESTSIZE];

	if (!pool->initialized)
		return 0;

	mutex_reader_lock(&drng->hash_lock);

	hash_cb = drng->hash_cb;
	digestsize = hash_cb->hash_digestsize(shash);
	digestsize_bits = digestsize << 3;

	/* Cap to maximum entropy that can ever be generated with given hash */
	esdm_cap_requested(digestsize_bits, requested_bits);

	/* Ensure that no more than the size of aux_pool can be requested */
	requested_bits = min_uint32(requested_bits, (ESDM_MAX_DIGESTSIZE << 3));
	requested_bits_osr = requested_bits + esdm_compress_osr();

	/* Cap entropy with entropy counter from aux pool and the used digest */
	collected_ent_bits =
		min_uint32(digestsize_bits,
			   (uint32_t)atomic_xchg(&pool->aux_entropy_bits, 0));

	/* We collected too much entropy and put the overflow back */
	if (collected_ent_bits > requested_bits_osr) {
		/* Amount of bits we collected too much */
		unused_bits = collected_ent_bits - requested_bits_osr;
		/* Put entropy back */
		atomic_add(&pool->aux_entropy_bits, (int)unused_bits);
		/* Fix collected entropy */
		collected_ent_bits = requested_bits_osr;
	}

	/* Apply oversampling: discount requested oversampling rate */
	returned_ent_bits = esdm_reduce_by_osr(collected_ent_bits);

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits by collecting %u bits of entropy from aux pool, %u bits of entropy remaining\n",
		returned_ent_bits, collected_ent_bits, unused_bits);

	/* Get the digest for the aux pool to be returned to the caller ... */
	if (hash_cb->hash_final(shash, aux_output) ||
	    /*
	     * ... and re-initialize the aux state. Do not add the aux pool
	     * digest for backward secrecy as it will be added with the
	     * insertion of the complete seed buffer after it has been filled.
	     */
	    hash_cb->hash_init(shash)) {
		returned_ent_bits = 0;
	} else {
		/*
		 * Do not truncate the output size exactly to collected_ent_bits
		 * as the aux pool may contain data that is not credited with
		 * entropy, but we want to use them to stir the DRNG state.
		 */
		memcpy(outbuf, aux_output, requested_bits >> 3);
	}

	mutex_reader_unlock(&drng->hash_lock);
	memset_secure(aux_output, 0, digestsize);
	return returned_ent_bits;
}

static void esdm_aux_get_backtrack(struct entropy_es *eb_es,
				   uint32_t requested_bits, bool __unused u)
{
	size_t i, pool_with_max_entropy = 0;
	uint32_t max_entropy = 0;

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
		if (requested_bits + esdm_compress_osr() < max_entropy)
			break;
	}

	/* Now we have the pool that we want to extract data from. */
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Aux Pool %zu selected to obtain data\n",
		    pool_with_max_entropy);

	/* Ensure aux pool extraction and backtracking op are atomic */
	mutex_w_lock(&esdm_pools[pool_with_max_entropy].lock);

	eb_es->e_bits = esdm_aux_get_pool(&esdm_pools[pool_with_max_entropy],
					  eb_es->e, requested_bits);

	/* Mix the extracted data back into pool for backtracking resistance */
	if (esdm_aux_pool_insert_locked(&esdm_pools[pool_with_max_entropy],
					(uint8_t *)eb_es,
					sizeof(struct entropy_es), 0))
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "Backtracking resistance operation failed\n");

	mutex_w_unlock(&esdm_pools[pool_with_max_entropy].lock);
}

static uint32_t esdm_aux_max_entropy(void)
{
	return esdm_get_digestsize() * ESDM_NUM_AUX_POOLS;
}

static void esdm_aux_es_state(char *buf, size_t buflen)
{
	const struct esdm_drng *esdm_drng_init = esdm_drng_init_instance();

	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf((char *)buf, buflen,
		 " Hash for operating entropy pool: %s\n"
		 " Available entropy: %u\n"
		 " Maximum entropy: %u\n"
		 " Pools: %u\n"
		 " Write wakeup threshold: %u"
		 " Digestsize: %u",
		 esdm_drng_init->hash_cb->hash_name(),
		 esdm_aux_avail_entropy(0), esdm_aux_max_entropy(),
		 ESDM_NUM_AUX_POOLS, esdm_write_wakeup_bits,
		 esdm_get_digestsize());
}

static bool esdm_aux_active(void)
{
	return true;
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
	.switch_hash = esdm_aux_switch_hash,
};
