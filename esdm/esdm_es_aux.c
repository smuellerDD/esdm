/*
 * ESDM Slow Entropy Source: Auxiliary entropy pool
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <stdio.h>

#include "config.h"
#include "esdm.h"
#include "esdm_crypto.h"
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
	void *aux_pool; /* Aux pool: digest state */
	atomic_t aux_entropy_bits;
	atomic_t digestsize; /* Digest size of used hash */
	bool initialized; /* Aux pool initialized? */

	/* Serialize read of entropy pool and update of aux pool */
	mutex_w_t lock;
};

static struct esdm_pool esdm_pool __aligned(ESDM_KCAPI_ALIGN) = {
	.aux_pool = NULL,
	.aux_entropy_bits = ATOMIC_INIT(0),
	.digestsize = ATOMIC_INIT(ESDM_MAX_DIGESTSIZE),
	.initialized = false,
	.lock = MUTEX_W_UNLOCKED,
};

/********************************** Helper ***********************************/

/* Entropy in bits present in aux pool */
static uint32_t esdm_aux_avail_entropy(uint32_t __unused u)
{
	/* Cap available entropy with max entropy */
	uint32_t avail_bits =
		min_uint32(esdm_get_digestsize(),
			   atomic_read_u32(&esdm_pool.aux_entropy_bits));

	/* Consider oversampling rate due to aux pool conditioning */
	return esdm_reduce_by_osr(avail_bits);
}

DSO_PUBLIC
uint32_t esdm_get_aux_ent(void)
{
	return esdm_aux_avail_entropy(0);
}

/* Set the digest size of the used hash in bytes */
static void esdm_set_digestsize(uint32_t digestsize)
{
	struct esdm_pool *pool = &esdm_pool;
	uint32_t ent_bits = (uint32_t)atomic_xchg(&pool->aux_entropy_bits, 0),
		 old_digestsize = esdm_get_digestsize();

	atomic_set(&esdm_pool.digestsize, (int)digestsize);

	/*
	 * Update the write wakeup threshold which must not be larger
	 * than the digest size of the current conditioning hash.
	 */
	digestsize = esdm_reduce_by_osr(digestsize << 3);
	esdm_write_wakeup_bits = digestsize;

	/*
	 * In case the new digest is larger than the old one, cap the available
	 * entropy to the old message digest used to process the existing data.
	 */
	ent_bits = min_uint32(ent_bits, old_digestsize);
	atomic_add(&pool->aux_entropy_bits, (int)ent_bits);
}

static void esdm_init_wakeup_bits(void)
{
	uint32_t digestsize = esdm_reduce_by_osr(esdm_get_digestsize());

	esdm_write_wakeup_bits = digestsize;
}

static int esdm_aux_init(void)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct esdm_pool *pool = &esdm_pool;
	const struct esdm_hash_cb *hash_cb;
	int ret = 0;

	mutex_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;
	if (hash_cb->hash_alloc)
		CKINT(hash_cb->hash_alloc(&pool->aux_pool));
	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "Aux ES hash allocated\n");
	pool->initialized = false;

	esdm_init_wakeup_bits();

out:
	mutex_unlock(&drng->hash_lock);
	return ret;
}

static void esdm_aux_fini(void)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct esdm_pool *pool = &esdm_pool;
	const struct esdm_hash_cb *hash_cb;

	mutex_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;
	if (hash_cb->hash_dealloc)
		hash_cb->hash_dealloc(pool->aux_pool);
	pool->aux_pool = NULL;
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Aux ES hash deallocated\n");
	mutex_unlock(&drng->hash_lock);
}

/* Obtain the digest size provided by the used hash in bits */
DSO_PUBLIC
uint32_t esdm_get_digestsize(void)
{
	return atomic_read_u32(&esdm_pool.digestsize) << 3;
}

/* Set entropy content in user-space controllable aux pool */
DSO_PUBLIC
void esdm_pool_set_entropy(uint32_t entropy_bits)
{
	atomic_set(&esdm_pool.aux_entropy_bits, (int)entropy_bits);

	/*
	 * As the DRNG is newly seeded, maybe the need entropy flag can be
	 * unset?
	 */
	esdm_shm_status_set_need_entropy();
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
static int esdm_aux_switch_hash(struct esdm_drng *drng, int __unused u,
				const struct esdm_hash_cb *new_cb,
				const struct esdm_hash_cb *old_cb)
{
#ifndef ESDM_CRYPTO_SWITCH
	return -EOPNOTSUPP;
#endif

	struct esdm_drng *init_drng = esdm_drng_init_instance();
	struct esdm_pool *pool = &esdm_pool;
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
	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "Re-initialize aux entropy pool with hash %s\n",
	       new_cb->hash_name());

out:
	new_cb->hash_dealloc(nhash);
	memset_secure(digest, 0, sizeof(digest));
	return ret;
}

/* Insert data into auxiliary pool by using the hash update function. */
static int esdm_aux_pool_insert_locked(const uint8_t *inbuf, size_t inbuflen,
				       uint32_t entropy_bits)
{
	struct esdm_pool *pool = &esdm_pool;
	struct hash_ctx *shash = (struct hash_ctx *)pool->aux_pool;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb;
	int ret;

	entropy_bits = min_uint32(entropy_bits, (uint32_t)(inbuflen << 3));

	mutex_reader_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;

	if (!pool->initialized) {
		ret = hash_cb->hash_init(shash);
		if (ret)
			goto out;
		pool->initialized = true;
	}

	ret = hash_cb->hash_update(shash, inbuf, inbuflen);
	if (ret)
		goto out;

	/*
	 * Cap the available entropy to the hash output size compliant to
	 * SP800-90B section 3.1.5.1 table 1.
	 */
	entropy_bits += atomic_read_u32(&pool->aux_entropy_bits);
	esdm_pool_set_entropy(
		min_uint32(entropy_bits, hash_cb->hash_digestsize(shash) << 3));

out:
	mutex_reader_unlock(&drng->hash_lock);
	return ret;
}

DSO_PUBLIC
int esdm_pool_insert_aux(const uint8_t *inbuf, size_t inbuflen,
			 uint32_t entropy_bits)
{
	struct esdm_pool *pool = &esdm_pool;
	int ret;

	mutex_w_lock(&pool->lock);
	ret = esdm_aux_pool_insert_locked(inbuf, inbuflen, entropy_bits);
	mutex_w_unlock(&pool->lock);

	/*
	 * As the DRNG is newly seeded, maybe the need entropy flag can be
	 * unset?
	 */
	esdm_shm_status_set_need_entropy();

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
static uint32_t esdm_aux_get_pool(uint8_t *outbuf, uint32_t requested_bits)
{
	struct esdm_pool *pool = &esdm_pool;
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

	logger(LOGGER_DEBUG, LOGGER_C_ES,
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
	struct esdm_pool *pool = &esdm_pool;

	/* Ensure aux pool extraction and backtracking op are atomic */
	mutex_w_lock(&pool->lock);

	eb_es->e_bits = esdm_aux_get_pool(eb_es->e, requested_bits);

	/* Mix the extracted data back into pool for backtracking resistance */
	if (esdm_aux_pool_insert_locked((uint8_t *)eb_es,
					sizeof(struct entropy_es), 0))
		logger(LOGGER_WARN, LOGGER_C_ES,
		       "Backtracking resistance operation failed\n");

	mutex_w_unlock(&pool->lock);
}

static void esdm_aux_es_state(char *buf, size_t buflen)
{
	const struct esdm_drng *esdm_drng_init = esdm_drng_init_instance();

	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf((char *)buf, buflen,
		 " Hash for operating entropy pool: %s\n"
		 " Available entropy: %u\n",
		 esdm_drng_init->hash_cb->hash_name(),
		 esdm_aux_avail_entropy(0));
}

static void esdm_aux_es_state_json(struct json_object *obj)
{
	const struct esdm_drng *esdm_drng_init = esdm_drng_init_instance();

	/* Assume the esdm_drng_init lock is taken by caller */
	json_object_object_add(obj, "active", json_object_new_boolean(true));
	json_object_object_add(obj, "hash", json_object_new_string(esdm_drng_init->hash_cb->hash_name()));
	json_object_object_add(obj, "avail_entropy", json_object_new_int(esdm_aux_avail_entropy(0)));
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
	.max_entropy = esdm_get_digestsize,
	.state = esdm_aux_es_state,
	.state_json = esdm_aux_es_state_json,
	.reset = esdm_aux_reset,
	.active = esdm_aux_active,
	.switch_hash = esdm_aux_switch_hash,
};
