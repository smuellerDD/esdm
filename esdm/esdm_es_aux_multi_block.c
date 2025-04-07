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

#include <errno.h>
#include <stdint.h>
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
#include <stdlib.h>
#include <assert.h>

#ifndef ESDM_HAS_AUX_MULTI_BLOCK
#error "Config error, multi block auxiliary source disabled and multi block code compiled in!"
#endif

/*
 * CAUTION:
 *
 * THE CODE OF THIS SOURCE NEEDS FURTHER ANALYSIS AND IS
 * DISABLED BY DEFAULT. ONLY ENABLE AFTER TALKING TO A
 * CRYPTOGRAPHIC AUTHORITY AND BEEING ABSOLUTELY SURE,
 * WHAT YOU ARE DOING!!!
 */

/*
 * Design Goals:
 * -------------
 * + do never store raw entropy directly and output it buffered (easy to get wrong and do duplicate outputs)
 * + spread inserted entropy fast into the whole pool via leftover hashing (via mix_pool())
 * + provide backtracking resistance after every output and input (via mix_pool())
 * + Only use cryptographic hashing as primitive in order to be able to argument with well established left-over hashing and formulas from AIS 20/31
 * + Mutate complete state with every operation (insert, output) as defense in depth against duplicate outputs
 *
 *
 * Aux. Pool Data Structure:
 * -------------------------
 *
 * Pool_Block[N * Message-Digest Blocks] = Pool -- used block data structure
 * H -- used hash function
 * entropy_pool -- entropy counter in pool
 *
 * +---------+---------+---------+---------+
 * + Block 0 + Block 1 +   ...   + Bl. N-1 +
 * +---------+---------+---------+---------+
 *
 *
 * Insert into blocks(input, entropy):
 * -----------------------------------
 * For block in input:
 *     Pool_Block[update_idx]' <- H(DOMAIN_SEP_INSERT || Current Pool || block)
 *     update_idx' <- (update_idx + 1) MOD N
 * mix_pool()
 * pool_entropy' <- min(N * Block_Size_Bits, pool_entropy + entropy)
 *
 *
 * Update after every operation: mix_pool(): make robust against low entropy inputs, provide backtracking resistance:
 * ------------------------------------------------------------------------------------------------------------------
 * TMP <- H(DOMAIN_SEP_UPDATE || Current Pool) // would be too slow, to do this on every iteration
 * For block_idx in pool:
 *     Pool_Block[block_idx]' <- H(DOMAIN_SEP_UPDATE || TMP || Pool_Block[block_idx])
 *
 *
 * Output (req_entropy: max digestsize(H) bits at once):
 * ----------------------------------------
 * OUT <- H(DOMAIN_SEP_OUTPUT || Current Pool)
 * mix_pool()
 * pool_entropy' <- max(pool_entropy - req_entropy, 0)
 */

/* Domain separation strings for different operations, prevent accidental identical outputs by design */
static const char *DOMAIN_SEP_INSERT = "INSERT";
static const char *DOMAIN_SEP_UPDATE = "UPDATE";
static const char *DOMAIN_SEP_OUTPUT = "OUTPUT";

/*
 * This is the multi-block auxiliary pool
 *
 * The aux pool array is aligned to 8 bytes to comfort any used 
 * cipher implementations of the hash functions used to read the pool: for some
 * accelerated implementations, we need an alignment to avoid a realignment
 * which involves memcpy(). The alignment to 8 bytes should satisfy all crypto
 * implementations.
 */
struct esdm_pool {
	uint8_t *aux_pool; /* Aux pool: num_blocks * digestsize */
	atomic_t aux_entropy_bits;
	atomic_t digestsize; /* Digest size of used hash */
	bool initialized; /* Aux pool initialized? */

	uint32_t num_blocks;
	uint32_t update_idx;

	/* Serialize read of entropy pool and update of aux pool */
	mutex_w_t lock;
};

static struct esdm_pool esdm_pool __aligned(ESDM_KCAPI_ALIGN) = {
	.aux_pool = NULL,
	.aux_entropy_bits = ATOMIC_INIT(0),
	.digestsize = ATOMIC_INIT(ESDM_MAX_DIGESTSIZE),
	.initialized = false,
	.num_blocks = 0,
	.update_idx = 0,
	.lock = MUTEX_W_UNLOCKED,
};

/********************************** Helper ***********************************/

/* Entropy in bits present in aux pool */
static uint32_t esdm_aux_avail_entropy(uint32_t __unused u)
{
	struct esdm_pool *pool = &esdm_pool;
	/* Cap available entropy with max entropy */
	uint32_t avail_bits =
		min_uint32(pool->num_blocks * esdm_get_digestsize(),
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
	 * than the digest size of the current conditioning hash multiplied
	 * by the number of blocks.
	 */
	digestsize = esdm_reduce_by_osr(digestsize << 3);
	esdm_write_wakeup_bits = pool->num_blocks * digestsize;

	/*
	 * In case the new digest size differs from the old one, cap the available
	 * entropy to the minimum of both sizes multiplied by the number of blocks.
	 */
	ent_bits = min_uint32(ent_bits,
			      pool->num_blocks *
				      min_uint32(old_digestsize, digestsize));
	atomic_add(&pool->aux_entropy_bits, (int)ent_bits);
}

static void esdm_init_wakeup_bits(void)
{
	struct esdm_pool *pool = &esdm_pool;
	uint32_t digestsize = esdm_reduce_by_osr(esdm_get_digestsize());

	esdm_write_wakeup_bits = pool->num_blocks * digestsize;
}

static int esdm_aux_init(void)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct esdm_pool *pool = &esdm_pool;
	const uint32_t multi_block_factor = ESDM_AUX_MULTI_BLOCK_FACTOR;
	int ret = 0;

	mutex_lock(&drng->hash_lock);
	/* at least num nodes + pr drng + init drng */
	pool->num_blocks = multi_block_factor * (esdm_online_nodes() + 2);
	pool->aux_pool = calloc(pool->num_blocks, esdm_get_digestsize());
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "Aux ES hash allocated with %u blocks\n", pool->num_blocks);
	pool->initialized = true;

	esdm_init_wakeup_bits();

	/*
	 * Announce that the aux pool needs entropy - after startup, the aux
	 * pool is empty and should wake up any waiters right away.
	 */
	esdm_shm_status_set_need_entropy();

	mutex_unlock(&drng->hash_lock);
	return ret;
}

static void esdm_aux_fini(void)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct esdm_pool *pool = &esdm_pool;

	mutex_lock(&drng->hash_lock);
	mutex_w_lock(&pool->lock);

	if (!pool->initialized)
		goto out;

	if (pool->aux_pool != NULL) {
		memset_secure(pool->aux_pool, 0,
			      pool->num_blocks * esdm_get_digestsize() / 8);
	}

	free(pool->aux_pool);
	pool->aux_pool = NULL;
	pool->initialized = false;
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "Aux ES hash deallocated\n");

out:
	mutex_w_unlock(&pool->lock);
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

static void esdm_aux_mix_pool_locked()
{
	struct esdm_pool *pool = &esdm_pool;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;
	uint8_t tmp_pool_hash[ESDM_MAX_DIGESTSIZE];
	struct hash_ctx *shash = NULL;
	int ret;

	CKINT(hash_cb->hash_alloc((void **)&shash));
	CKINT(hash_cb->hash_init(shash));
	CKINT(hash_cb->hash_update(shash, (const uint8_t *)DOMAIN_SEP_UPDATE,
				   strlen(DOMAIN_SEP_UPDATE)));
	CKINT(hash_cb->hash_update(shash, pool->aux_pool,
				   pool->num_blocks * esdm_get_digestsize() /
					   8));
	CKINT(hash_cb->hash_final(shash, tmp_pool_hash));
	hash_cb->hash_dealloc(shash);
	shash = NULL;

	for (uint32_t i = 0; i < pool->num_blocks; ++i) {
		CKINT(hash_cb->hash_alloc((void **)&shash));
		CKINT(hash_cb->hash_init(shash));
		CKINT(hash_cb->hash_update(shash,
					   (const uint8_t *)DOMAIN_SEP_UPDATE,
					   strlen(DOMAIN_SEP_UPDATE)));
		CKINT(hash_cb->hash_update(shash, tmp_pool_hash,
					   esdm_get_digestsize() / 8));
		CKINT(hash_cb->hash_update(
			shash, pool->aux_pool + (esdm_get_digestsize() / 8 * i),
			esdm_get_digestsize()));
		CKINT(hash_cb->hash_final(
			shash,
			pool->aux_pool + (esdm_get_digestsize() / 8 * i)));
		hash_cb->hash_dealloc(shash);
		shash = NULL;
	}

out:
	if (shash != NULL) {
		hash_cb->hash_dealloc(shash);
		shash = NULL;
	}
}

/* Insert data into auxiliary pool by using the hash update function. */
static int esdm_aux_pool_insert_locked(const uint8_t *inbuf, size_t inbuflen,
				       uint32_t entropy_bits)
{
	uint32_t num_input_blocks =
		((uint32_t)inbuflen + esdm_get_digestsize() / 8 - 1) /
		(esdm_get_digestsize() / 8);
	struct esdm_pool *pool = &esdm_pool;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb;
	struct hash_ctx *shash = NULL;
	int ret = 0;

	assert(pool->initialized);

	entropy_bits = min_uint32(entropy_bits, (uint32_t)(inbuflen << 3));

	mutex_reader_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;

	/* allow to insert multiple blocks before another expensive mixing operation */
	for (uint32_t block = 0; block < num_input_blocks; ++block) {
		CKINT(hash_cb->hash_alloc((void **)&shash));
		CKINT(hash_cb->hash_init(shash));
		CKINT(hash_cb->hash_update(shash,
					   (const uint8_t *)DOMAIN_SEP_INSERT,
					   strlen(DOMAIN_SEP_INSERT)));
		CKINT(hash_cb->hash_update(shash, pool->aux_pool,
					   pool->num_blocks *
						   esdm_get_digestsize() / 8));
		CKINT(hash_cb->hash_update(
			shash, inbuf + block * esdm_get_digestsize() / 8,
			min_size(esdm_get_digestsize() / 8, inbuflen)));
		CKINT(hash_cb->hash_final(
			shash, pool->aux_pool + (esdm_get_digestsize() / 8 *
						 pool->update_idx)));
		hash_cb->hash_dealloc(shash);
		shash = NULL;

		/* advance next block insert position and remaining hash length */
		pool->update_idx = (pool->update_idx + 1) % pool->num_blocks;
		inbuflen -= min_size(esdm_get_digestsize() / 8, inbuflen);
	}

	esdm_aux_mix_pool_locked();

	/*
	 * Cap the available entropy to the hash output size compliant to
	 * SP800-90B section 3.1.5.1 table 1.
	 */
	entropy_bits += atomic_read_u32(&pool->aux_entropy_bits);
	esdm_pool_set_entropy(min_uint32(
		entropy_bits,
		pool->num_blocks * (hash_cb->hash_digestsize(shash) << 3)));

out:
	mutex_reader_unlock(&drng->hash_lock);
	return ret;
}

DSO_PUBLIC
int esdm_pool_insert_aux(const uint8_t *inbuf, size_t inbuflen,
			 uint32_t entropy_bits)
{
	struct esdm_pool *pool = &esdm_pool;
	int ret = 0;

	mutex_w_lock(&pool->lock);
	ret = esdm_aux_pool_insert_locked(inbuf, inbuflen, entropy_bits);
	mutex_w_unlock(&pool->lock);

	/*
	 * As the DRNG is newly seeded, maybe the need entropy flag can be
	 * unset?
	 */
	esdm_shm_status_set_need_entropy();

	/* notify others about newly added entropy */
	esdm_es_add_entropy();

	return ret;
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
	void *ohash = NULL;
	void *nhash = NULL;
	uint8_t *old_aux_pool = NULL;
	uint8_t *new_aux_pool = NULL;
	int ret;

	if (!pool->initialized)
		return 0;

	/* We only switch if the processed DRNG is the initial DRNG. */
	if (init_drng != drng)
		return 0;

	CKINT(old_cb->hash_alloc(&ohash));
	CKINT(new_cb->hash_alloc(&nhash));
	new_aux_pool = calloc(pool->num_blocks, new_cb->hash_digestsize(nhash));

	/* Switch the hash state */
	old_aux_pool = pool->aux_pool;
	pool->aux_pool = new_aux_pool;

	esdm_set_digestsize(new_cb->hash_digestsize(pool->aux_pool));

	/*
	 * feed the old hash into the new state. We may feed
	 * uninitialized memory into the new state, but this is
	 * considered no issue and even good as we have some more
	 * uncertainty here.
	 */
	esdm_aux_pool_insert_locked(
		old_aux_pool, pool->num_blocks * old_cb->hash_digestsize(ohash),
		0);

	/* start overwriting from pos 0 again */
	pool->update_idx = 0;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Re-initialize aux entropy pool with hash %s\n",
		    new_cb->hash_name());

out:
	memset_secure(old_aux_pool, 0,
		      pool->num_blocks * old_cb->hash_digestsize(ohash));
	new_cb->hash_dealloc(nhash);
	old_cb->hash_dealloc(ohash);
	free(old_aux_pool);
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
	struct hash_ctx *shash = NULL;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb;
	uint32_t collected_ent_bits, returned_ent_bits,
		unused_bits = 0, digestsize, digestsize_bits,
		requested_bits_osr;
	uint8_t aux_output[ESDM_MAX_DIGESTSIZE];
	int ret;

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
		min_uint32(pool->num_blocks * digestsize_bits,
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

	CKINT(hash_cb->hash_alloc((void **)&shash));
	CKINT(hash_cb->hash_init(shash));
	CKINT(hash_cb->hash_update(shash, (const uint8_t *)DOMAIN_SEP_OUTPUT,
				   strlen(DOMAIN_SEP_OUTPUT)));
	CKINT(hash_cb->hash_update(shash, pool->aux_pool,
				   pool->num_blocks * esdm_get_digestsize() /
					   8));
	CKINT(hash_cb->hash_final(shash, aux_output));
	hash_cb->hash_dealloc(shash);
	shash = NULL;

	/* advance pool state and assure backtracking resistance */
	esdm_aux_mix_pool_locked();

	/*
	* Do not truncate the output size exactly to collected_ent_bits
	* as the aux pool may contain data that is not credited with
	* entropy, but we want to use them to stir the DRNG state.
	*/
	memcpy(outbuf, aux_output, requested_bits >> 3);

out:
	if (shash != NULL) {
		hash_cb->hash_dealloc(shash);
		shash = NULL;
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

	/*
	 * We always mix the pool for backtracking resistance,
	 * see: esdm_aux_mix_pool_locked
	 */
	eb_es->e_bits = esdm_aux_get_pool(eb_es->e, requested_bits);

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

static bool esdm_aux_active(void)
{
	return true;
}

struct esdm_es_cb esdm_es_aux = {
	.name = "Auxiliary (Multi-Block)",
	.init = esdm_aux_init,
	.fini = esdm_aux_fini,
	.monitor_es = NULL,
	.get_ent = esdm_aux_get_backtrack,
	.curr_entropy = esdm_aux_avail_entropy,
	.max_entropy = esdm_get_digestsize,
	.state = esdm_aux_es_state,
	.reset = esdm_aux_reset,
	.active = esdm_aux_active,
	.switch_hash = esdm_aux_switch_hash,
};
