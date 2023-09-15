/*
 * ESDM DRNG management
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

#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#include "build_bug_on.h"
#include "config.h"
#include "esdm.h"
#include "esdm_builtin_hash_drbg.h"
#include "esdm_builtin_chacha20.h"
#include "esdm_builtin_sha512.h"
#include "esdm_config.h"
#include "esdm_crypto.h"
#include "esdm_drng_atomic.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_botan.h"
#include "esdm_gnutls.h"
#include "esdm_leancrypto.h"
#include "esdm_node.h"
#include "esdm_openssl.h"
#include "helper.h"
#include "queue.h"
#include "ret_checkers.h"
#include "visibility.h"

/*
 * Maximum number of seconds between DRNG reseed intervals of the DRNG. Note,
 * this is enforced with the next request of random numbers from the
 * DRNG. Setting this value to zero implies a reseeding attempt before every
 * generated random number.
 */
static uint32_t esdm_drng_reseed_max_time = 600;

/*
 * Is ESDM for general-purpose use (i.e. is at least the esdm_drng_init
 * fully allocated)?
 */
static atomic_t esdm_avail = ATOMIC_INIT(0);

/* Guard protecting all crypto callback update operation of all DRNGs. */
DEFINE_MUTEX_W_UNLOCKED(esdm_crypto_cb_update);

/*
 * Default hash callback that provides the crypto primitive right from the
 * kernel start. It must not perform any memory allocation operation, but
 * simply perform the hash calculation.
 */
#if (defined(ESDM_HASH_SHA512) || defined(ESDM_HASH_SHA3_512))
#define ESDM_DEFAULT_HASH_CB &esdm_builtin_sha512_cb
#elif defined(ESDM_BOTAN)
#define ESDM_DEFAULT_HASH_CB &esdm_botan_hash_cb
#elif defined(ESDM_GNUTLS)
#define ESDM_DEFAULT_HASH_CB &esdm_gnutls_hash_cb
#elif defined(ESDM_LEANCRYPTO)
#define ESDM_DEFAULT_HASH_CB &esdm_leancrypto_hash_cb
#elif defined(ESDM_OPENSSL)
#define ESDM_DEFAULT_HASH_CB &esdm_openssl_hash_cb
#else
#error "Unknown default DRNG selected"
#endif

/*
 * Default DRNG callback that provides the crypto primitive which is
 * allocated either during late kernel boot stage. So, it is permissible for
 * the callback to perform memory allocation operations.
 */
const struct esdm_drng_cb *esdm_default_drng_cb =
#if defined(ESDM_DRNG_HASH_DRBG)
	&esdm_builtin_hash_drbg_cb;
#elif defined(ESDM_BOTAN)
	&esdm_botan_drbg_cb;
#elif defined(ESDM_DRNG_CHACHA20)
	&esdm_builtin_chacha20_cb;
#elif defined(ESDM_GNUTLS)
	&esdm_gnutls_drbg_cb;
#elif defined(ESDM_LEANCRYPTO)
	&esdm_leancrypto_drbg_cb;
#elif defined(ESDM_OPENSSL)
	&esdm_openssl_drbg_cb;
#else
#error "Unknown default DRNG selected"
#endif

/* DRNG for non-atomic use cases */
static struct esdm_drng esdm_drng_init = { ESDM_DRNG_STATE_INIT(
	esdm_drng_init, NULL, NULL, ESDM_DEFAULT_HASH_CB) };

/* Prediction-resistance DRNG: only deliver as much data as received entropy */
static struct esdm_drng esdm_drng_pr = { ESDM_DRNG_STATE_INIT(
	esdm_drng_pr, NULL, NULL, ESDM_DEFAULT_HASH_CB) };

/* Wait queue to wait until the ESDM is initialized - can freely be used */
DECLARE_WAIT_QUEUE(esdm_init_wait);

static atomic_t esdm_drng_mgr_terminate = ATOMIC_INIT(0);

/********************************** Helper ************************************/

bool esdm_get_available(void)
{
	return (atomic_read(&esdm_avail) == 2);
}

struct esdm_drng *esdm_drng_init_instance(void)
{
	return &esdm_drng_init;
}

/* Caller must call esdm_drng_put_instances! */
struct esdm_drng *esdm_drng_node_instance(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	uint32_t node = esdm_config_curr_node();

	if (esdm_drng && esdm_drng[node])
		return esdm_drng[node];

	return esdm_drng_init_instance();
}

/*
 * Reset the DRNG by clearing all meta data, but leave the state (which implies)
 * the state is credited with zero entropy, but is used to have a state other
 * than zero).
 */
void esdm_drng_reset(struct esdm_drng *drng)
{
	/* Ensure reseed during next call */
	atomic_set(&drng->requests, 1);
	atomic_set(&drng->requests_since_fully_seeded, 0);
	drng->last_seeded = time(NULL);
	drng->fully_seeded = false;
	/* Do not set force, as this flag is used for the emergency reseeding */
	drng->force_reseed = false;
	logger(LOGGER_DEBUG, LOGGER_C_DRNG, "reset DRNG\n");
}

/* Initialize the DRNG, except the mutex lock */
int esdm_drng_alloc_common(struct esdm_drng *drng,
			   const struct esdm_drng_cb *drng_cb)
{
	int ret = 0;

	if (!drng || !drng_cb)
		return -EINVAL;
	if (drng->drng)
		return 0;

	drng->drng_cb = drng_cb;
	CKINT(drng_cb->drng_alloc(&drng->drng,
				  ESDM_DRNG_SECURITY_STRENGTH_BYTES))
	esdm_drng_reset(drng);

out:
	return ret;
}

static void esdm_drng_dealloc_common(struct esdm_drng *drng)
{
	const struct esdm_drng_cb *drng_cb;

	if (!drng)
		return;

	/* This only works with a robust mutex */
	mutex_w_lock(&drng->lock);
	drng_cb = drng->drng_cb;
	drng_cb->drng_dealloc(drng->drng);
	drng->drng = NULL;
	mutex_w_unlock(&drng->lock);
}

static int esdm_drng_mgr_selftest(void)
{
	struct esdm_drng *drng = esdm_drng_node_instance();
	const struct esdm_hash_cb *hash_cb;
	const struct esdm_drng_cb *drng_cb;
	int ret = 0;

	/* Perform selftest of current crypto implementations */
	mutex_reader_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;
	if (hash_cb->hash_selftest)
		ret = hash_cb->hash_selftest();
	else
		logger(LOGGER_WARN, LOGGER_C_DRNG, "Hash self test missing\n");
	mutex_reader_unlock(&drng->hash_lock);
	CKINT_LOG(ret, "Hash self test failed: %d\n", ret);
	logger(LOGGER_DEBUG, LOGGER_C_DRNG,
	       "Hash self test passed successfully\n");

	mutex_w_lock(&drng->lock);
	drng_cb = drng->drng_cb;
	if (drng_cb->drng_selftest)
		ret = drng_cb->drng_selftest();
	else
		logger(LOGGER_WARN, LOGGER_C_DRNG, "DRNG self test missing\n");
	mutex_w_unlock(&drng->lock);
	CKINT_LOG(ret, "DRNG self test failed: %d\n", ret);
	logger(LOGGER_DEBUG, LOGGER_C_DRNG,
	       "DRNG self test passed successfully\n");

out:
	esdm_drng_put_instances();
	return ret;
}

int esdm_drng_mgr_reinitialize(void)
{
	int ret;

	CKINT(esdm_drng_mgr_selftest());

out:
	return ret;
}

/* Initialize the default DRNG during start time and perform its seeding */
int esdm_drng_mgr_initialize(void)
{
	int ret;

	/*
	 * If the esdm_avail is not 0, either the DRNG is initialized, or the
	 * initializiation process is in progress.
	 */
	if (atomic_cmpxchg(&esdm_avail, 0, 1) != 0)
		return 0;

	/* Initialize the PR DRNG inside init lock as it guards esdm_avail. */
	mutex_w_init(&esdm_drng_pr.lock, 1, 1);
	ret = esdm_drng_alloc_common(&esdm_drng_pr, esdm_default_drng_cb);
	mutex_w_unlock(&esdm_drng_pr.lock);

	if (!ret) {
		logger(LOGGER_VERBOSE, LOGGER_C_DRNG,
		       "DRNG with prediction resistance allocated\n");
		mutex_w_init(&esdm_drng_init.lock, 1, 1);
		ret = esdm_drng_alloc_common(&esdm_drng_init,
					     esdm_default_drng_cb);
		mutex_w_unlock(&esdm_drng_init.lock);
		if (!ret) {
			atomic_set(&esdm_avail, 2);
			logger(LOGGER_VERBOSE, LOGGER_C_DRNG,
			       "DRNG without prediction resistance allocated\n");
		}
	}

	CKINT(ret);

	logger(LOGGER_DEBUG, LOGGER_C_DRNG,
	       "ESDM for general use is available\n");

	CKINT(esdm_drng_mgr_selftest());

out:
	if (ret)
		atomic_set(&esdm_avail, 0);
	return ret;
}

void esdm_drng_mgr_finalize(void)
{
	atomic_set(&esdm_drng_mgr_terminate, 1);
	esdm_drng_dealloc_common(esdm_drng_init_instance());
	esdm_drng_dealloc_common(&esdm_drng_pr);
}

DSO_PUBLIC
int esdm_sp80090c_compliant(void)
{
#ifndef ESDM_OVERSAMPLE_ENTROPY_SOURCES
	return false;
#else
	/* SP800-90C only requested in FIPS mode */
	return esdm_config_fips_enabled();
#endif
}

DSO_PUBLIC
int esdm_ntg1_compliant(void)
{
	/* Implies using of /dev/random with O_SYNC */
	return true;
}

DSO_PUBLIC
int esdm_ntg1_2022_compliant(void)
{
	return
#ifdef ESDM_AIS2031_NTG1_SEEDING_STRATEGY
		true
#else
		false
#endif
		;
}

DSO_PUBLIC
uint32_t esdm_get_reseed_max_time(void)
{
	return esdm_drng_reseed_max_time;
}

DSO_PUBLIC
void esdm_set_reseed_max_time(uint32_t seconds)
{
	if (!seconds)
		return;

	/* We allow at most 1h reseed time */
	esdm_drng_reseed_max_time = min_uint32(seconds, 60 * 60);
}

/************************* Random Number Generation ***************************/

static bool esdm_time_after(time_t curr, time_t base)
{
	if (curr == (time_t)-1)
		return false;
	if (base == (time_t)-1)
		return true;
	return (curr > base) ? true : false;
}

static time_t esdm_time_after_now(time_t base)
{
	time_t curr = time(NULL);

	if (curr == (time_t)-1)
		return 0;
	return esdm_time_after(curr, base) ? (curr - base) : 0;
}

/* Inject a data buffer into the DRNG - caller must hold its lock */
void esdm_drng_inject(struct esdm_drng *drng, const uint8_t *inbuf,
		      size_t inbuflen, bool fully_seeded, const char *drng_type)
{
	BUILD_BUG_ON(ESDM_DRNG_RESEED_THRESH > INT_MAX);
	logger(LOGGER_DEBUG, LOGGER_C_DRNG, "seeding %s DRNG with %zu bytes\n",
	       drng_type, inbuflen);

	if (!drng->drng)
		return;

	if (drng->drng_cb->drng_seed(drng->drng, inbuf, inbuflen) < 0) {
		logger(LOGGER_WARN, LOGGER_C_DRNG,
		       "seeding of %s DRNG failed\n", drng_type);
		drng->force_reseed = true;
	} else {
		int gc = ESDM_DRNG_RESEED_THRESH - atomic_read(&drng->requests);

		logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		       "%s DRNG stats since last seeding: %lu secs; generate calls: %d\n",
		       drng_type, esdm_time_after_now(drng->last_seeded), gc);

		/* Count the numbers of generate ops since last fully seeded */
		if (fully_seeded)
			atomic_set(&drng->requests_since_fully_seeded, 0);
		else
			atomic_add(&drng->requests_since_fully_seeded, gc);

		drng->last_seeded = time(NULL);
		atomic_set(&drng->requests, ESDM_DRNG_RESEED_THRESH);
		drng->force_reseed = false;

		if (!drng->fully_seeded) {
			drng->fully_seeded = fully_seeded;
			if (drng->fully_seeded)
				logger(LOGGER_DEBUG, LOGGER_C_DRNG,
				       "%s DRNG fully seeded\n", drng_type);
		}
	}
}

/*
 * Perform the seeding of the DRNG with data from entropy source.
 * The function returns the entropy injected into the DRNG in bits.
 *
 * The caller must hold the DRNG lock.
 */
static uint32_t esdm_drng_seed_es_nolock(struct esdm_drng *drng, bool init_ops,
					 const char *drng_type)
{
	struct entropy_buf seedbuf __aligned(ESDM_KCAPI_ALIGN),
		collected_seedbuf;
	uint32_t collected_entropy = 0;
	unsigned int i, num_es_delivered = 0;
	bool forced = drng->force_reseed;

	for_each_esdm_es (i)
		collected_seedbuf.entropy_es[i].e_bits = 0;

	/*
	 * This clearing is not strictly needed, but it silences
	 * valgrind.
	 */
	memset(&seedbuf, 0, sizeof(seedbuf));

	do {
		/* Count the number of ES which delivered entropy */
		num_es_delivered = 0;

		if (collected_entropy) {
			logger(LOGGER_VERBOSE, LOGGER_C_DRNG,
			       "Force fully seeding level for %s DRNG by repeatedly pull entropy from available entropy sources\n",
			       drng_type);
		}

		esdm_fill_seed_buffer(
			&seedbuf, esdm_get_seed_entropy_osr(drng->fully_seeded),
			forced && !drng->fully_seeded);

		collected_entropy += esdm_entropy_rate_eb(&seedbuf);

		/* Sum iterations up. */
		for_each_esdm_es (i) {
			collected_seedbuf.entropy_es[i].e_bits +=
				seedbuf.entropy_es[i].e_bits;
			num_es_delivered += !!seedbuf.entropy_es[i].e_bits;
		}

		/* Inject seed data into DRNG */
		esdm_drng_inject(drng, (uint8_t *)&seedbuf, sizeof(seedbuf),
				 esdm_fully_seeded(drng->fully_seeded,
						   collected_entropy,
						   &collected_seedbuf),
				 "regular");

		/*
		 * Set the seeding state of the ESDM
		 *
		 * Do not call esdm_init_ops(seedbuf) here as the atomic DRNG
		 * does not serve common users.
		 */
		if (init_ops)
			esdm_init_ops(&collected_seedbuf);

		/*
	 * Emergency reseeding: If we reached the min seed threshold now
	 * multiple times but never reached fully seeded level and we collect
	 * entropy, keep doing it until we reached fully seeded level for
	 * at least one DRNG. This operation is not continued if the
	 * ES do not deliver entropy such that we cannot reach the fully seeded
	 * level.
	 *
	 * The emergency reseeding implies that the consecutively injected
	 * entropy can be added up. This is applicable due to the fact that
	 * the entire operation is atomic which means that the DRNG is not
	 * producing data while this is ongoing.
	 */
	} while (forced && !drng->fully_seeded &&
		 num_es_delivered >= (esdm_ntg1_2022_compliant() ? 2 : 1));

	memset_secure(&seedbuf, 0, sizeof(seedbuf));

	return collected_entropy;
}

static void esdm_drng_seed_es(struct esdm_drng *drng)
{
	mutex_w_lock(&drng->lock);
	esdm_drng_seed_es_nolock(drng, true, "regular");
	mutex_w_unlock(&drng->lock);
}

static void esdm_drng_seed(struct esdm_drng *drng)
{
	BUILD_BUG_ON(ESDM_MIN_SEED_ENTROPY_BITS >
		     ESDM_DRNG_SECURITY_STRENGTH_BITS);

	/* (Re-)Seed DRNG */
	esdm_drng_seed_es(drng);
	/* (Re-)Seed atomic DRNG from regular DRNG */
	esdm_drng_atomic_seed_drng(drng);
}

static void esdm_drng_seed_work_one(struct esdm_drng *drng, uint32_t node)
{
	logger(LOGGER_DEBUG, LOGGER_C_DRNG,
	       "reseed triggered by system events for DRNG on node %d\n", node);
	esdm_drng_seed(drng);
	if (drng->fully_seeded) {
		/* Prevent reseed storm */
		drng->last_seeded += node * 60;
	}
}

/**
 * @brief Seeding of one not yet fully seeded DRNG
 *
 * Perform the seeding of a DRNG. The code seeds one DRNG that is currently
 * not (fully) seeded. The logic picks the DRNG to be seeded.
 *
 * @param [in] force Apply the forced seeding operation.
 */
static void __esdm_drng_seed_work(bool force)
{
	struct esdm_drng **esdm_drng;

	/*
	 * If the DRNG is not yet initialized, let us try to seed the atomic
	 * DRNG.
	 */
	if (!esdm_get_available()) {
		struct esdm_drng *atomic;

		if (thread_queue_sleeper(&esdm_init_wait)) {
			esdm_init_ops(NULL);
			return;
		}
		atomic = esdm_get_atomic();
		if (!atomic || atomic->fully_seeded)
			return;

		atomic->force_reseed |= force;
		mutex_w_lock(&atomic->lock);
		esdm_drng_seed_es_nolock(atomic, false, "atomic");
		mutex_w_unlock(&atomic->lock);

		return;
	}

	esdm_drng = esdm_drng_get_instances();
	if (esdm_drng) {
		uint32_t node;

		for_each_online_node(node)
		{
			struct esdm_drng *drng = esdm_drng[node];

			if (!drng)
				continue;

			if (drng && !drng->fully_seeded) {
				/* return code does not matter */
				drng->force_reseed |= force;
				esdm_drng_seed_work_one(drng, node);
				goto out;
			}
		}
	} else {
		if (!esdm_drng_init.fully_seeded) {
			esdm_drng_init.force_reseed |= force;
			esdm_drng_seed_work_one(&esdm_drng_init, 0);
			goto out;
		}
	}

	if (!esdm_drng_pr.fully_seeded) {
		esdm_drng_pr.force_reseed |= force;
		esdm_drng_seed_work_one(&esdm_drng_pr, 0);
		goto out;
	}

	esdm_pool_all_nodes_seeded(true);

out:
	esdm_drng_put_instances();
}

void esdm_drng_seed_work(void)
{
	__esdm_drng_seed_work(false);

	/* Allow the seeding operation to be called again */
	esdm_pool_unlock();
}

/* Force all DRNGs to reseed before next generation */
DSO_PUBLIC
void esdm_drng_force_reseed(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	uint32_t node;

	/*
	 * If the initial DRNG is over the reseed threshold, allow a forced
	 * reseed only for the initial DRNG as this is the fallback for all. It
	 * must be kept seeded before all others to keep the ESDM operational.
	 */
	if (!esdm_drng ||
	    (atomic_read_u32(&esdm_drng_init.requests_since_fully_seeded) >
	     ESDM_DRNG_RESEED_THRESH)) {
		esdm_drng_init.force_reseed = esdm_drng_init.fully_seeded;
		logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		       "force reseed of initial DRNG\n");
		goto out;
	}

	for_each_online_node(node)
	{
		struct esdm_drng *drng = esdm_drng[node];

		if (!drng)
			continue;

		drng->force_reseed = drng->fully_seeded;
		logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		       "force reseed of DRNG on CPU %u\n", node);
	}

	esdm_drng_atomic_force_reseed();

out:
	esdm_drng_put_instances();
}

static bool esdm_drng_must_reseed(struct esdm_drng *drng)
{
	return (atomic_dec_and_test(&drng->requests) || drng->force_reseed ||
		esdm_time_after_now(drng->last_seeded +
				    esdm_drng_reseed_max_time));
}

/**
 * @brief Get random data out of the DRNG which is reseeded frequently.
 *
 * @param [in] drng DRNG instance
 * @param [in] outbuf buffer for storing random data
 * @param [in] outbuflen length of outbuf
 *
 * @return
 * * < 0 in error case (DRNG generation or update failed)
 * * >=0 returning the returned number of bytes
 */
static ssize_t esdm_drng_get(struct esdm_drng *drng, uint8_t *outbuf,
			     size_t outbuflen)
{
	ssize_t processed = 0;
	bool pr = (drng == &esdm_drng_pr) ? true : false;

	if (!outbuf || !outbuflen)
		return 0;

	if (!esdm_get_available())
		return -EOPNOTSUPP;

	outbuflen = min_size(outbuflen, SSIZE_MAX);

	/*
	 * If the entire ESDM ran without full reseed for too long,
	 * revert to the unseeded state.
	 *
	 * Note a reseed requested by drng->force_reseed or esdm_drng_seed()
	 * does not imply that sufficient entropy was received to fill the DRNG.
	 * If this state persists, then the following check applies.
	 */
	if (atomic_read_u32(&drng->requests_since_fully_seeded) >
	    esdm_config_drng_max_wo_reseed())
		esdm_unset_fully_seeded(drng);

	/* Loop to collect random bits for the caller. */
	while (outbuflen) {
		uint32_t todo =
			min_uint32((uint32_t)outbuflen, ESDM_DRNG_MAX_REQSIZE);
		ssize_t ret;

		/* In normal operation, check whether to reseed */
		if (!pr && esdm_drng_must_reseed(drng)) {
			if (!esdm_pool_trylock()) {
				/*
				 * Entropy pool cannot be locked, try to reseed
				 * next time, but continue to generate random
				 * bits.
				 */
				drng->force_reseed = true;
			} else {
				/* Perform synchronous reseed */
				esdm_drng_seed(drng);
				esdm_pool_unlock();
			}
		}

		mutex_w_lock(&drng->lock);

		/*
		 * Handle prediction resistance requests.
		 *
		 * Note, as we do not reseed before the generate call, it
		 * implies that this code path is only truly producing
		 * prediction resistance bits following the definition of
		 * SP800-90A with a separate DRBG instance that is dedicated to
		 * the PR operation. A DRBG instance that would be both used for
		 * non-PR and PR behavior would not comply with the definition
		 * of SP800-90A.
		 */
		if (pr) {
			/* If async reseed did not deliver entropy, try now */
			if (!drng->fully_seeded) {
				uint32_t collected_ent_bits;

				/* If we cannot get the pool lock, try again. */
				if (!esdm_pool_trylock()) {
					mutex_w_unlock(&drng->lock);
					continue;
				}

				collected_ent_bits = esdm_drng_seed_es_nolock(
					drng, true, "regular");

				esdm_pool_unlock();

				/* If no new entropy was received, stop now. */
				if (!collected_ent_bits) {
					mutex_w_unlock(&drng->lock);
					goto out;
				}

				/* If no new entropy was received, stop now. */
				todo = min_uint32(todo,
						  collected_ent_bits >> 3);
			}

			/* Do not produce more than DRNG security strength. */
			todo = min_uint32(todo, esdm_security_strength() >> 3);
		}

		/* Now, generate random bits from the properly seeded DRNG. */
		ret = drng->drng_cb->drng_generate(drng->drng,
						   outbuf + processed, todo);
		mutex_w_unlock(&drng->lock);
		if (ret <= 0) {
			logger(LOGGER_WARN, LOGGER_C_DRNG,
			       "getting random data from DRNG failed (%zd)\n",
			       ret);
			return -EFAULT;
		}
		processed += ret;
		outbuflen -= (size_t)ret;

		if (pr) {
			/* Force the async reseed for PR DRNG */
			esdm_unset_fully_seeded(drng);
			if (outbuflen)
				sched_yield();
		}
	}

out:
	return processed;
}

static ssize_t esdm_drng_get_sleep(uint8_t *outbuf, size_t outbuflen, bool pr)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	struct esdm_drng *drng = &esdm_drng_init;
	uint32_t node = esdm_config_curr_node();
	ssize_t ret;

	if (pr) {
		logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		       "Using prediction resistance DRNG instance to service generate request\n");
		drng = &esdm_drng_pr;
	} else if (esdm_drng && esdm_drng[node] &&
		   esdm_drng[node]->fully_seeded) {
		logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		       "Using DRNG instance on node %u to service generate request\n",
		       node);
		drng = esdm_drng[node];
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		       "Using DRNG instance on node 0 to service generate request\n");
	}

	CKINT(esdm_drng_mgr_initialize());
	CKINT(esdm_drng_get(drng, outbuf, outbuflen));

out:
	esdm_drng_put_instances();
	return ret;
}

/*
 * Reset ESDM such that all existing entropy is gone.
 */
void esdm_reset(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();

	if (!esdm_drng) {
		mutex_w_lock(&esdm_drng_init.lock);
		esdm_drng_reset(&esdm_drng_init);
		mutex_w_unlock(&esdm_drng_init.lock);
	} else {
		uint32_t cpu;

		for_each_online_node(cpu)
		{
			struct esdm_drng *drng = esdm_drng[cpu];

			if (!drng)
				continue;
			mutex_w_lock(&drng->lock);
			esdm_drng_reset(drng);
			mutex_w_unlock(&drng->lock);
		}
	}

	esdm_drng_put_instances();

	mutex_w_lock(&esdm_drng_pr.lock);
	esdm_drng_reset(&esdm_drng_pr);
	mutex_w_unlock(&esdm_drng_pr.lock);

	esdm_drng_atomic_reset();
	esdm_set_entropy_thresh(ESDM_FULL_SEED_ENTROPY_BITS);

	esdm_reset_state();
}

/******************* Generic ESDM kernel output interfaces ********************/

/* Force one DRBG to be fully seeded */
void esdm_force_fully_seeded(void)
{
	if (esdm_pool_all_nodes_seeded_get())
		return;

	esdm_pool_lock();
	__esdm_drng_seed_work(true);
	esdm_pool_unlock();
}

/* Force all DRBG to be fully seeded */
void esdm_force_fully_seeded_all_drbgs(void)
{
	if (esdm_pool_all_nodes_seeded_get())
		return;

	esdm_pool_lock();
	do {
		__esdm_drng_seed_work(true);
	} while (esdm_es_reseed_wanted());
	esdm_pool_unlock();
}

static int esdm_drng_sleep_while_not_all_nodes_seeded(unsigned int nonblock)
{
	esdm_force_fully_seeded_all_drbgs();
	if (esdm_pool_all_nodes_seeded_get())
		return 0;
	if (nonblock)
		return -EAGAIN;
	thread_wait_event(&esdm_init_wait,
			  esdm_pool_all_nodes_seeded_get() &&
				  !atomic_read(&esdm_drng_mgr_terminate));
	return 0;
}

static int esdm_drng_sleep_while_nonoperational(unsigned int nonblock)
{
	esdm_force_fully_seeded();
	if (esdm_state_operational())
		return 0;
	if (nonblock)
		return -EAGAIN;
	thread_wait_event(&esdm_init_wait,
			  esdm_state_operational() &&
				  !atomic_read(&esdm_drng_mgr_terminate));
	return 0;
}

static int esdm_drng_sleep_while_non_min_seeded(unsigned int nonblock)
{
	esdm_force_fully_seeded();
	if (esdm_state_min_seeded())
		return 0;
	if (nonblock)
		return -EAGAIN;
	thread_wait_event(&esdm_init_wait,
			  esdm_state_min_seeded() &&
				  !atomic_read(&esdm_drng_mgr_terminate));
	return 0;
}

DSO_PUBLIC
ssize_t esdm_get_seed(uint64_t *buf, size_t nbytes,
		      enum esdm_get_seed_flags flags)
{
	struct entropy_buf *eb = (struct entropy_buf *)(buf + 2);
	uint64_t buflen = sizeof(struct entropy_buf) + 2 * sizeof(uint64_t);
	uint64_t collected_bits = 0;
	int ret;

	/* Ensure buffer is aligned as required */
	BUILD_BUG_ON(sizeof(buflen) < ESDM_KCAPI_ALIGN);
	if (nbytes < sizeof(buflen))
		return -EINVAL;

	/* Write buffer size into first word */
	buf[0] = buflen;
	if (nbytes < buflen)
		return -EMSGSIZE;

	ret = esdm_drng_sleep_while_not_all_nodes_seeded(
		flags & ESDM_GET_SEED_NONBLOCK);
	if (ret < 0)
		return ret;

	/* Try to get the pool lock and sleep on it to get it. */
	esdm_pool_lock();

	/* If an ESDM DRNG becomes unseeded, give this DRNG precedence. */
	if (!esdm_pool_all_nodes_seeded_get()) {
		esdm_pool_unlock();
		return 0;
	}

	/*
	 * Try to get seed data - a rarely used busyloop is cheaper than a wait
	 * queue that is constantly woken up by the hot code path of
	 * esdm_init_ops.
	 */
	for (;;) {
		esdm_fill_seed_buffer(
			eb,
			esdm_get_seed_entropy_osr(flags &
						  ESDM_GET_SEED_FULLY_SEEDED),
			false);
		collected_bits = esdm_entropy_rate_eb(eb);

		/* Break the collection loop if we got entropy, ... */
		if (collected_bits ||
		    /* ... a DRNG becomes unseeded, give DRNG precedence, ... */
		    !esdm_pool_all_nodes_seeded_get() ||
		    /* ... when the DRNG manager terminates, or ... */
		    atomic_read(&esdm_drng_mgr_terminate) ||
		    /* ... if the caller does not want a blocking behavior. */
		    (flags & ESDM_GET_SEED_NONBLOCK))
			break;

		nanosleep(&poll_ts, NULL);
	}

	esdm_pool_unlock();

	/* Write collected entropy size into second word */
	buf[1] = collected_bits;

	return (ssize_t)buflen;
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_pr(uint8_t *buf, size_t nbytes)
{
	esdm_drng_sleep_while_nonoperational(0);
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, true);
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_pr_noblock(uint8_t *buf, size_t nbytes)
{
	int ret = esdm_drng_sleep_while_nonoperational(1);

	if (ret)
		return ret;
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, true);
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_full_noblock(uint8_t *buf, size_t nbytes)
{
	int ret = esdm_drng_sleep_while_nonoperational(1);

	if (ret)
		return ret;
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, false);
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_full(uint8_t *buf, size_t nbytes)
{
	esdm_drng_sleep_while_nonoperational(0);
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, false);
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_min(uint8_t *buf, size_t nbytes)
{
	esdm_drng_sleep_while_non_min_seeded(0);
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, false);
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_min_noblock(uint8_t *buf, size_t nbytes)
{
	int ret = esdm_drng_sleep_while_non_min_seeded(1);

	if (ret)
		return ret;
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, false);
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes(uint8_t *buf, size_t nbytes)
{
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, false);
}
