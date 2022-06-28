/*
 * ESDM DRNG management
 *
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

#include <errno.h>
#include <limits.h>

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
#include "esdm_node.h"
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
const struct esdm_hash_cb *esdm_default_hash_cb = &esdm_builtin_sha512_cb;

/*
 * Default DRNG callback that provides the crypto primitive which is
 * allocated either during late kernel boot stage. So, it is permissible for
 * the callback to perform memory allocation operations.
 */
const struct esdm_drng_cb *esdm_default_drng_cb =
#if defined(ESDM_DRNG_HASH_DRBG)
	&esdm_builtin_hash_drbg_cb;
#elif defined(ESDM_DRNG_CHACHA20)
	&esdm_builtin_chacha20_cb;
#else
#error "Unknown default DRNG selected"
#endif

/* DRNG for non-atomic use cases */
static struct esdm_drng esdm_drng_init = {
	ESDM_DRNG_STATE_INIT(esdm_drng_init, NULL, NULL,
			     &esdm_builtin_sha512_cb),
	.lock = MUTEX_W_UNLOCKED,
};

/* Wait queue to wait until the ESDM is initialized - can freely be used */
DECLARE_WAIT_QUEUE(esdm_init_wait);

/********************************** Helper ************************************/

bool esdm_get_available(void)
{
	return !!atomic_read(&esdm_avail);
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

void esdm_drng_reset(struct esdm_drng *drng)
{
	atomic_set(&drng->requests, ESDM_DRNG_RESEED_THRESH);
	atomic_set(&drng->requests_since_fully_seeded, 0);
	drng->last_seeded = time(NULL);
	drng->fully_seeded = false;
	drng->force_reseed = true;
	logger(LOGGER_DEBUG, LOGGER_C_DRNG, "reset DRNG\n");
}

/* Initialize the DRNG, except the mutex lock */
int esdm_drng_alloc_common(struct esdm_drng *drng,
			   const struct esdm_drng_cb *drng_cb)
{
	int ret = 0;

	if (!drng || !drng_cb)
		return -EINVAL;

	drng->drng_cb = drng_cb;
	CKINT(drng_cb->drng_alloc(&drng->drng,
				  ESDM_DRNG_SECURITY_STRENGTH_BYTES))
	esdm_drng_reset(drng);

out:
	return ret;
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
		logger(LOGGER_WARN, LOGGER_C_DRNG, "DRMG self test missing\n");
	mutex_w_unlock(&drng->lock);
	CKINT_LOG(ret, "DRNG self test failed: %d\n", ret);
	logger(LOGGER_DEBUG, LOGGER_C_DRNG,
	       "DRNG self test passed successfully\n");

out:
	esdm_drng_put_instances();
	return ret;
}

/* Initialize the default DRNG during boot and perform its seeding */
int esdm_drng_mgr_initalize(void)
{
	int ret;

	if (esdm_get_available())
		return 0;

	logger(LOGGER_VERBOSE, LOGGER_C_DRNG, "Initialize DRNG manager\n");

	/* Catch programming error */
	if (esdm_drng_init.hash_cb != esdm_default_hash_cb) {
		logger(LOGGER_ERR, LOGGER_C_DRNG, "Programming bug at %s\n",
		       __func__);
	}

	mutex_w_lock(&esdm_drng_init.lock);
	if (esdm_get_available()) {
		mutex_w_unlock(&esdm_drng_init.lock);
		return 0;
	}

	ret = esdm_drng_alloc_common(&esdm_drng_init, esdm_default_drng_cb);
	mutex_w_unlock(&esdm_drng_init.lock);
	CKINT(ret);

	logger(LOGGER_DEBUG, LOGGER_C_DRNG,
	       "ESDM for general use is available\n");
	atomic_set(&esdm_avail, 1);

	CKINT(esdm_drng_mgr_selftest());

out:
	return ret;
}

void esdm_drng_mgr_finalize(void)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_drng_cb *drng_cb;

	mutex_w_lock(&drng->lock);
	drng_cb = drng->drng_cb;
	drng_cb->drng_dealloc(drng->drng);
	drng->drng = NULL;
	mutex_w_unlock(&drng->lock);
}

DSO_PUBLIC
int esdm_sp80090c_compliant(void)
{
#ifndef ESDM_OVERSAMPLE_ENTROPY_SOURCES
		return false;
#endif

	/* SP800-90C only requested in FIPS mode */
	return esdm_config_fips_enabled();
}

DSO_PUBLIC
int esdm_ntg1_compliant(void)
{
	/* Implies using of /dev/random with O_SYNC */
	return true;
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
	esdm_drng_reseed_max_time = min_t(uint32_t, seconds, 60 * 60);
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
void esdm_drng_inject(struct esdm_drng *drng,
		      const uint8_t *inbuf, size_t inbuflen,
		      bool fully_seeded, const char *drng_type)
{
	BUILD_BUG_ON(ESDM_DRNG_RESEED_THRESH > INT_MAX);
	logger(LOGGER_DEBUG, LOGGER_C_DRNG,
	       "seeding %s DRNG with %zu bytes\n", drng_type, inbuflen);

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
 */
static uint32_t esdm_drng_seed_es(struct esdm_drng *drng)
{
	struct entropy_buf seedbuf __aligned(ESDM_KCAPI_ALIGN);
	uint32_t collected_entropy;

	/* This clearing is not strictly needed, but it silences valgrind */
	memset(&seedbuf, 0, sizeof(seedbuf));
	esdm_fill_seed_buffer(&seedbuf,
			      esdm_get_seed_entropy_osr(drng->fully_seeded));

	collected_entropy = esdm_entropy_rate_eb(&seedbuf);
	esdm_drng_inject(drng, (uint8_t *)&seedbuf, sizeof(seedbuf),
			 esdm_fully_seeded(drng->fully_seeded,
					   collected_entropy), "regular");

	/* Set the seeding state of the ESDM */
	esdm_init_ops(&seedbuf);

	memset_secure(&seedbuf, 0, sizeof(seedbuf));

	return collected_entropy;
}

static void esdm_drng_seed(struct esdm_drng *drng)
{
	BUILD_BUG_ON(ESDM_MIN_SEED_ENTROPY_BITS >
		     ESDM_DRNG_SECURITY_STRENGTH_BITS);

	if (esdm_get_available()) {
		/* (Re-)Seed DRNG */
		esdm_drng_seed_es(drng);
		/* (Re-)Seed atomic DRNG from regular DRNG */
		esdm_drng_atomic_seed_drng(drng);
	} else {
		/*
		 * If no-one is waiting for the DRNG, seed the atomic DRNG
		 * directly from the entropy sources.
		 */
		if (!thread_queue_sleeper(&esdm_init_wait))
			esdm_drng_atomic_seed_es();
		else
			esdm_init_ops(NULL);
	}
}

static void esdm_drng_seed_work_one(struct esdm_drng *drng, uint32_t node)
{
	logger(LOGGER_DEBUG, LOGGER_C_DRNG,
	       "reseed triggered by system events for DRNG on node %d\n",
	       node);
	esdm_drng_seed(drng);
	if (drng->fully_seeded) {
		/* Prevent reseed storm */
		drng->last_seeded += node * 60;
	}
}

static void __esdm_drng_seed_work(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();

	if (esdm_drng) {
		uint32_t node;

		for_each_online_node(node) {
			struct esdm_drng *drng = esdm_drng[node];

			if (!drng)
				continue;

			mutex_w_lock(&drng->lock);
			if (drng && !drng->fully_seeded) {
				/* return code does not matter */
				esdm_drng_seed_work_one(drng, node);
				mutex_w_unlock(&drng->lock);
				goto out;
			}
			mutex_w_unlock(&drng->lock);
		}
	} else {
		if (!esdm_drng_init.fully_seeded) {
			mutex_w_lock(&esdm_drng_init.lock);
			esdm_drng_seed_work_one(&esdm_drng_init, 0);
			mutex_w_unlock(&esdm_drng_init.lock);
			goto out;
		}
	}

	esdm_pool_all_nodes_seeded(true);

out:
	esdm_drng_put_instances();
}

void esdm_drng_seed_work(void)
{
	do {
		__esdm_drng_seed_work();
	} while (esdm_es_reseed_wanted());

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

	for_each_online_node(node) {
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
	return (atomic_dec_and_test(&drng->requests) ||
		drng->force_reseed ||
		esdm_time_after_now(drng->last_seeded +
				    esdm_drng_reseed_max_time));
}

/**
 * esdm_drng_get() - Get random data out of the DRNG which is reseeded
 * frequently.
 *
 * @drng: DRNG instance
 * @outbuf: buffer for storing random data
 * @outbuflen: length of outbuf
 * @pr: operate the DRNG with prediction resistance (i.e. reseed from the
 *	entropy sources and only return the amount bytes for which we have
 *	received fresh entropy)
 *
 * @return:
 * * < 0 in error case (DRNG generation or update failed)
 * * >=0 returning the returned number of bytes
 */
static ssize_t esdm_drng_get(struct esdm_drng *drng, uint8_t *outbuf,
			     size_t outbuflen, bool pr)
{
	ssize_t processed = 0;

	if (!outbuf || !outbuflen)
		return 0;

	if (!esdm_get_available())
		return -EOPNOTSUPP;

	outbuflen = min_t(size_t, outbuflen, SSIZE_MAX);

	if (atomic_read_u32(&drng->requests_since_fully_seeded) >
	    esdm_config_drng_max_wo_reseed())
		esdm_unset_fully_seeded(drng);

	while (outbuflen) {
		uint32_t todo = min_t(uint32_t, outbuflen,
				      ESDM_DRNG_MAX_REQSIZE);
		ssize_t ret;

		if (esdm_drng_must_reseed(drng)) {
			if (esdm_pool_trylock()) {
				drng->force_reseed = true;
			} else {
				esdm_drng_seed(drng);
				esdm_pool_unlock();
			}
		}

		mutex_w_lock(&drng->lock);

		/*
		 * Handle the prediction resistance: force a reseed and
		 * only generate the amount of data that was seeded. Note,
		 * esdm_drng_seed_es returns the entropy amount in bits, but
		 * we operate here in bytes.
		 */
		if (pr) {
			uint32_t collected_entropy_bits;

			/* If ESDM is not operational, PR is not possible. */
			if (!esdm_state_operational()) {
				mutex_w_unlock(&drng->lock);
				goto out;
			}

			collected_entropy_bits = esdm_drng_seed_es(drng);

			/* If no new entropy was received, stop now. */
			if (!collected_entropy_bits) {
				mutex_w_unlock(&drng->lock);
				goto out;
			}

			/*
			 * Do not produce more than the amount of entropy
			 * we received.
			 */
			todo = min_t(uint32_t, todo,
				     collected_entropy_bits >> 3);

			/*
			 * Do not produce more than the security strength of
			 * the DRNG - the DRNG can only produce this amount of
			 * entropy. This is a bit more strict than SP800-90A
			 * prediction resistance, but complies with the
			 * German AIS20/31 as well as when using the DRNG as
			 * a conditioning component to chain with other DRNGs.
			 */
			todo = min_t(uint32_t, todo,
				     esdm_security_strength() >> 3);
		}
		ret = drng->drng_cb->drng_generate(drng->drng,
						   outbuf + processed, todo);

		/*
		 * In FIPS mode according to IG 7.19, force a reseed after
		 * generating data as conditioning component.
		 */
		if (pr && esdm_sp80090c_compliant())
			drng->force_reseed = true;

		mutex_w_unlock(&drng->lock);
		if (ret <= 0) {
			logger(LOGGER_WARN, LOGGER_C_DRNG,
			       "getting random data from DRNG failed (%zd)\n",
			       ret);
			return -EFAULT;
		}
		processed += ret;
		outbuflen -= (size_t)ret;

		if (pr && outbuflen) {
			/*
			 * In FIPS mode, be compliant to FIPS IG 7.19, at most
			 * only the security strength bits of data are allowed
			 * to be generated. Thus the processing stops here.
			 */
			if (esdm_sp80090c_compliant())
				goto out;

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
	ssize_t rc;
	int ret;

	if (esdm_drng && esdm_drng[node] && esdm_drng[node]->fully_seeded) {
		logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		       "Using DRNG instance on node %u to service generate request\n",
		       node);
		drng = esdm_drng[node];
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		       "Using DRNG instance on node 0 to service generate request\n");
	}

	ret = esdm_drng_mgr_initalize();
	if (ret)
		return ret;

	rc = esdm_drng_get(drng, outbuf, outbuflen, pr);
	esdm_drng_put_instances();

	return rc;
}

/*
 * Reset ESDM such that all existing entropy is gone.
 *
 * TODO: After this call is invoked, the esdm_init_monitor should be invoked
 * to monitor the ES for new entropy.
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

		for_each_online_node(cpu) {
			struct esdm_drng *drng = esdm_drng[cpu];

			if (!drng)
				continue;
			mutex_w_lock(&drng->lock);
			esdm_drng_reset(drng);
			mutex_w_unlock(&drng->lock);
		}
	}
	esdm_drng_atomic_reset();
	esdm_set_entropy_thresh(ESDM_FULL_SEED_ENTROPY_BITS);

	esdm_reset_state();
	esdm_drng_put_instances();
}

/******************* Generic ESDM kernel output interfaces ********************/

int esdm_drng_sleep_while_nonoperational(int nonblock)
{
	if (esdm_state_operational())
		return 0;
	if (nonblock)
		return -EAGAIN;
	thread_wait_event(&esdm_init_wait, esdm_state_operational());
	return 0;
}

void esdm_drng_sleep_while_non_min_seeded(void)
{
	if (esdm_state_min_seeded())
		return;
	thread_wait_event(&esdm_init_wait, esdm_state_min_seeded());
	return;
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_pr(uint8_t *buf, size_t nbytes)
{
	esdm_drng_sleep_while_nonoperational(0);
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, true);
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
	esdm_drng_sleep_while_non_min_seeded();
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, false);
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes(uint8_t *buf, size_t nbytes)
{
	return esdm_drng_get_sleep(buf, (uint32_t)nbytes, false);
}
