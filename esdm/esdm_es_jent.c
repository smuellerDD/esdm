/*
 * ESDM Fast Entropy Source: Jitter RNG
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

#include <jitterentropy.h>
#include <stdio.h>

#include "atomic.h"
#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_jent.h"
#include "esdm_es_mgr.h"
#include "helper.h"
#include "esdm_logger.h"
#include "ret_checkers.h"

/*
 * This lock shall prevent a deallocation of the ESDM while a Jitter RNG
 * operation is ongoing. This lock, however, is not needed when the Jitter
 * RNG is called in monitor context, i.e. from esdm_jent_async_monitor
 * as the monitor is immediately killed when a termination signal arrives.
 * Thus, the lock only needs to be held for the synchronous case where
 * a signal handler operates.
 */
static DEFINE_MUTEX_W_UNLOCKED(esdm_jent_lock);

static atomic_t esdm_jent_initialized = ATOMIC_INIT(0);
static struct rand_data *esdm_jent_state = NULL;

#if (ESDM_JENT_ENTROPY_BLOCKS != 0)
static struct esdm_es_buf esdm_jent_buf;
static struct rand_data *esdm_jent_state_thread = NULL;
/*
 * Whether the async cache/collector are allocated. The async cache and the
 * async collector are read lock-free by the monitor thread (producer) and by
 * esdm_es_buf_try_get() (consumers), so they must NOT be freed/reallocated on
 * the reinit path while those readers can still run - that would be a
 * use-after-free. They are allocated once, reset in place on reinit, and freed
 * only in esdm_jent_finalize() (the .fini callback), which the ES manager
 * invokes after it has joined the monitor thread.
 */
static bool esdm_jent_async_alloced = false;
#endif

int esdm_jent_status(char *buf, size_t buf_length)
{
	int ret = -ENOENT;

#if JENT_VERSION >= 3070000
	mutex_w_lock(&esdm_jent_lock);
	if (atomic_read(&esdm_jent_initialized) && esdm_jent_state) {
		ret = jent_status(esdm_jent_state, buf, buf_length);
	} else {
		ret = -EAGAIN;
	}
	mutex_w_unlock(&esdm_jent_lock);
#else
	snprintf(buf, buf_length, "{}");
#endif

	return ret;
}

bool esdm_jent_ntg1(void)
{
#if JENT_VERSION >= 3070000
	const bool jent_secure_memory = jent_secure_memory_supported();
#ifdef ESDM_JENT_NTG1
	const bool jent_ntg1 = true;
#else
	const bool jent_ntg1 = false;
#endif
#else
	const bool jent_secure_memory = false;
	const bool jent_ntg1 = false;
#endif

	return jent_secure_memory && jent_ntg1;
}

static uint32_t esdm_jent_entropylevel(uint32_t requested_bits)
{
	return esdm_fast_noise_entropylevel(
		atomic_read(&esdm_jent_initialized) ?
			esdm_config_es_jent_entropy_rate() :
			0,
		requested_bits);
}

static uint32_t esdm_jent_poolsize(void)
{
	return esdm_jent_entropylevel(esdm_security_strength());
}

/*
 * esdm_get_jent() - Get Jitter RNG entropy
 *
 * @eb: entropy buffer to store entropy
 * @requested_bits: requested entropy in bits
 */
static void esdm_jent_get(struct rand_data **ec, struct entropy_es *eb_es,
			  uint32_t requested_bits, bool __unused unused)
{
	ssize_t ret;
	uint32_t ent_bits;

	if (!atomic_read(&esdm_jent_initialized))
		goto err;

	ret = jent_read_entropy_safe(ec, (char *)eb_es->e, requested_bits >> 3);

	if (ret < 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "Jitter RNG failed with %zd\n", ret);
		goto err;
	}

	ent_bits = esdm_jent_entropylevel((uint32_t)(ret << 3));
	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits of entropy from %ssynchronous Jitter RNG noise source instance\n",
		ent_bits, (*ec == esdm_jent_state) ? "" : "a");

	eb_es->e_bits = ent_bits;
	return;

err:
	eb_es->e_bits = 0;
}

#if (ESDM_JENT_ENTROPY_BLOCKS != 0)

static void esdm_jent_buf_fill(struct entropy_es *eb_es,
			       uint32_t requested_bits, void *ctx)
{
	(void)ctx;
	esdm_jent_get(&esdm_jent_state_thread, eb_es, requested_bits, false);
}

static int esdm_jent_async_monitor(void)
{
	uint32_t requested_bits = esdm_get_seed_entropy_osr(false, true);

	if (!esdm_config_es_jent_async_enabled())
		return 0;

	return esdm_es_buf_monitor(&esdm_jent_buf, requested_bits,
				   esdm_jent_buf_fill, NULL);
}

static void esdm_jent_get_check(struct entropy_es *eb_es,
				uint32_t requested_bits, bool __unused unused)
{
	/*
	 * Serve small requests without initial oversampling from the async
	 * cache; fall back to the synchronous Jitter RNG instance on miss or
	 * when the request is too large for a single cached block.
	 */
	if (esdm_config_es_jent_async_enabled() &&
	    esdm_es_buf_try_get(&esdm_jent_buf, eb_es, requested_bits))
		return;

	mutex_w_lock(&esdm_jent_lock);
	esdm_jent_get(&esdm_jent_state, eb_es, requested_bits, unused);
	mutex_w_unlock(&esdm_jent_lock);
}

static int esdm_jent_async_init(unsigned int osr, unsigned int flags)
{
	int ret = 0;

	/*
	 * When the asynchronous Jitter RNG block collection is disabled (e.g.
	 * the server's small-memory mode or --jent_block_disable), this second
	 * collector instance and its block cache are never consumed - the
	 * synchronous esdm_jent_state serves every request. Skip the allocation
	 * to save a full Jitter RNG collector plus the ESDM_JENT_ENTROPY_BLOCKS
	 * sized cache. esdm_jent_get_check() and esdm_jent_async_monitor()
	 * already gate on esdm_config_es_jent_async_enabled() and
	 * esdm_es_buf_try_get() tolerates the unallocated (NULL) buffer, so a
	 * later runtime re-enable simply keeps using the synchronous path.
	 */
	if (!esdm_config_es_jent_async_enabled())
		return 0;

	/*
	 * On a repeated init (reinit) reuse the existing collector and only
	 * reset the cache in place: the monitor and lock-free consumers may
	 * still be reading them, so they must not be freed/reallocated here (see
	 * the esdm_jent_async_alloced comment). A reinit that changes the jent
	 * flags therefore keeps the previously selected async collector flags;
	 * the synchronous collector (re-created below under the lock) reflects
	 * the new flags. This safety-over-exotic-reconfig tradeoff matches the
	 * reset-on-reinit handling of the TPM2/PKCS11 caches.
	 */
	if (esdm_jent_async_alloced) {
		esdm_es_buf_reset(&esdm_jent_buf);
		return 0;
	}

	CKINT(esdm_es_buf_alloc(&esdm_jent_buf, ESDM_JENT_ENTROPY_BLOCKS,
				"JitterRNG"));

	esdm_jent_state_thread = jent_entropy_collector_alloc(osr, flags);
	CKNULL(esdm_jent_state_thread, -EFAULT);

	esdm_jent_async_alloced = true;

out:
	return ret;
}

static void esdm_jent_async_fini(void)
{
	jent_entropy_collector_free(esdm_jent_state_thread);
	esdm_jent_state_thread = NULL;

	esdm_es_buf_free(&esdm_jent_buf);
	esdm_jent_async_alloced = false;
}

#else

static void esdm_jent_get_check(struct entropy_es *eb_es,
				uint32_t requested_bits, bool __unused unused)
{
	mutex_w_lock(&esdm_jent_lock);
	esdm_jent_get(&esdm_jent_state, eb_es, requested_bits, unused);
	mutex_w_unlock(&esdm_jent_lock);
}

static inline int esdm_jent_async_init(unsigned int osr, unsigned int flags)
{
	(void)osr;
	(void)flags;

	return 0;
}

static inline void esdm_jent_async_fini(void)
{
}

#endif

/*
 * Tear down the Jitter RNG ES. free_async selects whether the async cache and
 * its collector are freed too:
 *   - true  (.fini / shutdown): the ES manager has already joined the monitor
 *            thread, so freeing the lock-free-accessed async objects is safe.
 *   - false (reinit, from esdm_jent_initialize): the monitor and consumers may
 *            still run, so the async cache/collector are left allocated (reset
 *            in place by the subsequent esdm_jent_async_init) and only the
 *            synchronous collector - which is accessed solely under
 *            esdm_jent_lock - is freed here.
 */
static void esdm_jent_finalize_internal(bool free_async)
{
	if (!atomic_read(&esdm_jent_initialized))
		return;

	atomic_set(&esdm_jent_initialized, 0);
	esdm_es_mgr_monitor_wakeup();

	mutex_w_lock(&esdm_jent_lock);

	if (free_async)
		esdm_jent_async_fini();

	jent_entropy_collector_free(esdm_jent_state);
	esdm_jent_state = NULL;
	mutex_w_unlock(&esdm_jent_lock);
}

static void esdm_jent_finalize(void)
{
	esdm_jent_finalize_internal(true);
}

static int esdm_jent_initialize(void)
{
	unsigned int flags = 0;
	int ret;

	/*
	 * Allow the init function to be called multiple times. Use the
	 * async-preserving teardown: on reinit the monitor thread is NOT joined
	 * (unlike shutdown), so the async cache/collector must be reset in place
	 * rather than freed under the lock-free monitor/consumer readers.
	 */
	esdm_jent_finalize_internal(false);

	/*
	 * esdm_jent_lock is statically initialized (DEFINE_MUTEX_W_UNLOCKED) and
	 * left unlocked by esdm_jent_finalize() above, so just acquire it.
	 * Re-running mutex_w_init() here on the already-initialized mutex (the
	 * reinit path) is undefined behaviour and leaks the mutexattr.
	 */
	mutex_w_lock(&esdm_jent_lock);

	if (esdm_config_sp80090c_compliant() || esdm_config_fips_enabled() ||
	    esdm_ntg1_2024_compliant()) {
		flags |= JENT_FORCE_FIPS;
	}

#if JENT_VERSION >= 3070000
	if (esdm_jent_ntg1()) {
		flags |= JENT_NTG1;
	}

	switch (ESDM_JENT_MAX_MEM) {
	case 1:
		flags |= JENT_MAX_MEMSIZE_1kB;
		break;
	case 2:
		flags |= JENT_MAX_MEMSIZE_2kB;
		break;
	case 3:
		flags |= JENT_MAX_MEMSIZE_4kB;
		break;
	case 4:
		flags |= JENT_MAX_MEMSIZE_8kB;
		break;
	case 5:
		flags |= JENT_MAX_MEMSIZE_16kB;
		break;
	case 6:
		flags |= JENT_MAX_MEMSIZE_32kB;
		break;
	case 7:
		flags |= JENT_MAX_MEMSIZE_64kB;
		break;
	case 8:
		flags |= JENT_MAX_MEMSIZE_128kB;
		break;
	case 9:
		flags |= JENT_MAX_MEMSIZE_256kB;
		break;
	case 10:
		flags |= JENT_MAX_MEMSIZE_512kB;
		break;
	case 11:
		flags |= JENT_MAX_MEMSIZE_1MB;
		break;
	case 12:
		flags |= JENT_MAX_MEMSIZE_2MB;
		break;
	case 13:
		flags |= JENT_MAX_MEMSIZE_4MB;
		break;
	case 14:
		flags |= JENT_MAX_MEMSIZE_8MB;
		break;
	case 15:
		flags |= JENT_MAX_MEMSIZE_16MB;
		break;
	case 16:
		flags |= JENT_MAX_MEMSIZE_32MB;
		break;
	case 17:
		flags |= JENT_MAX_MEMSIZE_64MB;
		break;
	case 18:
		flags |= JENT_MAX_MEMSIZE_128MB;
		break;
	case 19:
		flags |= JENT_MAX_MEMSIZE_256MB;
		break;
	case 20:
		flags |= JENT_MAX_MEMSIZE_512MB;
		break;
	}

	switch (ESDM_JENT_HASH_LOOP_COUNT) {
	case 0:
		flags |= JENT_HASHLOOP_1;
		break;
	case 1:
		flags |= JENT_HASHLOOP_2;
		break;
	case 2:
		flags |= JENT_HASHLOOP_4;
		break;
	case 3:
		flags |= JENT_HASHLOOP_8;
		break;
	case 4:
		flags |= JENT_HASHLOOP_16;
		break;
	case 5:
		flags |= JENT_HASHLOOP_32;
		break;
	case 6:
		flags |= JENT_HASHLOOP_64;
		break;
	case 7:
		flags |= JENT_HASHLOOP_128;
		break;
	}
#endif /* JENT_VERSION >= 3070000 */

	CKINT(jent_entropy_init_ex(ESDM_JENT_OSR, flags));

	/* Initialize the Jitter RNG after the clocksources are initialized. */
	CKINT(esdm_jent_async_init(ESDM_JENT_OSR, flags));

	esdm_jent_state = jent_entropy_collector_alloc(ESDM_JENT_OSR, flags);
	if (!esdm_jent_state) {
		esdm_jent_async_fini();
		ret = -EFAULT;
		goto out;
	}

	atomic_set(&esdm_jent_initialized, 1);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Jitter RNG working on current system\n");

out:
	mutex_w_unlock(&esdm_jent_lock);

	if (ret) {
		esdm_config_es_jent_entropy_rate_set(0);
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "Jitter RNG unusable on current system\n");
	}

	return ret;
}

static void esdm_jent_es_state(char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Library version: %u\n"
		 " Standards compliance: %s%s\n"
		 " Entropy Rate per 256 data bits: %u\n"
		 " Oversampling Rate: %u\n",
		 esdm_jent_poolsize(), jent_version(),
		 (esdm_sp80090c_compliant() || esdm_config_fips_enabled() ||
		  esdm_ntg1_2024_compliant() || esdm_jent_ntg1()) ?
			 "SP800-90B " :
			 "",
		 esdm_jent_ntg1() ? "NTG.1(2024)" : "",
		 esdm_jent_entropylevel(256), ESDM_JENT_OSR);
}

static bool esdm_jent_active(void)
{
	return (esdm_jent_state != NULL);
}

struct esdm_es_cb esdm_es_jent = {
	.name = "JitterRNG",
	.init = esdm_jent_initialize,
	.fini = esdm_jent_finalize,
#if (ESDM_JENT_ENTROPY_BLOCKS != 0)
	.monitor_es = esdm_jent_async_monitor,
#else
	.monitor_es = NULL,
#endif
	.get_ent = esdm_jent_get_check,
	.curr_entropy = esdm_jent_entropylevel,
	.max_entropy = esdm_jent_poolsize,
	.state = esdm_jent_es_state,
	.reset = NULL,
	.active = esdm_jent_active,
};
