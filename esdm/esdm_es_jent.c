/*
 * ESDM Fast Entropy Source: Jitter RNG
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

#include <jitterentropy.h>

#include "atomic.h"
#include "build_bug_on.h"
#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
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
#define ESDM_IS_POWER_OF_2(n) (BUILD_BUG_ON((n & (n - 1)) != 0))

/* Entropy buffer filled by Jitter RNG thread - must be power of 2 */
#define ESDM_JENT_ENTROPY_BLOCKS_MASK (ESDM_JENT_ENTROPY_BLOCKS - 1)

static struct entropy_es
	esdm_jent_async[ESDM_JENT_ENTROPY_BLOCKS] __aligned(sizeof(uint64_t));

enum esdm_jent_async_state {
	buffer_empty,
	buffer_filling,
	buffer_filled,
	buffer_reading,
};
static volatile enum esdm_jent_async_state
	esdm_jent_async_set[ESDM_JENT_ENTROPY_BLOCKS];

static struct rand_data *esdm_jent_state_thread = NULL;
#endif

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
static void esdm_jent_get(struct rand_data *ec, struct entropy_es *eb_es,
			  uint32_t requested_bits, bool __unused unused)
{
	ssize_t ret;
	uint32_t ent_bits;

	if (!atomic_read(&esdm_jent_initialized))
		goto err;

	if (esdm_config_fips_enabled()) {
		ret = jent_read_entropy(ec, (char *)eb_es->e,
					requested_bits >> 3);
	} else {
		ret = jent_read_entropy_safe(&ec, (char *)eb_es->e,
					     requested_bits >> 3);
	}

	if (ret < 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "Jitter RNG failed with %zd\n", ret);
		goto err;
	}

	ent_bits = esdm_jent_entropylevel((uint32_t)(ret << 3));
	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits of entropy from %ssynchronous Jitter RNG noise source instance\n",
		ent_bits, (ec == esdm_jent_state) ? "" : "a");

	eb_es->e_bits = ent_bits;
	return;

err:
	eb_es->e_bits = 0;
}

#if (ESDM_JENT_ENTROPY_BLOCKS != 0)

static int esdm_jent_async_monitor(void)
{
	unsigned int i, requested_bits = esdm_get_seed_entropy_osr(true);

	if (!esdm_config_es_jent_async_enabled())
		return 0;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Jitter RNG block filling started\n");

	for (i = 0; i < ESDM_JENT_ENTROPY_BLOCKS; i++) {
		if (__sync_val_compare_and_swap(&esdm_jent_async_set[i],
						buffer_empty,
						buffer_filling) != buffer_empty)
			continue;

		/*
		 * Always gather entropy data including
		 * potential oversampling factor.
		 */
		esdm_jent_get(esdm_jent_state_thread, &esdm_jent_async[i],
			      requested_bits, false);

		esdm_jent_async_set[i] = buffer_filled;

		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"Jitter RNG ES monitor: filled slot %u with %u bits of entropy\n",
			i, requested_bits);
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Jitter RNG block filling completed\n");

	return 0;
}

static void esdm_jent_async_get(struct entropy_es *eb_es,
				uint32_t requested_bits, bool __unused unused)
{
	static atomic_t idx = ATOMIC_INIT(-1);
	unsigned int slot;

	(void)requested_bits;

	if (!atomic_read(&esdm_jent_initialized)) {
		eb_es->e_bits = 0;
		return;
	}

	/* ESDM_JENT_ENTROPY_BLOCKS must be a power of 2 */
	ESDM_IS_POWER_OF_2(ESDM_JENT_ENTROPY_BLOCKS);
	slot = ((unsigned int)atomic_inc(&idx)) & ESDM_JENT_ENTROPY_BLOCKS_MASK;

	if (__sync_val_compare_and_swap(&esdm_jent_async_set[slot],
					buffer_filled,
					buffer_reading) != buffer_filled) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "Jitter RNG ES monitor: buffer slot %u exhausted\n",
			    slot);

		mutex_w_lock(&esdm_jent_lock);
		esdm_jent_get(esdm_jent_state, eb_es, requested_bits, unused);
		mutex_w_unlock(&esdm_jent_lock);

		esdm_es_mgr_monitor_wakeup();
		return;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Jitter RNG ES monitor: used slot %u\n", slot);

	memcpy(eb_es->e, esdm_jent_async[slot].e,
	       ESDM_DRNG_INIT_SEED_SIZE_BYTES);
	eb_es->e_bits = esdm_jent_async[slot].e_bits;

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits of entropy from Jitter RNG noise source\n",
		eb_es->e_bits);

	memset_secure(&esdm_jent_async[slot], 0, sizeof(struct entropy_es));

	esdm_jent_async_set[slot] = buffer_empty;

	if (!(slot % (ESDM_JENT_ENTROPY_BLOCKS / 4)) && slot)
		esdm_es_mgr_monitor_wakeup();
}

static void esdm_jent_get_check(struct entropy_es *eb_es,
				uint32_t requested_bits, bool __unused unused)
{
	if (esdm_config_es_jent_async_enabled() &&
	    (requested_bits == esdm_get_seed_entropy_osr(true))) {
		esdm_jent_async_get(eb_es, requested_bits, unused);
	} else {
		mutex_w_lock(&esdm_jent_lock);
		esdm_jent_get(esdm_jent_state, eb_es, requested_bits, unused);
		mutex_w_unlock(&esdm_jent_lock);
	}
}

static int esdm_jent_async_init(void)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < ESDM_JENT_ENTROPY_BLOCKS; i++)
		esdm_jent_async_set[i] = buffer_empty;

	esdm_jent_state_thread = jent_entropy_collector_alloc(0, 0);
	CKNULL(esdm_jent_state_thread, -EFAULT);

out:
	return ret;
}

static void esdm_jent_async_fini(void)
{
	jent_entropy_collector_free(esdm_jent_state_thread);
	esdm_jent_state_thread = NULL;

	/* Reset state */
	memset_secure(esdm_jent_async, 0, sizeof(esdm_jent_async));
}

#else

static void esdm_jent_get_check(struct entropy_es *eb_es,
				uint32_t requested_bits, bool __unused unused)
{
	esdm_jent_get(eb_es, requested_bits, unused);
}

static inline int esdm_jent_async_init(void)
{
	return 0;
}

static inline void esdm_jent_async_fini(void)
{
}

#endif

static void esdm_jent_finalize(void)
{
	if (!atomic_read(&esdm_jent_initialized))
		return;

	atomic_set(&esdm_jent_initialized, 0);
	esdm_es_mgr_monitor_wakeup();

	mutex_w_lock(&esdm_jent_lock);

	esdm_jent_async_fini();

	jent_entropy_collector_free(esdm_jent_state);
	esdm_jent_state = NULL;
	mutex_w_unlock(&esdm_jent_lock);
}

static int esdm_jent_initialize(void)
{
	int ret;

	/* Allow the init function to be called multiple times */
	esdm_jent_finalize();

	mutex_w_init(&esdm_jent_lock, 1, 1);

	CKINT(jent_entropy_init());

	/* Initialize the Jitter RNG after the clocksources are initialized. */
	CKINT(esdm_jent_async_init());

	esdm_jent_state = jent_entropy_collector_alloc(0, 0);
	CKNULL(esdm_jent_state, -EFAULT);

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
		 " Entropy Rate per 256 data bits: %u\n",
		 esdm_jent_poolsize(), jent_version(),
		 esdm_jent_entropylevel(256));
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
	.switch_hash = NULL,
};
