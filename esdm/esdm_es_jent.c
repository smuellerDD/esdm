/*
 * ESDM Fast Entropy Source: Jitter RNG
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

#include <jitterentropy.h>

#include "atomic.h"
#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_jent.h"
#include "helper.h"
#include "logger.h"
#include "mutex_w.h"
#include "queue.h"
#include "threading_support.h"

static DEFINE_MUTEX_W_UNLOCKED(esdm_jent_lock);

static atomic_t esdm_jent_initialized = ATOMIC_INIT(0);
static struct rand_data *esdm_jent_state = NULL;

/* Entropy buffer filled by Jitter RNG thread - must be power of 2 */
#define ESDM_JENT_ENTROPY_BLOCKS	128
#define ESDM_JENT_ENTROPY_BLOCKS_MASK	(ESDM_JENT_ENTROPY_BLOCKS - 1)
static struct entropy_es
esdm_jent_entropy_buffer[ESDM_JENT_ENTROPY_BLOCKS] __aligned(sizeof(uint64_t));
static atomic_t esdm_jent_entropy_buffer_reader = ATOMIC_INIT(0);
static atomic_t esdm_jent_entropy_buffer_writer = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE(esdm_jent_entropy_buffer_wait);

static bool esdm_jent_entropy_buffer_enable = false;

static uint32_t esdm_jent_entropylevel(uint32_t requested_bits)
{
	return esdm_fast_noise_entropylevel(
		atomic_read(&esdm_jent_initialized) ?
		esdm_config_es_jent_entropy_rate() : 0, requested_bits);
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
static void esdm_jent_get(struct entropy_es *eb_es, uint32_t requested_bits,
			  bool __unused unused)
{
	ssize_t ret;
	uint32_t ent_bits;

	mutex_w_lock(&esdm_jent_lock);

	if (!atomic_read(&esdm_jent_initialized)) {
		mutex_w_unlock(&esdm_jent_lock);
		goto err;
	}

	if (esdm_config_fips_enabled()) {
		ret = jent_read_entropy(esdm_jent_state, (char *)eb_es->e,
					requested_bits >> 3);
	} else {
		ret = jent_read_entropy_safe(&esdm_jent_state, (char *)eb_es->e,
					     requested_bits >> 3);
	}
	mutex_w_unlock(&esdm_jent_lock);

	if (ret < 0) {
		logger(LOGGER_DEBUG, LOGGER_C_ES,
		       "Jitter RNG failed with %zd\n", ret);
		goto err;
	}

	ent_bits = esdm_jent_entropylevel((uint32_t)(ret << 3));
	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "obtained %u bits of entropy from Jitter RNG noise source\n",
	       ent_bits);

	eb_es->e_bits = ent_bits;
	return;

err:
	eb_es->e_bits = 0;
}

static int esdm_jent_entropy_buffer_monitor(void __unused *unused)
{
	thread_set_name(es_jent_collector, 0);

	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "Jitter RNG starting monitor thread\n");

	while (atomic_read(&esdm_jent_initialized)) {
		uint32_t reader =
			atomic_read_u32(&esdm_jent_entropy_buffer_reader);
		uint32_t writer =
			atomic_read_u32(&esdm_jent_entropy_buffer_writer);
		uint32_t avail_slots = (writer >= reader) ?
				       (writer - reader) :
				       (0 - reader + writer);

		if (avail_slots < (ESDM_JENT_ENTROPY_BLOCKS / 2)) {
			unsigned int i, curr_slot;

			avail_slots = min_uint32(avail_slots,
						 ESDM_JENT_ENTROPY_BLOCKS);

			for (i = 0;
			     i < ESDM_JENT_ENTROPY_BLOCKS - avail_slots;
			     i++) {
				curr_slot = (writer + i) &
					    ESDM_JENT_ENTROPY_BLOCKS_MASK;

				/*
				 * Always gather entropy data including
				 * potential oversampling factor.
				 */
				esdm_jent_get(
					&esdm_jent_entropy_buffer[curr_slot],
					esdm_get_seed_entropy_osr(false) >> 3,
					false);

				logger(LOGGER_DEBUG, LOGGER_C_ES,
				       "Jitter RNG ES monitor: filled slot %u\n",
				       curr_slot);

				atomic_inc(&esdm_jent_entropy_buffer_writer);
			}
		}

		thread_wait_no_event(&esdm_jent_entropy_buffer_wait);
	}

	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "Jitter RNG terminating monitor thread\n");

	/* Reset state */
	atomic_set(&esdm_jent_entropy_buffer_reader, 0);
	atomic_set(&esdm_jent_entropy_buffer_writer, 0);
	memset_secure(esdm_jent_entropy_buffer, 0,
		      sizeof(esdm_jent_entropy_buffer));

	return 0;
}

static void esdm_jent_entropy_buffer_get(struct entropy_es *eb_es,
					 uint32_t requested_bits,
					 bool __unused unused)
{
	uint32_t reader =
			(uint32_t)atomic_inc(&esdm_jent_entropy_buffer_reader);
	uint32_t writer = atomic_read_u32(&esdm_jent_entropy_buffer_writer);
	uint32_t delta = (writer >= reader) ? (writer - reader) :
					      (0 - reader + writer);

	if (delta > ESDM_JENT_ENTROPY_BLOCKS) {
		atomic_dec(&esdm_jent_entropy_buffer_reader);
		esdm_jent_get(eb_es, requested_bits, unused);
	} else {
		reader &= ESDM_JENT_ENTROPY_BLOCKS_MASK;
		logger(LOGGER_DEBUG, LOGGER_C_ES,
		       "Jitter RNG ES monitor: used slot %u\n", reader);
		memcpy(eb_es->e, esdm_jent_entropy_buffer[reader].e,
		       ESDM_DRNG_INIT_SEED_SIZE_BYTES);
		eb_es->e_bits = esdm_jent_entropy_buffer[reader].e_bits;
		memset_secure(&esdm_jent_entropy_buffer[reader], 0,
			      sizeof(struct entropy_es));
	}
	thread_wake_all(&esdm_jent_entropy_buffer_wait);
}

static void esdm_jent_get_check(struct entropy_es *eb_es,
				uint32_t requested_bits, bool __unused unused)
{
	if (esdm_jent_entropy_buffer_enable) {
		esdm_jent_entropy_buffer_get(eb_es, requested_bits, unused);
	} else {
		esdm_jent_get(eb_es, requested_bits, unused);
	}
}

static void esdm_jent_finalize(void)
{
	if (!atomic_read(&esdm_jent_initialized))
		return;

	atomic_set(&esdm_jent_initialized, 0);
	thread_wake_all(&esdm_jent_entropy_buffer_wait);

	mutex_w_lock(&esdm_jent_lock);
	jent_entropy_collector_free(esdm_jent_state);
	esdm_jent_state = NULL;
	mutex_w_unlock(&esdm_jent_lock);
}

static int esdm_jent_initialize(void)
{
	/* Allow the init function to be called multiple times */
	esdm_jent_finalize();

	mutex_w_init(&esdm_jent_lock, 1, 1);

	/* Initialize the Jitter RNG after the clocksources are initialized. */
	if (jent_entropy_init() ||
	    (esdm_jent_state = jent_entropy_collector_alloc(0, 0)) == NULL) {
		esdm_config_es_jent_entropy_rate_set(0);
		mutex_w_unlock(&esdm_jent_lock);
		logger(LOGGER_WARN, LOGGER_C_ES,
		       "Jitter RNG unusable on current system\n");
		return -EFAULT;
	}
	atomic_set(&esdm_jent_initialized, 1);
	mutex_w_unlock(&esdm_jent_lock);
	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "Jitter RNG working on current system\n");

	if (esdm_jent_entropy_buffer_enable) {
		int ret = thread_start(esdm_jent_entropy_buffer_monitor, NULL,
				       ESDM_THREAD_JITTER_RNG_MONITOR_GROUP,
				       NULL);

		if (ret) {
			logger(LOGGER_WARN, LOGGER_C_ES,
			       "Jitter RNG ES monitor: failed to start: %d\n",
			       ret);
		}
	}

	/* Do not trigger a reseed if the DRNG manger is not available */
	if (!esdm_get_available())
		return 0;

	return 0;
}

static void esdm_jent_es_state(char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Library version: %u\n",
		 esdm_jent_poolsize(),
		 jent_version());
}

static bool esdm_jent_active(void)
{
	return (esdm_jent_state != NULL);
}

struct esdm_es_cb esdm_es_jent = {
	.name			= "JitterRNG",
	.init			= esdm_jent_initialize,
	.fini			= esdm_jent_finalize,
	.monitor_es		= NULL,
	.get_ent		= esdm_jent_get_check,
	.curr_entropy		= esdm_jent_entropylevel,
	.max_entropy		= esdm_jent_poolsize,
	.state			= esdm_jent_es_state,
	.reset			= NULL,
	.active			= esdm_jent_active,
	.switch_hash		= NULL,
};
