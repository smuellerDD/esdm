/*
 * ESDM Fast Entropy Source: Jitter RNG
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

#include <jitterentropy.h>

#include "atomic.h"
#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_jent.h"
#include "logger.h"
#include "mutex_w.h"

static DEFINE_MUTEX_W_UNLOCKED(esdm_jent_lock);

static atomic_t esdm_jent_initialized = ATOMIC_INIT(0);
static struct rand_data *esdm_jent_state;

static int esdm_jent_initialize(void)
{
	mutex_w_lock(&esdm_jent_lock);

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
	logger(LOGGER_DEBUG, LOGGER_C_ES, "Jitter RNG working on current system\n");

	/* Do not trigger a reseed if the DRNG manger is not available */
	if (!esdm_get_available())
		return 0;

	esdm_drng_force_reseed();
	if (esdm_config_es_jent_entropy_rate())
		esdm_es_add_entropy();

	return 0;
}

static void esdm_jent_finalize(void)
{
	if (!atomic_read(&esdm_jent_initialized))
		return;

	atomic_set(&esdm_jent_initialized, 0);

	mutex_w_lock(&esdm_jent_lock);
	jent_entropy_collector_free(esdm_jent_state);
	esdm_jent_state = NULL;
	mutex_w_unlock(&esdm_jent_lock);
}

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

	ret = jent_read_entropy_safe(&esdm_jent_state, (char *)eb_es->e,
				     requested_bits >> 3);
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

static void esdm_jent_es_state(char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Library version: %u\n",
		 esdm_jent_poolsize(),
		 jent_version());
}

struct esdm_es_cb esdm_es_jent = {
	.name			= "JitterRNG",
	.init			= esdm_jent_initialize,
	.fini			= esdm_jent_finalize,
	.get_ent		= esdm_jent_get,
	.curr_entropy		= esdm_jent_entropylevel,
	.max_entropy		= esdm_jent_poolsize,
	.state			= esdm_jent_es_state,
	.reset			= NULL,
	.switch_hash		= NULL,
};
