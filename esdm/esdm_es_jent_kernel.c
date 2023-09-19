/*
 * ESDM Fast Entropy Source: Linux jitter-based entropy source
 *
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <kcapi.h>

#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_jent_kernel.h"
#include "helper.h"

static struct kcapi_handle *jent_rng = NULL;

static void esdm_jent_kernel_finalize(void)
{
	if (jent_rng == NULL)
		return;

	kcapi_rng_destroy(jent_rng);
	jent_rng = NULL;
}

static int esdm_jent_kernel_init(void)
{
	int ret;

	/* Allow the init function to be called multiple times */
	esdm_jent_kernel_finalize();

	ret = kcapi_rng_init(&jent_rng, "jitterentropy_rng", 0);
	if (ret != 0) {
		logger(LOGGER_WARN, LOGGER_C_ES,
		       "Disabling kernel-based jitter entropy source as it is not present, error: %s\n",
		       strerror(errno));
		return 0;
	}

	return 0;
}

static uint32_t esdm_jent_kernel_entropylevel(uint32_t requested_bits)
{
	if (jent_rng == NULL)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_jent_kernel_entropy_rate(), requested_bits);
}

static uint32_t esdm_jent_kernel_poolsize(void)
{
	if (jent_rng == NULL)
		return 0;

	return esdm_jent_kernel_entropylevel(esdm_security_strength());
}

static void esdm_jent_kernel_get(struct entropy_es *eb_es,
				 uint32_t requested_bits, bool __unused unsused)
{
	if (jent_rng == NULL)
		goto err;

	if (kcapi_rng_generate(jent_rng, eb_es->e, requested_bits >> 3) < 0)
		goto err;

	eb_es->e_bits = esdm_jent_kernel_entropylevel(requested_bits);
	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "obtained %u bits of entropy from kernel-based jitter RNG entropy source\n",
	       eb_es->e_bits);

	return;

err:
	eb_es->e_bits = 0;
}

static void esdm_jent_kernel_es_state(char *buf, size_t buflen)
{
	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n",
		 esdm_jent_kernel_poolsize(),
		 esdm_jent_kernel_entropylevel(256));
}

static void esdm_jent_kernel_es_state_json(struct json_object *obj)
{
	/* Assume the esdm_drng_init lock is taken by caller */
	json_object_object_add(obj, "avail_entropy", json_object_new_int(esdm_jent_kernel_poolsize()));
	json_object_object_add(obj, "entropy_level", json_object_new_int(esdm_jent_kernel_entropylevel(256)));
}

static bool esdm_jent_kernel_active(void)
{
	return jent_rng != NULL;
}

struct esdm_es_cb esdm_es_jent_kernel = {
	.name = "KernelJitterRNG",
	.init = esdm_jent_kernel_init,
	.fini = esdm_jent_kernel_finalize,
	.monitor_es = NULL,
	.get_ent = esdm_jent_kernel_get,
	.curr_entropy = esdm_jent_kernel_entropylevel,
	.max_entropy = esdm_jent_kernel_poolsize,
	.state = esdm_jent_kernel_es_state,
	.state_json = esdm_jent_kernel_es_state_json,
	.reset = NULL,
	.active = esdm_jent_kernel_active,
	.switch_hash = NULL,
};
