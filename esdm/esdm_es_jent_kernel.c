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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <kcapi.h>

#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_jent_kernel.h"
#include "helper.h"
#include "mutex.h"

static struct kcapi_handle *jent_rng = NULL;
static DEFINE_MUTEX_UNLOCKED(jent_rng_mutex);
/*
 * Override of the name of the kernel crypto API RNG, as given on the command
 * line of the server. NULL means "use the compile-time default
 * ESDM_JENT_KERNEL_NAME". Configuration like the entropy rates: it outlives
 * esdm_fini().
 */
static char *jent_kernel_runtime_name = NULL;
/* Between init and fini - a new name is opened at once then */
static bool jent_kernel_initialized = false;

#if (ESDM_JENT_KERNEL_ENTROPY_BLOCKS != 0)
static struct esdm_es_buf jent_kernel_buf;
static bool jent_kernel_buf_alloced = false;

/*
 * What a block of @requested_bits is credited with at present: the configured
 * rate. Unlike esdm_jent_kernel_entropylevel() it does not ask whether the
 * handle is open now - a block cached before was read from an RNG that
 * delivered.
 */
static uint32_t esdm_jent_kernel_buf_credit(uint32_t requested_bits)
{
	return esdm_fast_noise_entropylevel(
		esdm_config_es_jent_kernel_entropy_rate(), requested_bits);
}
#endif

static bool esdm_jent_kernel_active(void);

/* Caller must hold jent_rng_mutex. */
static const char *esdm_jent_kernel_name_locked(void)
{
	return jent_kernel_runtime_name ? jent_kernel_runtime_name :
					  ESDM_JENT_KERNEL_NAME;
}

static void esdm_jent_kernel_finalize_locked(void)
{
	if (jent_rng == NULL)
		return;

	kcapi_rng_destroy(jent_rng);
	jent_rng = NULL;
}

static void esdm_jent_kernel_finalize(void)
{
	mutex_lock(&jent_rng_mutex);
	esdm_jent_kernel_finalize_locked();
	jent_kernel_initialized = false;
	mutex_unlock(&jent_rng_mutex);

#if (ESDM_JENT_KERNEL_ENTROPY_BLOCKS != 0)
	if (jent_kernel_buf_alloced) {
		esdm_es_buf_free(&jent_kernel_buf);
		jent_kernel_buf_alloced = false;
	}
#endif
}

/*
 * Open the kernel crypto API RNG of the configured name, replacing the handle
 * in use. Caller must hold jent_rng_mutex (write lock).
 *
 * @return 0 on success, a negative errno otherwise
 */
static int esdm_jent_kernel_open_locked(void)
{
	const char *name = esdm_jent_kernel_name_locked();
	int ret;

	esdm_jent_kernel_finalize_locked();

	ret = kcapi_rng_init(&jent_rng, name, 0);
	if (ret != 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling kernel-based jitter entropy source as the kernel RNG %s is not present, error: %s\n",
			name, strerror(errno));
		jent_rng = NULL;
		return ret < 0 ? ret : -ENOENT;
	}

	return 0;
}

static int esdm_jent_kernel_init(void)
{
	mutex_lock(&jent_rng_mutex);

	/* Allow the init function to be called multiple times */
	(void)esdm_jent_kernel_open_locked();
	jent_kernel_initialized = true;

	mutex_unlock(&jent_rng_mutex);

#if (ESDM_JENT_KERNEL_ENTROPY_BLOCKS != 0)
	if (jent_kernel_buf_alloced) {
		esdm_es_buf_reset(&jent_kernel_buf);
	} else if (!esdm_es_buf_alloc(&jent_kernel_buf,
				      ESDM_JENT_KERNEL_ENTROPY_BLOCKS,
				      "KernelJitterRNG",
				      esdm_config_es_jent_kernel_entropy_rate,
				      esdm_jent_kernel_buf_credit)) {
		jent_kernel_buf_alloced = true;
	}
#endif

	return 0;
}

/* Caller must hold jent_rng_mutex. */
static uint32_t esdm_jent_kernel_entropylevel_locked(uint32_t requested_bits)
{
	if (jent_rng == NULL)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_jent_kernel_entropy_rate(), requested_bits);
}

static uint32_t esdm_jent_kernel_entropylevel(uint32_t requested_bits)
{
	uint32_t ret;

	mutex_reader_lock(&jent_rng_mutex);
	ret = esdm_jent_kernel_entropylevel_locked(requested_bits);
	mutex_reader_unlock(&jent_rng_mutex);

	return ret;
}

static uint32_t esdm_jent_kernel_poolsize(void)
{
	uint32_t ret;

	mutex_reader_lock(&jent_rng_mutex);
	ret = esdm_jent_kernel_entropylevel_locked(esdm_security_strength());
	mutex_reader_unlock(&jent_rng_mutex);

	return ret;
}

/*
 * Use an exclusive lock: the underlying kcapi handle wraps a single AF_ALG
 * socket and is not safe for concurrent kcapi_rng_generate() calls. The async
 * monitor and a synchronous consumer fallback must serialise through this
 * lock.
 */
static void esdm_jent_kernel_get_sync(struct entropy_es *eb_es,
				      uint32_t requested_bits)
{
	mutex_lock(&jent_rng_mutex);

	if (jent_rng == NULL)
		goto err;

	/*
	 * kcapi_rng_generate() returns the number of bytes produced: the full
	 * length on success, a negative errno on error, or 0 if the AF_ALG
	 * recv() hits EOF (e.g. the kernel jitterentropy_rng socket was torn
	 * down). Insist on the full length so a short/zero read can never leave
	 * eb_es->e (partly) uninitialized while still being credited the full
	 * requested entropy below.
	 */
	if (kcapi_rng_generate(jent_rng, eb_es->e, requested_bits >> 3) !=
	    (ssize_t)(requested_bits >> 3))
		goto err;

	eb_es->e_bits = esdm_jent_kernel_entropylevel_locked(requested_bits);
	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits of entropy from kernel-based jitter RNG entropy source\n",
		eb_es->e_bits);

	mutex_unlock(&jent_rng_mutex);

	return;

err:
	mutex_unlock(&jent_rng_mutex);
	eb_es->e_bits = 0;
}

#if (ESDM_JENT_KERNEL_ENTROPY_BLOCKS != 0)

static void esdm_jent_kernel_buf_fill(struct entropy_es *eb_es,
				      uint32_t requested_bits, void *ctx)
{
	(void)ctx;
	esdm_jent_kernel_get_sync(eb_es, requested_bits);
}

static int esdm_jent_kernel_monitor(void)
{
	uint32_t requested_bits = esdm_get_seed_entropy_osr(false, true);

	if (!esdm_jent_kernel_active())
		return 0;

	return esdm_es_buf_monitor(&jent_kernel_buf, requested_bits,
				   esdm_jent_kernel_buf_fill, NULL);
}

/* A block of the cache only, see struct esdm_es_cb.get_cached */
static bool esdm_jent_kernel_get_cached(struct entropy_es *eb_es,
					uint32_t requested_bits)
{
	return esdm_es_buf_try_get(&jent_kernel_buf, eb_es, requested_bits,
				   !!esdm_config_es_jent_kernel_entropy_rate());
}

static void esdm_jent_kernel_get(struct entropy_es *eb_es,
				 uint32_t requested_bits, bool allow_cached)
{
	if (allow_cached && esdm_jent_kernel_get_cached(eb_es, requested_bits))
		return;

	esdm_jent_kernel_get_sync(eb_es, requested_bits);
}

#else /* ESDM_JENT_KERNEL_ENTROPY_BLOCKS == 0 */

static void esdm_jent_kernel_get(struct entropy_es *eb_es,
				 uint32_t requested_bits,
				 bool __unused allow_cached)
{
	esdm_jent_kernel_get_sync(eb_es, requested_bits);
}

#endif

static void esdm_jent_kernel_es_state(char *buf, size_t buflen)
{
	uint32_t poolsize, entropy_rate;
	/* Copied, as a new name frees the old one */
	char name[CRYPTO_MAX_ALG_NAME_ESDM];

	mutex_reader_lock(&jent_rng_mutex);
	poolsize =
		esdm_jent_kernel_entropylevel_locked(esdm_security_strength());
	entropy_rate = esdm_jent_kernel_entropylevel_locked(256);
	snprintf(name, sizeof(name), "%s", esdm_jent_kernel_name_locked());
	mutex_reader_unlock(&jent_rng_mutex);

	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n"
		 " Kernel RNG: %s\n",
		 poolsize, entropy_rate, name);
}

static bool esdm_jent_kernel_active(void)
{
	bool ret;

	mutex_reader_lock(&jent_rng_mutex);
	ret = jent_rng != NULL;
	mutex_reader_unlock(&jent_rng_mutex);

	return ret;
}

/*
 * Read from the kernel's jitterentropy RNG and require two different answers.
 */
static int esdm_jent_kernel_selftest(void)
{
	uint8_t first[16], second[16];
	int ret = 0;

	mutex_lock(&jent_rng_mutex);

	if (jent_rng == NULL) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"KernelJitterRNG ES: not initialized - nothing to test\n");
		goto out;
	}

	if (kcapi_rng_generate(jent_rng, first, sizeof(first)) !=
		    (ssize_t)sizeof(first) ||
	    kcapi_rng_generate(jent_rng, second, sizeof(second)) !=
		    (ssize_t)sizeof(second)) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"KernelJitterRNG ES: the kernel jitterentropy RNG did not deliver\n");
		ret = -EFAULT;
		goto out;
	}

	if (!memcmp(first, second, sizeof(first))) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"KernelJitterRNG ES: the kernel jitterentropy RNG repeated its output\n");
		ret = -EFAULT;
	}

out:
	mutex_unlock(&jent_rng_mutex);
	memset_secure(first, 0, sizeof(first));
	memset_secure(second, 0, sizeof(second));

	return ret;
}

DSO_PUBLIC
int esdm_es_jent_kernel_set_name(const char *name)
{
	char *new_copy = NULL;
	char *old;
	bool reopened;
	int ret = 0;

	if (!name || strlen(name) >= CRYPTO_MAX_ALG_NAME_ESDM)
		return -EINVAL;

	if (name[0] != '\0') {
		new_copy = strdup(name);
		if (!new_copy)
			return -ENOMEM;
	}

	mutex_lock(&jent_rng_mutex);

	old = jent_kernel_runtime_name;
	jent_kernel_runtime_name = new_copy;

	/*
	 * Set before esdm_init(), as the server does, the RNG is opened by the
	 * init of the source. Once the source runs, it is replaced right away.
	 */
	reopened = jent_kernel_initialized;
	if (reopened)
		ret = esdm_jent_kernel_open_locked();

	mutex_unlock(&jent_rng_mutex);

#if (ESDM_JENT_KERNEL_ENTROPY_BLOCKS != 0)
	/* What the old RNG delivered is not credited for the new one */
	if (reopened && jent_kernel_buf_alloced)
		esdm_es_buf_reset(&jent_kernel_buf);
#endif

	free(old);

	return ret;
}

struct esdm_es_cb esdm_es_jent_kernel = {
	.name = "KernelJitterRNG",
	.init = esdm_jent_kernel_init,
	.fini = esdm_jent_kernel_finalize,
#if (ESDM_JENT_KERNEL_ENTROPY_BLOCKS != 0)
	.monitor_es = esdm_jent_kernel_monitor,
#else
	.monitor_es = NULL,
#endif
	.get_ent = esdm_jent_kernel_get,
#if (ESDM_JENT_KERNEL_ENTROPY_BLOCKS != 0)
	.get_cached = esdm_jent_kernel_get_cached,
#endif
	.curr_entropy = esdm_jent_kernel_entropylevel,
	.max_entropy = esdm_jent_kernel_poolsize,
	.state = esdm_jent_kernel_es_state,
	.reset = NULL,
	.active = esdm_jent_kernel_active,
	.selftest = esdm_jent_kernel_selftest,
};
