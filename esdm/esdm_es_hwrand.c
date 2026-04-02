/*
 * ESDM Fast Entropy Source: Linux /dev/hwrng-based entropy source
 *
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "esdm_config.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_hwrand.h"
#include "esdm_node.h"
#include "helper.h"
#include "mutex.h"

#define ESDM_ES_HWRAND_AVAIL "/sys/devices/virtual/misc/hw_random/rng_available"
#define ESDM_ES_HWRAND_IF "/dev/hwrng"

static int esdm_hwrand_fd = -1;
static DEFINE_MUTEX_UNLOCKED(hwrand_mutex);

/* Caller must hold hwrand_mutex (write lock). */
static void esdm_hwrand_finalize_locked(void)
{
	if (esdm_hwrand_fd >= 0)
		close(esdm_hwrand_fd);
	esdm_hwrand_fd = -1;
}

static void esdm_hwrand_finalize(void)
{
	mutex_lock(&hwrand_mutex);
	esdm_hwrand_finalize_locked();
	mutex_unlock(&hwrand_mutex);
}

static int esdm_hwrand_init(void)
{
	char buf[1];
	size_t buflen = 1;
	int fd;

	mutex_lock(&hwrand_mutex);

	/* Allow the init function to be called multiple times */
	esdm_hwrand_finalize_locked();

	esdm_hwrand_fd = open(ESDM_ES_HWRAND_IF, O_RDONLY | O_CLOEXEC);
	if (esdm_hwrand_fd < 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling /dev/hwrng-based entropy source as device not present, error opening %s: %s\n",
			ESDM_ES_HWRAND_IF, strerror(errno));
		mutex_unlock(&hwrand_mutex);
		return 0;
	}

	/* Check the presence of RNG-providers */
	fd = open(ESDM_ES_HWRAND_AVAIL, O_RDONLY);
	if (fd >= 0) {
		if (esdm_safe_read(fd, (uint8_t *)buf, buflen) != (ssize_t)buflen &&
		    buf[0] == '\n') {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"Disabling /dev/hwrng-based entropy source as it has no backing device\n");
			close(esdm_hwrand_fd);
			esdm_hwrand_fd = -1;
		}
		close(fd);
	}

	mutex_unlock(&hwrand_mutex);

	return 0;
}

/* Caller must hold hwrand_mutex. */
static uint32_t esdm_hwrand_entropylevel_locked(uint32_t requested_bits)
{
	if (esdm_hwrand_fd < 0)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_hwrand_entropy_rate(), requested_bits);
}

static uint32_t esdm_hwrand_entropylevel(uint32_t requested_bits)
{
	uint32_t ret;

	mutex_reader_lock(&hwrand_mutex);
	ret = esdm_hwrand_entropylevel_locked(requested_bits);
	mutex_reader_unlock(&hwrand_mutex);

	return ret;
}

static uint32_t esdm_hwrand_poolsize(void)
{
	uint32_t ret;

	mutex_reader_lock(&hwrand_mutex);
	ret = esdm_hwrand_entropylevel_locked(esdm_security_strength());
	mutex_reader_unlock(&hwrand_mutex);

	return ret;
}

/*
 * Read entropy from /dev/hwrng in chunks. Many hwrng backends impose an upper
 * limit on a single read (e.g. 32 bytes for a TPM 2.0); chunking ensures
 * compatibility across all backends.
 */
static void esdm_hwrand_get(struct entropy_es *eb_es, uint32_t requested_bits,
			    bool __unused unsused)
{
	static const size_t hwrng_chunk_len = 32;
	uint8_t buffer[hwrng_chunk_len];
	uint32_t done_bits = 0;

	/*
	 * Use an exclusive lock: on I/O failure esdm_hwrand_fd is closed and
	 * reset, which is a write to shared state.
	 */
	mutex_lock(&hwrand_mutex);

	if (esdm_hwrand_fd < 0)
		goto err;

	do {
		uint32_t chunk_size_bits = min_uint32(hwrng_chunk_len * 8,
						      requested_bits - done_bits);
		uint32_t chunk_size_bytes = chunk_size_bits >> 3;

		if (esdm_safe_read(esdm_hwrand_fd, buffer, hwrng_chunk_len) != (ssize_t)hwrng_chunk_len) {
			close(esdm_hwrand_fd);
			esdm_hwrand_fd = -1;
			goto err;
		}
		memcpy(eb_es->e + (done_bits >> 3), buffer, chunk_size_bytes);
		done_bits += chunk_size_bits;
	} while (done_bits < requested_bits);

	eb_es->e_bits = esdm_hwrand_entropylevel_locked(requested_bits);
	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits of entropy from /dev/hwrng RNG entropy source\n",
		eb_es->e_bits);

	mutex_unlock(&hwrand_mutex);
	memset_secure(buffer, 0, hwrng_chunk_len);
	return;

err:
	mutex_unlock(&hwrand_mutex);
	memset_secure(buffer, 0, hwrng_chunk_len);
	eb_es->e_bits = 0;
}

static void esdm_hwrand_es_state(char *buf, size_t buflen)
{
	uint32_t poolsize, entropy_rate;

	mutex_reader_lock(&hwrand_mutex);
	poolsize = esdm_hwrand_entropylevel_locked(esdm_security_strength());
	entropy_rate = esdm_hwrand_entropylevel_locked(256);
	mutex_reader_unlock(&hwrand_mutex);

	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n",
		 poolsize, entropy_rate);
}

static bool esdm_hwrand_active(void)
{
	bool ret;

	mutex_reader_lock(&hwrand_mutex);
	ret = esdm_hwrand_fd >= 0;
	mutex_reader_unlock(&hwrand_mutex);

	return ret;
}

struct esdm_es_cb esdm_es_hwrand = {
	.name = "LinuxHWRand",
	.init = esdm_hwrand_init,
	.fini = esdm_hwrand_finalize,
	.monitor_es = NULL,
	.get_ent = esdm_hwrand_get,
	.curr_entropy = esdm_hwrand_entropylevel,
	.max_entropy = esdm_hwrand_poolsize,
	.state = esdm_hwrand_es_state,
	.reset = NULL,
	.active = esdm_hwrand_active,
	.switch_hash = NULL,
};
