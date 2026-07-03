/*
 * ESDM Fast Entropy Source: Linux /dev/hwrng-based entropy source
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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "esdm_config.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_hwrand.h"
#include "esdm_es_mgr.h"
#include "esdm_node.h"
#include "helper.h"
#include "mutex.h"

#define ESDM_ES_HWRAND_IF "/dev/hwrng"

/*
 * Bound the time spent waiting for /dev/hwrng to deliver data. The read runs
 * on the synchronous, pre-RPC seeding path, so a stalled or backend-less
 * /dev/hwrng (e.g. a virtio-rng without a host source, or a slow TPM-backed
 * hwrng) must not be able to hang daemon startup. The fd is opened
 * non-blocking and reads are gated by poll() with a bounded total budget; on
 * timeout the source is treated as failed for this request and claims no
 * entropy, exactly like a hard read error.
 */
#define ESDM_ES_HWRAND_POLL_SLICE_MS 500
#define ESDM_ES_HWRAND_READ_TIMEOUT_MS 2000

static int esdm_hwrand_fd = -1;
/*
 * Tracks whether the last read from /dev/hwrng failed (e.g. no backing
 * device after USB hwrng removal). While set, no entropy is claimed so a
 * device-less /dev/hwrng cannot inflate the available entropy estimate;
 * the fd stays open so a re-inserted device is picked up again. Written
 * only under the hwrand_mutex write lock, read under the reader lock.
 */
static bool esdm_hwrand_read_failed = false;
static DEFINE_MUTEX_UNLOCKED(hwrand_mutex);

#if (ESDM_HWRAND_ENTROPY_BLOCKS != 0)
static struct esdm_es_buf hwrand_buf;
static bool hwrand_buf_alloced = false;
#endif

static bool esdm_hwrand_active(void);

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

#if (ESDM_HWRAND_ENTROPY_BLOCKS != 0)
	if (hwrand_buf_alloced) {
		esdm_es_buf_free(&hwrand_buf);
		hwrand_buf_alloced = false;
	}
#endif
}

static int esdm_hwrand_init(void)
{
	mutex_lock(&hwrand_mutex);

	/* Allow the init function to be called multiple times */
	esdm_hwrand_finalize_locked();

	esdm_hwrand_read_failed = false;
	esdm_hwrand_fd =
		open(ESDM_ES_HWRAND_IF, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (esdm_hwrand_fd < 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling /dev/hwrng-based entropy source as device not present, error opening %s: %s\n",
			ESDM_ES_HWRAND_IF, strerror(errno));
		mutex_unlock(&hwrand_mutex);
		return 0;
	}

	mutex_unlock(&hwrand_mutex);

#if (ESDM_HWRAND_ENTROPY_BLOCKS != 0)
	if (hwrand_buf_alloced) {
		esdm_es_buf_reset(&hwrand_buf);
	} else if (esdm_es_buf_alloc(&hwrand_buf, ESDM_HWRAND_ENTROPY_BLOCKS,
				     "LinuxHWRand") == 0) {
		hwrand_buf_alloced = true;
	}
#endif

	return 0;
}

/* Caller must hold hwrand_mutex. */
static uint32_t esdm_hwrand_entropylevel_locked(uint32_t requested_bits)
{
	if (esdm_hwrand_fd < 0 || esdm_hwrand_read_failed)
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
 * Read exactly @buflen bytes from the non-blocking hwrng @fd, bounded by a
 * total wait budget. Returns the number of bytes read (== @buflen on success),
 * or a negative errno on error, or -ETIMEDOUT if the device did not deliver
 * the requested data within ESDM_ES_HWRAND_READ_TIMEOUT_MS.
 */
static ssize_t esdm_hwrand_read_bounded(int fd, uint8_t *buf, size_t buflen)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	size_t bytes_read = 0;
	int waited_ms = 0;

	while (bytes_read < buflen) {
		ssize_t ret = read(fd, buf + bytes_read, buflen - bytes_read);
		int pret;

		if (ret > 0) {
			bytes_read += (size_t)ret;
			continue;
		}
		if (ret == 0)
			return (ssize_t)bytes_read;
		if (errno == EINTR)
			continue;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return -errno;

		/* No data ready: wait for it, bounded by the total budget. */
		if (waited_ms >= ESDM_ES_HWRAND_READ_TIMEOUT_MS)
			return -ETIMEDOUT;

		pfd.revents = 0;
		pret = poll(&pfd, 1, ESDM_ES_HWRAND_POLL_SLICE_MS);
		if (pret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (pret == 0)
			waited_ms += ESDM_ES_HWRAND_POLL_SLICE_MS;
	}

	return (ssize_t)bytes_read;
}

/*
 * Read entropy from /dev/hwrng in chunks. Many hwrng backends impose an upper
 * limit on a single read (e.g. 32 bytes for a TPM 2.0); chunking ensures
 * compatibility across all backends.
 */
static void esdm_hwrand_get_sync(struct entropy_es *eb_es,
				 uint32_t requested_bits)
{
	static const size_t hwrng_chunk_len = 32;
	uint8_t buffer[hwrng_chunk_len];
	uint32_t done_bits = 0;

	/*
	 * Use an exclusive lock: the read outcome is recorded in
	 * esdm_hwrand_read_failed, which is a write to shared state.
	 */
	mutex_lock(&hwrand_mutex);

	if (esdm_hwrand_fd < 0)
		goto err;

	do {
		uint32_t chunk_size_bits = min_uint32(
			hwrng_chunk_len * 8, requested_bits - done_bits);
		uint32_t chunk_size_bytes = chunk_size_bits >> 3;

		if (esdm_hwrand_read_bounded(esdm_hwrand_fd, buffer,
					     hwrng_chunk_len) !=
		    (ssize_t)hwrng_chunk_len) {
			esdm_hwrand_read_failed = true;
			goto err;
		}
		memcpy(eb_es->e + (done_bits >> 3), buffer, chunk_size_bytes);
		done_bits += chunk_size_bits;
	} while (done_bits < requested_bits);

	esdm_hwrand_read_failed = false;
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

#if (ESDM_HWRAND_ENTROPY_BLOCKS != 0)

static void esdm_hwrand_buf_fill(struct entropy_es *eb_es,
				 uint32_t requested_bits, void *ctx)
{
	(void)ctx;
	esdm_hwrand_get_sync(eb_es, requested_bits);
}

static int esdm_hwrand_monitor(void)
{
	uint32_t requested_bits = esdm_get_seed_entropy_osr(false, true);

	if (!esdm_hwrand_active())
		return 0;

	return esdm_es_buf_monitor(&hwrand_buf, requested_bits,
				   esdm_hwrand_buf_fill, NULL);
}

static void esdm_hwrand_get(struct entropy_es *eb_es, uint32_t requested_bits,
			    bool __unused unsused)
{
	if (esdm_es_buf_try_get(&hwrand_buf, eb_es, requested_bits))
		return;

	esdm_hwrand_get_sync(eb_es, requested_bits);
}

#else /* ESDM_HWRAND_ENTROPY_BLOCKS == 0 */

static void esdm_hwrand_get(struct entropy_es *eb_es, uint32_t requested_bits,
			    bool __unused unsused)
{
	esdm_hwrand_get_sync(eb_es, requested_bits);
}

#endif

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
#if (ESDM_HWRAND_ENTROPY_BLOCKS != 0)
	.monitor_es = esdm_hwrand_monitor,
#else
	.monitor_es = NULL,
#endif
	.get_ent = esdm_hwrand_get,
	.curr_entropy = esdm_hwrand_entropylevel,
	.max_entropy = esdm_hwrand_poolsize,
	.state = esdm_hwrand_es_state,
	.reset = NULL,
	.active = esdm_hwrand_active,
};
