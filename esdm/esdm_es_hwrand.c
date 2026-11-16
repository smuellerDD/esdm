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
#include <json-c/json.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "esdm_config.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_hwrand.h"
#include "esdm_es_mgr.h"
#include "esdm_es_reader.h"
#include "esdm_node.h"
#include "helper.h"
#include "math_helper.h"
#include "mutex.h"

#define ESDM_ES_HWRAND_IF "/dev/hwrng"

/*
 * Bound the wait for /dev/hwrng. It is read on the seeding path under a seed
 * or DRNG lock and in the synchronous pre-RPC seeding at startup, so a stalled
 * or backend-less device (virtio-rng without host source, slow TPM-backed
 * hwrng) must not hang the clients or the startup.
 *
 * Neither poll (unimplemented) nor O_NONBLOCK bound the wait for the hwrng
 * mutex, so the thread of esdm_es_reader.h reads it, see there. O_NONBLOCK
 * keeps that thread out of the driver's uninterruptible wait for data, which
 * would stall the setuid() of the privilege drop: it signals every thread.
 * A read finding no data is retried until the deadline. On a timeout or error
 * the source fails: no entropy, no reads for seeding; the ES monitor probes it
 * every ESDM_ES_HWRAND_PROBE_INTERVAL_SEC at most until a probe delivers.
 */
#define ESDM_ES_HWRAND_READ_TIMEOUT_MS 2000
#define ESDM_ES_HWRAND_PROBE_INTERVAL_SEC 10

/* The reader of the device, NULL for none: under hwrand_mutex */
static struct esdm_es_reader *esdm_hwrand_reader = NULL;
static DEFINE_MUTEX_UNLOCKED(hwrand_mutex);

/*
 * Readable without waiting for a read in progress: device open, last read
 * failed (e.g. USB hwrng removed). While failed, no entropy is claimed, so a
 * device-less /dev/hwrng cannot inflate the estimate; the fd stays open to
 * pick up a re-inserted device.
 */
static atomic_bool esdm_hwrand_present = false;
static atomic_bool esdm_hwrand_read_failed = false;

/* Monotonic ns: the next probe of a failing device */
static _Atomic uint64_t esdm_hwrand_probe_at = 0;

#ifdef ESDM_TESTMODE
static const char *esdm_hwrand_path = ESDM_ES_HWRAND_IF;

void esdm_hwrand_test_set_path(const char *path)
{
	esdm_hwrand_path = path ? path : ESDM_ES_HWRAND_IF;
}
#else
#define esdm_hwrand_path ESDM_ES_HWRAND_IF
#endif

/* Caller must hold hwrand_mutex (write lock). */
static void esdm_hwrand_finalize_locked(void)
{
	atomic_store(&esdm_hwrand_present, false);
	esdm_es_reader_free(esdm_hwrand_reader);
	esdm_hwrand_reader = NULL;
}

static void esdm_hwrand_finalize(void)
{
	mutex_lock(&hwrand_mutex);
	esdm_hwrand_finalize_locked();
	mutex_unlock(&hwrand_mutex);
}

/*
 * Reader op, in chunks: many hwrng backends cap a single read (e.g. 32 bytes
 * for a TPM 2.0). The reader bounds the wait for it.
 */
static int esdm_hwrand_read_op(int fd, uint8_t *buf, size_t len,
			       uint64_t deadline_ns)
{
	static const size_t hwrng_chunk_len = 32;
	static const struct timespec retry = { .tv_nsec = 10 * 1000000 };
	size_t done = 0;

	while (done < len) {
		ssize_t ret = read(fd, buf + done,
				   min_size(hwrng_chunk_len, len - done));

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN)
				return -errno;
			if (esdm_monotonic_wait_ns() >= deadline_ns)
				return -ETIMEDOUT;
			nanosleep(&retry, NULL);
			continue;
		}
		/* End of file: no device behind it */
		if (!ret)
			return -ENODEV;
		done += (size_t)ret;
	}

	return 0;
}

/*
 * Read @len bytes from the device: 0, or a negative errno marking it failed,
 * except -EBUSY. @wait: see esdm_es_reader_read().
 */
static int esdm_hwrand_read(uint8_t *buf, size_t len, bool wait)
{
	int ret = -ENODEV;

	mutex_reader_lock(&hwrand_mutex);
	if (esdm_hwrand_reader)
		ret = esdm_es_reader_read(
			esdm_hwrand_reader, buf, len,
			esdm_monotonic_wait_ns() +
				ESDM_ES_HWRAND_READ_TIMEOUT_MS * 1000000ULL,
			wait);
	mutex_reader_unlock(&hwrand_mutex);

	if (ret == -EBUSY)
		return ret;
	if (ret) {
		if (!atomic_exchange(&esdm_hwrand_read_failed, true))
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"HWRand ES: no data from %s: %s - no entropy until it delivers again\n",
				esdm_hwrand_path, strerror(-ret));
	} else if (atomic_exchange(&esdm_hwrand_read_failed, false)) {
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "HWRand ES: %s delivers again\n", esdm_hwrand_path);
	}

	return ret;
}

static int esdm_hwrand_init(void)
{
	int fd;

	mutex_lock(&hwrand_mutex);

	/* Allow the init function to be called multiple times */
	esdm_hwrand_finalize_locked();

	atomic_store(&esdm_hwrand_read_failed, false);
	atomic_store(&esdm_hwrand_probe_at, 0);
	fd = open(esdm_hwrand_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling /dev/hwrng-based entropy source as device not present, error opening %s: %s\n",
			esdm_hwrand_path, strerror(errno));
	} else if (!esdm_es_reader_alloc(&esdm_hwrand_reader, fd,
					 esdm_hwrand_read_op, "hwrng")) {
		atomic_store(&esdm_hwrand_present, true);
	}

	mutex_unlock(&hwrand_mutex);

	return 0;
}

/* Without a lock: a read in progress is not waited for */
static uint32_t esdm_hwrand_entropylevel(uint32_t requested_bits)
{
	if (!atomic_load(&esdm_hwrand_present) ||
	    atomic_load(&esdm_hwrand_read_failed))
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_hwrand_entropy_rate(), requested_bits);
}

static uint32_t esdm_hwrand_poolsize(void)
{
	return esdm_hwrand_entropylevel(esdm_security_strength());
}

/*
 * A failing device is left to the ES monitor's probes. One credited with
 * nothing is not waited for, or seedings would queue for no entropy.
 */
static void esdm_hwrand_get(struct entropy_es *eb_es, uint32_t requested_bits)
{
	eb_es->e_bits = 0;

	if (atomic_load(&esdm_hwrand_read_failed) ||
	    esdm_hwrand_read(eb_es->e, requested_bits >> 3,
			     !!esdm_config_es_hwrand_entropy_rate()))
		return;

	eb_es->e_bits = esdm_hwrand_entropylevel(requested_bits);
	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits of entropy from /dev/hwrng RNG entropy source\n",
		eb_es->e_bits);
}

static bool esdm_hwrand_active(void)
{
	return atomic_load(&esdm_hwrand_present);
}

/* Probes a failing device */
static int esdm_hwrand_monitor(void)
{
	if (!esdm_hwrand_active())
		return 0;

	if (atomic_load(&esdm_hwrand_read_failed)) {
		uint8_t probe[32];
		uint64_t now = esdm_monotonic_now_ns();

		if (now < atomic_load(&esdm_hwrand_probe_at))
			return 0;
		atomic_store(&esdm_hwrand_probe_at,
			     now + ESDM_ES_HWRAND_PROBE_INTERVAL_SEC *
					     1000000000ULL);
		(void)esdm_hwrand_read(probe, sizeof(probe), true);
		memset_secure(probe, 0, sizeof(probe));
		return 0;
	}

	return 0;
}

static void esdm_hwrand_es_state_json(char *buf, size_t buflen)
{
	struct json_object *obj = json_object_new_object();

	if (obj) {
		json_object_object_add(
			obj, "available_entropy",
			json_object_new_int64(esdm_hwrand_poolsize()));
		json_object_object_add(
			obj, "entropy_rate_per_256_data_bits",
			json_object_new_int64(esdm_hwrand_entropylevel(256)));
	}

	esdm_es_state_write(obj, buf, buflen);
}

/* The device is still open and its last read worked. */
static int esdm_hwrand_selftest(void)
{
	if (!esdm_hwrand_active()) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "HWRand ES: no device - nothing to test\n");
		return 0;
	}

	if (atomic_load(&esdm_hwrand_read_failed)) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"HWRand ES: the last read from the device failed\n");
		return -EFAULT;
	}

	return 0;
}

struct esdm_es_cb esdm_es_hwrand = {
	.name = "LinuxHWRand",
	.init = esdm_hwrand_init,
	.fini = esdm_hwrand_finalize,
	.monitor_es = esdm_hwrand_monitor,
	.get_ent = esdm_hwrand_get,
	.curr_entropy = esdm_hwrand_entropylevel,
	.max_entropy = esdm_hwrand_poolsize,
	.state_json = esdm_hwrand_es_state_json,
	.reset = NULL,
	.active = esdm_hwrand_active,
	.selftest = esdm_hwrand_selftest,
};
