/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bitshift.h"
#include "build_bug_on.h"
#include "conv_be_le.h"
#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_reader.h"
#include "esdm_es_tpm2.h"
#include "helper.h"
#include "math_helper.h"
#include "mutex.h"

/*
 * A TPM command blocks while the TPM is busy - a long command of another
 * process (CreatePrimary: seconds to minutes) or, for good, a hung vTPM - and
 * the TPM is read on the seeding path under the pool and DRNG locks. So a
 * reader thread (esdm_es_reader.h) reads it, waited for until a deadline only.
 * On a timeout or error the source fails: no entropy, no reads for seeding;
 * the ES monitor probes it every ESDM_ES_TPM2_PROBE_INTERVAL_SEC at most until
 * a probe delivers.
 *
 * The thread waits in the kernel uninterruptibly meanwhile, and a setuid() of
 * the privilege drop, which signals every thread, waits for it. No mode of
 * /dev/tpmrm0 avoids that: its poll and read take the same locks.
 */
#define ESDM_ES_TPM2_READ_TIMEOUT_MS 2000
#define ESDM_ES_TPM2_PROBE_INTERVAL_SEC 10

/* The reader of the TPM, NULL for none: under tpm2_mutex */
static struct esdm_es_reader *tpm2_reader = NULL;
static DEFINE_MUTEX_UNLOCKED(tpm2_mutex);

/*
 * Readable without waiting for a read in progress: TPM open, last read failed,
 * last self test failed (sticky until one passes).
 */
static atomic_bool tpm2_present = false;
static atomic_bool tpm2_read_failed = false;
static atomic_bool tpm2_selftest_failed = false;

/* Monotonic ns: the next probe of a failing TPM */
static _Atomic uint64_t tpm2_probe_at = 0;

/* session type */
typedef uint16_t TPM2_ST;

/* command code */
typedef uint32_t TPM2_CC;

/* return code */
typedef uint32_t TPM2_RC;

static const TPM2_ST TPM2_ST_NO_SESSIONS = 0x8001;

#ifdef ESDM_TPM2_STIR
static const TPM2_CC TPM2_CC_STIR_RANDOM = 0x00000146;
#endif
static const TPM2_CC TPM2_CC_GET_RANDOM = 0x0000017B;

static const TPM2_RC TPM2_RC_SUCCESS = 0x00000000;
static const TPM2_RC TPM2_RC_RETRY = 0x00000922;
static const TPM2_RC TPM2_RC_TESTING = 0x0000090A;
static const TPM2_RC TPM2_RC_YIELDED = 0x00000908;

struct TPM2CommandHeader {
	TPM2_ST tag;
	uint32_t commandSize;
	TPM2_CC commandCode;
} __attribute((__packed__));

struct TPM2ResponseHeader {
	TPM2_ST tag;
	uint32_t responseSize;
	TPM2_RC responseCode;
} __attribute((__packed__));

/*
 * Send a TPM 2.0 command to @fd and receive the response, retrying no more
 * once @deadline_ns passed.
 *
 * Returns 0 on success, -1 on failure (I/O error or TPM error).
 *
 * rsp_buffer may be NULL only when rsp_buffer_len is 0.
 */
static int esdm_es_tpm2_transceive(int fd, uint64_t deadline_ns,
				   struct TPM2CommandHeader *cmd,
				   uint8_t *cmd_buffer, uint32_t cmd_buffer_len,
				   struct TPM2ResponseHeader *rsp,
				   uint8_t *rsp_buffer, uint32_t rsp_buffer_len)
{
	uint8_t buf[256];
	static const int max_retries = 5;
	int retries = 0;
	int ret = -1, cancelstate;
	ssize_t safe_ret = -1;

	if (sizeof(struct TPM2CommandHeader) + cmd_buffer_len > sizeof(buf) ||
	    sizeof(struct TPM2ResponseHeader) + rsp_buffer_len > sizeof(buf)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "TPM 2.0 transceive: buffer too small\n");
		goto out;
	}

	do {
		if (retries++ && esdm_monotonic_wait_ns() >= deadline_ns)
			break;
		memset(buf, 0, sizeof(buf));

		/* Serialize command header as big-endian into buf */
		be16_to_ptr(buf + offsetof(struct TPM2CommandHeader, tag),
			    cmd->tag);
		be32_to_ptr(buf + offsetof(struct TPM2CommandHeader,
					   commandSize),
			    cmd->commandSize);
		be32_to_ptr(buf + offsetof(struct TPM2CommandHeader,
					   commandCode),
			    cmd->commandCode);
		memcpy(buf + sizeof(struct TPM2CommandHeader), cmd_buffer,
		       cmd_buffer_len);

		/*
		 * Not cancelled between command and response: a response
		 * left unread makes the fd refuse the next command.
		 */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
		safe_ret = esdm_safe_write(fd, buf,
					   sizeof(struct TPM2CommandHeader) +
						   cmd_buffer_len);
		if (safe_ret == (ssize_t)(sizeof(struct TPM2CommandHeader) +
					  cmd_buffer_len))
			safe_ret = esdm_safe_read(
				fd, buf,
				sizeof(struct TPM2ResponseHeader) +
					rsp_buffer_len);
		else
			safe_ret = -1;
		pthread_setcancelstate(cancelstate, NULL);

		/*
		 * A response shorter than the header - including a 0-byte EOF
		 * read (resource manager closed the fd) - cannot be parsed.
		 * Treat it as a hard I/O error instead of memcpy'ing the zeroed
		 * buffer below, which would otherwise yield responseCode 0 and
		 * be mistaken for TPM2_RC_SUCCESS.
		 */
		if (safe_ret < (ssize_t)sizeof(struct TPM2ResponseHeader)) {
			esdm_logger(LOGGER_WARN, LOGGER_C_ES,
				    "TPM 2.0 response read failed: %zd\n",
				    safe_ret);
			goto out;
		}
		/*
		 * Parse the header before judging the length: a TPM error
		 * response is header-only (10 bytes), so requiring the full
		 * expected response length up front made every error response
		 * - including the retryable RC_RETRY/RC_YIELDED/RC_TESTING -
		 * an unparsed instant retry with the backoff below dead.
		 */
		memcpy(rsp, buf, sizeof(struct TPM2ResponseHeader));
		rsp->tag = ptr_to_be16((uint8_t *)&rsp->tag);
		rsp->responseSize = ptr_to_be32((uint8_t *)&rsp->responseSize);
		rsp->responseCode = ptr_to_be32((uint8_t *)&rsp->responseCode);

		if (rsp->responseCode == TPM2_RC_SUCCESS) {
			/* A success response must carry the full payload. */
			if (safe_ret !=
			    (ssize_t)(sizeof(struct TPM2ResponseHeader) +
				      rsp_buffer_len)) {
				continue;
			}

			/*
			 * Copy only the payload bytes (responseSize includes
			 * the header), and guard against a NULL rsp_buffer.
			 */
			if (rsp_buffer && rsp_buffer_len > 0) {
				size_t payload_len = 0;

				if (rsp->responseSize >
				    sizeof(struct TPM2ResponseHeader))
					payload_len =
						rsp->responseSize -
						sizeof(struct TPM2ResponseHeader);
				memcpy(rsp_buffer,
				       buf + sizeof(struct TPM2ResponseHeader),
				       min_size(payload_len, rsp_buffer_len));
			}

			ret = 0;
			break;
		}

		if (rsp->responseCode == TPM2_RC_RETRY ||
		    rsp->responseCode == TPM2_RC_YIELDED ||
		    rsp->responseCode == TPM2_RC_TESTING) {
			/*
			 * backoff: 10 ms, 20 ms, 30 ms
			 * should only happen shortly after boot/tpm2_selftest
			 */
			if (retries < max_retries)
				usleep(10000U * (unsigned int)retries);
			continue;
		}

		/* Unrecoverable TPM error */
		break;
	} while (retries < max_retries);

out:
	memset_secure(buf, 0, sizeof(buf));
	return ret;
}

/* One TPM2_CC_GetRandom on @fd, len must be in [1, 32]. */
static int esdm_es_tpm2_get_internal(int fd, uint64_t deadline_ns, uint8_t *buf,
				     uint32_t len)
{
#ifdef ESDM_TPM2_STIR
	struct timespec stir_clock_real;
	struct timespec stir_clock_monotonic;
	static const uint16_t stir_data_len =
		sizeof(stir_clock_real) + sizeof(stir_clock_monotonic);
	uint8_t stir_buf[sizeof(uint16_t) + sizeof(stir_clock_real) +
			 sizeof(stir_clock_monotonic)] = { 0 };
	struct TPM2CommandHeader stirrandom_cmd = {
		.tag = TPM2_ST_NO_SESSIONS,
		.commandSize =
			sizeof(struct TPM2CommandHeader) + sizeof(stir_buf),
		.commandCode = TPM2_CC_STIR_RANDOM
	};
	struct TPM2ResponseHeader stirrandom_rsp = { 0 };
#endif
	struct TPM2CommandHeader getrandom_cmd = {
		.tag = TPM2_ST_NO_SESSIONS,
		.commandSize =
			sizeof(struct TPM2CommandHeader) + sizeof(uint16_t),
		.commandCode = TPM2_CC_GET_RANDOM
	};
	uint16_t bytes_requested = be_bswap16(len);
	uint8_t resp_buf[32 + 2] = { 0 };
	struct TPM2ResponseHeader getrandom_rsp = { 0 };
	uint16_t bytes_returned = 0;

	if (len == 0 || len > 32)
		return -1;

#ifdef ESDM_TPM2_STIR
	/*
	 * Explicitly trigger a reseed of the TPM's internal DRBG before
	 * requesting random data. Also mix in additional data on every
	 * request for additional domain separation inside the TPM.
	 * It is highly unlikely, to get the exact same realtime and monotonic
	 * time tuples on all systems every time.
	 */

	/* stir buffer size */
	be16_to_ptr(stir_buf, stir_data_len);

	/* inject real and monotonic time as additional input without entropy */
	(void)clock_gettime(CLOCK_REALTIME, &stir_clock_real);
	(void)clock_gettime(CLOCK_MONOTONIC, &stir_clock_monotonic);
	memcpy(stir_buf + sizeof(uint16_t), &stir_clock_real,
	       sizeof(stir_clock_real));
	memcpy(stir_buf + sizeof(uint16_t) + sizeof(stir_clock_real),
	       &stir_clock_monotonic, sizeof(stir_clock_monotonic));

	if (esdm_es_tpm2_transceive(fd, deadline_ns, &stirrandom_cmd, stir_buf,
				    sizeof(stir_buf), &stirrandom_rsp, NULL,
				    0)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 stir random failed\n");
		memset_secure(stir_buf, 0, sizeof(stir_buf));
		return -1;
	}
	memset_secure(stir_buf, 0, sizeof(stir_buf));
#endif

	if (esdm_es_tpm2_transceive(fd, deadline_ns, &getrandom_cmd,
				    (uint8_t *)&bytes_requested,
				    sizeof(bytes_requested), &getrandom_rsp,
				    resp_buf, sizeof(resp_buf))) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 get random failed. RC: 0x%04x\n",
			    getrandom_rsp.responseCode);
		memset_secure(resp_buf, 0, sizeof(resp_buf));
		return -1;
	}

	if (getrandom_rsp.responseSize !=
	    sizeof(struct TPM2ResponseHeader) + sizeof(uint16_t) + len) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 unexpected response size: %u\n",
			    getrandom_rsp.responseSize);
		memset_secure(resp_buf, 0, sizeof(resp_buf));
		return -1;
	}

	bytes_returned = ptr_to_be16(resp_buf);
	if (bytes_returned != len) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 returned %u bytes, expected %u\n",
			    bytes_returned, len);
		memset_secure(resp_buf, 0, sizeof(resp_buf));
		return -1;
	}

	memcpy(buf, resp_buf + 2, len);
	memset_secure(resp_buf, 0, sizeof(resp_buf));

	return 0;
}

/* Reader op: GetRandom yields 32 bytes at most, the parser nothing shorter */
static int esdm_es_tpm2_read_op(int fd, uint8_t *buf, size_t len,
				uint64_t deadline_ns)
{
	static const uint32_t tpm2_max_chunk_bytes = 32;
	uint8_t chunk[32];
	size_t done = 0;
	int ret = 0;

	while (done < len) {
		size_t n = min_size(tpm2_max_chunk_bytes, len - done);

		if (esdm_monotonic_wait_ns() >= deadline_ns) {
			ret = -ETIMEDOUT;
			break;
		}
		if (esdm_es_tpm2_get_internal(fd, deadline_ns, chunk,
					      tpm2_max_chunk_bytes)) {
			ret = -EIO;
			break;
		}
		memcpy(buf + done, chunk, n);
		done += n;
	}

	memset_secure(chunk, 0, sizeof(chunk));
	return ret;
}

/*
 * Read @len bytes from the TPM: 0, or a negative errno marking it failed,
 * except -EBUSY. @wait: see esdm_es_reader_read().
 */
static int esdm_es_tpm2_read(uint8_t *buf, size_t len, uint64_t deadline_ns,
			     bool wait)
{
	int ret = -ENODEV;

	mutex_reader_lock(&tpm2_mutex);
	if (tpm2_reader)
		ret = esdm_es_reader_read(tpm2_reader, buf, len, deadline_ns,
					  wait);
	mutex_reader_unlock(&tpm2_mutex);

	if (ret == -EBUSY)
		return ret;
	if (ret) {
		if (!atomic_exchange(&tpm2_read_failed, true))
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"TPM2 ES: no data from the TPM: %s - no entropy until it delivers again\n",
				strerror(-ret));
	} else if (atomic_exchange(&tpm2_read_failed, false)) {
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "TPM2 ES: the TPM delivers again\n");
	}

	return ret;
}

static uint64_t esdm_es_tpm2_deadline(void)
{
	return esdm_monotonic_wait_ns() +
	       ESDM_ES_TPM2_READ_TIMEOUT_MS * 1000000ULL;
}

/* Caller must hold tpm2_mutex (write lock). */
static void esdm_es_tpm2_finalize_locked(void)
{
	atomic_store(&tpm2_present, false);
	esdm_es_reader_free(tpm2_reader);
	tpm2_reader = NULL;
}

static void esdm_es_tpm2_finalize(void)
{
	mutex_lock(&tpm2_mutex);
	esdm_es_tpm2_finalize_locked();
	mutex_unlock(&tpm2_mutex);
}

static int esdm_es_tpm2_init(void)
{
	int fd;

	mutex_lock(&tpm2_mutex);

	/* Allow the init function to be called multiple times */
	esdm_es_tpm2_finalize_locked();

	atomic_store(&tpm2_read_failed, false);
	atomic_store(&tpm2_probe_at, 0);
	fd = open(ESDM_TPM2_RM_PATH, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling TPM 2.0 entropy source as it is not present, error: %s\n",
			strerror(errno));
	} else if (!esdm_es_reader_alloc(&tpm2_reader, fd, esdm_es_tpm2_read_op,
					 "tpm2")) {
		atomic_store(&tpm2_present, true);
	}

	mutex_unlock(&tpm2_mutex);

	return 0;
}

/* Without a lock: a read in progress is not waited for */
static uint32_t esdm_es_tpm2_entropylevel(uint32_t requested_bits)
{
	if (!atomic_load(&tpm2_present) || atomic_load(&tpm2_read_failed) ||
	    atomic_load(&tpm2_selftest_failed))
		return 0;

	return esdm_fast_noise_entropylevel(esdm_config_es_tpm2_entropy_rate(),
					    requested_bits);
}

static uint32_t esdm_es_tpm2_poolsize(void)
{
	return esdm_es_tpm2_entropylevel(esdm_security_strength());
}

/*
 * A failing TPM is left to the ES monitor's probes. One credited with nothing
 * is not waited for: it serves one command at a time, so seedings would queue
 * for data adding no entropy.
 */
static void esdm_es_tpm2_get(struct entropy_es *eb_es, uint32_t requested_bits)
{
	eb_es->e_bits = 0;

	if (atomic_load(&tpm2_read_failed) ||
	    esdm_es_tpm2_read(eb_es->e, requested_bits >> 3,
			      esdm_es_tpm2_deadline(),
			      !!esdm_config_es_tpm2_entropy_rate()))
		return;

	eb_es->e_bits = esdm_es_tpm2_entropylevel(requested_bits);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from TPM 2.0 entropy source\n",
		    eb_es->e_bits);
}

static bool esdm_es_tpm2_active(void)
{
	return atomic_load(&tpm2_present);
}

/* Probes a failing TPM */
static int esdm_es_tpm2_monitor(void)
{
	if (!esdm_es_tpm2_active())
		return 0;

	if (atomic_load(&tpm2_read_failed)) {
		uint8_t probe[32];
		uint64_t now = esdm_monotonic_now_ns();

		if (now < atomic_load(&tpm2_probe_at))
			return 0;
		atomic_store(&tpm2_probe_at,
			     now + ESDM_ES_TPM2_PROBE_INTERVAL_SEC *
					     1000000000ULL);
		(void)esdm_es_tpm2_read(probe, sizeof(probe),
					esdm_es_tpm2_deadline(), true);
		memset_secure(probe, 0, sizeof(probe));
		return 0;
	}

	return 0;
}

static void esdm_es_tpm2_es_state_json(char *buf, size_t buflen)
{
#ifdef ESDM_TPM2_STIR
	const bool stir = 1;
#else
	const bool stir = 0;
#endif
	struct json_object *obj = json_object_new_object();

	if (obj) {
		json_object_object_add(
			obj, "available_entropy",
			json_object_new_int64(esdm_es_tpm2_poolsize()));
		json_object_object_add(
			obj, "entropy_rate_per_256_data_bits",
			json_object_new_int64(esdm_es_tpm2_entropylevel(256)));
		json_object_object_add(obj, "stir",
				       json_object_new_int64(stir));
	}

	esdm_es_state_write(obj, buf, buflen);
}

/*
 * Two reads of the TPM that have to succeed and have to differ. A repetition
 * is sticky: no entropy is credited until a later self test passes.
 */
static int esdm_es_tpm2_selftest(void)
{
	uint8_t first[32], second[32];
	uint64_t deadline_ns = esdm_es_tpm2_deadline();
	int ret = 0;

	if (!esdm_es_tpm2_active()) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "TPM2 ES: no device - nothing to test\n");
		return 0;
	}

	ret = esdm_es_tpm2_read(first, sizeof(first), deadline_ns, true);
	if (!ret)
		ret = esdm_es_tpm2_read(second, sizeof(second), deadline_ns,
					true);
	if (ret == -EBUSY) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "TPM2 ES: busy with another read - not tested\n");
		ret = 0;
		goto out;
	}
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "TPM2 ES: the TPM did not deliver\n");
		ret = -EFAULT;
		goto out;
	}

	if (!memcmp(first, second, sizeof(first))) {
		atomic_store(&tpm2_selftest_failed, true);
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "TPM2 ES: the TPM repeated its output\n");
		ret = -EFAULT;
		goto out;
	}

	if (atomic_exchange(&tpm2_selftest_failed, false))
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "TPM2 ES: self test passed again\n");

out:
	memset_secure(first, 0, sizeof(first));
	memset_secure(second, 0, sizeof(second));
	return ret;
}

struct esdm_es_cb esdm_es_tpm2 = {
	.name = "TPM2.0",
	.init = esdm_es_tpm2_init,
	.fini = esdm_es_tpm2_finalize,
	.monitor_es = esdm_es_tpm2_monitor,
	.get_ent = esdm_es_tpm2_get,
	.curr_entropy = esdm_es_tpm2_entropylevel,
	.max_entropy = esdm_es_tpm2_poolsize,
	.state_json = esdm_es_tpm2_es_state_json,
	.reset = NULL,
	.active = esdm_es_tpm2_active,
	.selftest = esdm_es_tpm2_selftest,
};
