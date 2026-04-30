/*
 * ESDM Slow Entropy Source: Scheduler-based
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
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_sched.h"
#include "esdm_es_mgr.h"
#include "helper.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "mutex.h"
#include "test_pertubation.h"

static int esdm_sched_entropy_fd = -1;
static uint32_t esdm_sched_requested_bits_set = 0;
static enum esdm_es_data_size esdm_sched_data_size = esdm_es_data_equal;
/*
 * Serialises access to the kernel /dev/esdm_es fd and its per-fd state
 * (esdm_sched_requested_bits_set, esdm_sched_data_size). Held during the
 * configure-then-read pair in esdm_sched_get_sync so the async monitor
 * cannot race a consumer fallback.
 */
static DEFINE_MUTEX_UNLOCKED(sched_mutex);

#if (ESDM_SCHED_ENTROPY_BLOCKS != 0)
static struct esdm_es_buf sched_buf;
static bool sched_buf_alloced = false;

static void esdm_sched_buf_fill(struct entropy_es *eb_es,
				uint32_t requested_bits, void *ctx);
#endif

/* Caller must hold sched_mutex (write lock). */
static void esdm_sched_finalize_locked(void)
{
	if (esdm_sched_entropy_fd >= 0)
		close(esdm_sched_entropy_fd);
	esdm_sched_entropy_fd = -1;
}

static void esdm_sched_finalize(void)
{
	mutex_lock(&sched_mutex);
	esdm_sched_finalize_locked();
	mutex_unlock(&sched_mutex);

#if (ESDM_SCHED_ENTROPY_BLOCKS != 0)
	if (sched_buf_alloced) {
		esdm_es_buf_free(&sched_buf);
		sched_buf_alloced = false;
	}
#endif
}

bool esdm_sched_enabled(void)
{
	bool ret;

	mutex_reader_lock(&sched_mutex);
	ret = (esdm_sched_entropy_fd != -1) &&
	      esdm_config_es_sched_entropy_rate();
	mutex_reader_unlock(&sched_mutex);

	return ret;
}

/* Caller must hold sched_mutex. */
static void esdm_sched_set_requested_bits_locked(uint32_t requested_bits)
{
	esdm_kernel_set_requested_bits(&esdm_sched_requested_bits_set,
				       requested_bits, esdm_sched_entropy_fd,
				       ESDM_SCHED_CONF);
}

/* Caller must hold sched_mutex. Set requested bit size and entropy rate. */
static int esdm_sched_set_entropy_rate_locked(uint32_t requested_bits)
{
	uint32_t entropy[2];
	int ret;

	if (esdm_sched_entropy_fd < 0)
		return -EOPNOTSUPP;

	if (esdm_sched_requested_bits_set != requested_bits)
		entropy[0] = requested_bits;
	else
		entropy[0] = 0;

	entropy[1] = esdm_config_es_sched_entropy_rate();
	/* Convert into events */
	if (!entropy[1])
		entropy[1] = 0xffffffff;
	else {
		entropy[1] = ESDM_DRNG_SECURITY_STRENGTH_BITS *
			     ESDM_DRNG_SECURITY_STRENGTH_BITS / entropy[1];
	}

	/* Set current entropy rate */
	ret = ioctl(esdm_sched_entropy_fd, ESDM_SCHED_CONF, entropy);
	if (ret < 0)
		return -EINVAL;

	esdm_sched_requested_bits_set = requested_bits;
	return 0;
}

/* Caller must hold sched_mutex. */
static uint32_t esdm_sched_entropylevel_locked(uint32_t requested_bits)
{
	uint32_t entropy;
	int ret;

	(void)requested_bits;

	/*
	 * Note, due to esdm_config_es_sched_entropy_rate_set, IRQ and Sched ES
	 * together are not allowed to deliver entropy.
	 */

	if (esdm_sched_entropy_fd < 0)
		return 0;

	/* Set current entropy rate */
	if (esdm_sched_set_entropy_rate_locked(esdm_sched_requested_bits_set) <
	    0)
		return 0;

	/* Read entropy level */
	ret = ioctl(esdm_sched_entropy_fd, ESDM_SCHED_AVAIL_ENTROPY, &entropy);
	if (ret < 0)
		return 0;

	return entropy;
}

static uint32_t esdm_sched_entropylevel(uint32_t requested_bits)
{
	uint32_t ret;

	mutex_lock(&sched_mutex);
	ret = esdm_sched_entropylevel_locked(requested_bits);
	mutex_unlock(&sched_mutex);

	return ret;
}

static int esdm_sched_initialize(void)
{
	uint32_t status[2];
	int ret, fd;

	mutex_lock(&sched_mutex);

	/*
	 * We are not closing an available file descriptor as we may not have
	 * the privileges any more to do so.
	 */
	fd = esdm_sched_entropy_fd;
	if (fd < 0)
		fd = open("/dev/esdm_es", O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		mutex_unlock(&sched_mutex);
		esdm_logger(
			esdm_config_es_sched_retry() ? LOGGER_VERBOSE :
						       LOGGER_WARN,
			LOGGER_C_ES,
			"Disabling scheduler-based entropy source which is not present in kernel\n");
		return 0;
	}

	ret = ioctl(fd, ESDM_SCHED_ENT_BUF_SIZE, &status);
	if (ret < 0 && errno == ENOTTY) {
		esdm_sched_entropy_fd = fd;
		esdm_sched_finalize_locked();
		mutex_unlock(&sched_mutex);
		esdm_logger(
			esdm_config_es_sched_retry() ? LOGGER_VERBOSE :
						       LOGGER_WARN,
			LOGGER_C_ES,
			"Disabling scheduler-based entropy source which is not present in kernel\n");
		return 0;
	}
	if (ret < 0) {
		close(fd);
		mutex_unlock(&sched_mutex);
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"Failure to obtain scheduler entropy source status from kernel, errno: %i, error: %s\n",
			errno, strerror(errno));
		return -EAGAIN;
	}

	if (status[0] == sizeof(struct entropy_es)) {
		esdm_sched_data_size = esdm_es_data_equal;
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
			    "Kernel entropy buffer has equal size as ESDM\n");
	} else if (status[0] == sizeof(struct entropy_es_small)) {
		esdm_sched_data_size = esdm_es_data_small;
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"Kernel entropy buffer has smaller size as ESDM - Scheduler ES alone will never be able to fully seed the ESDM\n");
	} else if (status[0] == sizeof(struct entropy_es_large)) {
		esdm_sched_data_size = esdm_es_data_large;
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
			    "Kernel entropy buffer has larger size as ESDM\n");
	} else {
		close(fd);
		mutex_unlock(&sched_mutex);
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "Kernel entropy buffer has different size\n");
		return -EFAULT;
	}

	esdm_sched_entropy_fd = fd;

	mutex_unlock(&sched_mutex);

#if (ESDM_SCHED_ENTROPY_BLOCKS != 0)
	if (sched_buf_alloced) {
		esdm_es_buf_reset(&sched_buf);
	} else if (esdm_es_buf_alloc(&sched_buf, ESDM_SCHED_ENTROPY_BLOCKS,
				     "Scheduler") == 0) {
		sched_buf_alloced = true;
	}
#endif

	esdm_es_add_entropy();

	return 0;
}

static int esdm_sched_seed_monitor(void)
{
	uint32_t ent;
	bool fd_present;

	if (esdm_pool_all_nodes_seeded_get())
		return 0;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES, "Scheduler ES monitor check\n");

	mutex_reader_lock(&sched_mutex);
	fd_present = esdm_sched_entropy_fd >= 0;
	mutex_reader_unlock(&sched_mutex);

	if (esdm_config_es_sched_retry() && !fd_present) {
		int ret = esdm_sched_initialize();

		/* Return error */
		if (ret)
			return ret;

		mutex_reader_lock(&sched_mutex);
		fd_present = esdm_sched_entropy_fd >= 0;
		mutex_reader_unlock(&sched_mutex);

		if (!fd_present) {
			if (getuid()) {
				esdm_logger(
					LOGGER_WARN, LOGGER_C_ES,
					"Scheduler ES cannot initialize as privileges are missing!\n");
				return 0;
			}

			return -EAGAIN;
		}
	}

	if (!fd_present)
		return 0;

	ent = esdm_sched_entropylevel(esdm_security_strength());

	if (!esdm_config_es_sched_entropy_rate())
		return 0;

	if (ent >= esdm_config_es_sched_entropy_rate()) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "Full entropy of scheduler ES detected\n");
#if (ESDM_SCHED_ENTROPY_BLOCKS != 0)
		if (sched_buf_alloced) {
			uint32_t requested_bits =
				esdm_get_seed_entropy_osr(false, true);

			esdm_es_buf_monitor(&sched_buf, requested_bits,
					    esdm_sched_buf_fill, NULL);
		} else {
			esdm_es_add_entropy();
		}
#else
		esdm_es_add_entropy();
#endif
		esdm_test_seed_entropy(ent);
	}

	return 0;
}

static uint32_t esdm_sched_poolsize(void)
{
	return esdm_sched_entropylevel(esdm_security_strength());
}

/*
 * esdm_get_sched() - Get scheduler entropy
 *
 * @eb: entropy buffer to store entropy
 * @requested_bits: requested entropy in bits
 *
 * Use an exclusive lock around the configure-then-read pair: the per-fd
 * requested-bits configuration written by
 * esdm_sched_set_requested_bits_locked is consumed by the subsequent
 * esdm_kernel_read ioctl. Without this lock the async monitor and a consumer
 * fallback could interleave and read with the other thread's configuration in
 * effect.
 */
static void esdm_sched_get_sync(struct entropy_es *eb_es,
				uint32_t requested_bits)
{
	unsigned int ioctl_cmd;

	mutex_lock(&sched_mutex);

	if (esdm_sched_entropy_fd < 0)
		goto err;

	switch (esdm_sched_data_size) {
	case esdm_es_data_equal:
		ioctl_cmd = ESDM_SCHED_ENT_BUF;
		break;
	case esdm_es_data_large:
		ioctl_cmd = ESDM_SCHED_ENT_BUF_LARGE;
		break;
	case esdm_es_data_small:
		ioctl_cmd = ESDM_SCHED_ENT_BUF_SMALL;
		break;
	default:
		goto err;
	}

	esdm_sched_set_requested_bits_locked(requested_bits);

	esdm_kernel_read(eb_es, esdm_sched_entropy_fd, ioctl_cmd,
			 esdm_sched_data_size, esdm_es_sched.name);

	mutex_unlock(&sched_mutex);
	return;

err:
	mutex_unlock(&sched_mutex);
	eb_es->e_bits = 0;
}

#if (ESDM_SCHED_ENTROPY_BLOCKS != 0)

static void esdm_sched_buf_fill(struct entropy_es *eb_es,
				uint32_t requested_bits, void *ctx)
{
	(void)ctx;
	esdm_sched_get_sync(eb_es, requested_bits);
}

static void esdm_sched_get(struct entropy_es *eb_es, uint32_t requested_bits,
			   bool __unused unused)
{
	if (esdm_es_buf_try_get(&sched_buf, eb_es, requested_bits))
		return;

	esdm_sched_get_sync(eb_es, requested_bits);
}

#else /* ESDM_SCHED_ENTROPY_BLOCKS == 0 */

static void esdm_sched_get(struct entropy_es *eb_es, uint32_t requested_bits,
			   bool __unused unused)
{
	esdm_sched_get_sync(eb_es, requested_bits);
}

#endif

static void esdm_sched_es_state(char *buf, size_t buflen)
{
	char status[250], *status_p = (buflen < sizeof(status)) ? status : buf;

	mutex_lock(&sched_mutex);

	if (esdm_sched_entropy_fd >= 0) {
		ssize_t ret;

		esdm_sched_set_entropy_rate_locked(
			esdm_sched_requested_bits_set);

		ret = ioctl(esdm_sched_entropy_fd, ESDM_SCHED_STATUS, status_p);
		if (ret < 0) {
			snprintf(buf, buflen,
				 " failure in reading kernel status\n");
		} else if (buflen < sizeof(status)) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
			snprintf(buf, buflen, "%s", status_p);
#pragma GCC diagnostic pop
		}
	} else {
		snprintf(buf, buflen, " disabled - missing kernel support\n");
	}

	mutex_unlock(&sched_mutex);
}

static void esdm_sched_reset(void)
{
	uint32_t reset[2];

	reset[0] = ESDM_ES_MGR_RESET_BIT;
	reset[1] = 0;

	mutex_lock(&sched_mutex);
	if (esdm_sched_entropy_fd >= 0) {
		int ret = ioctl(esdm_sched_entropy_fd, ESDM_SCHED_CONF, reset);

		if (ret < 0) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ES,
				"Reset of scheduler entropy source failed\n");
		}
	}
	mutex_unlock(&sched_mutex);
}

static bool esdm_sched_active(void)
{
	bool fd_present;

	mutex_reader_lock(&sched_mutex);
	fd_present = esdm_sched_entropy_fd != -1;
	mutex_reader_unlock(&sched_mutex);

	return esdm_config_es_sched_retry() || fd_present;
}

struct esdm_es_cb esdm_es_sched = {
	.name = "Scheduler",
	.init = esdm_sched_initialize,
	.fini = esdm_sched_finalize,
	.monitor_es = esdm_sched_seed_monitor,
	.get_ent = esdm_sched_get,
	.curr_entropy = esdm_sched_entropylevel,
	.max_entropy = esdm_sched_poolsize,
	.state = esdm_sched_es_state,
	.reset = esdm_sched_reset,
	.active = esdm_sched_active,
	.switch_hash = NULL,
};
