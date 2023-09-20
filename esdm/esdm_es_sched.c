/*
 * ESDM Slow Entropy Source: Scheduler-based
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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched.h"
#include "helper.h"
#include "logger.h"
#include "memset_secure.h"
#include "test_pertubation.h"

static int esdm_sched_entropy_fd = -1;
static uint32_t esdm_sched_requested_bits_set = 0;
static enum esdm_es_data_size esdm_sched_data_size = esdm_es_data_equal;

static void esdm_sched_finalize(void)
{
	if (esdm_sched_entropy_fd >= 0)
		close(esdm_sched_entropy_fd);
	esdm_sched_entropy_fd = -1;
}

bool esdm_sched_enabled(void)
{
	return (esdm_sched_entropy_fd != -1) &&
	       esdm_config_es_sched_entropy_rate();
}

/* Only set requested bit size */
static void esdm_sched_set_requested_bits(uint32_t requested_bits)
{
	esdm_kernel_set_requested_bits(&esdm_sched_requested_bits_set,
				       requested_bits, esdm_sched_entropy_fd,
				       ESDM_SCHED_CONF);
}

/* Set requested bit size and entropy rate */
static int esdm_sched_set_entropy_rate(uint32_t requested_bits)
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
	ret = ioctl(esdm_sched_entropy_fd, ESDM_SCHED_CONF, &entropy);
	if (ret < 0)
		return -EINVAL;

	esdm_sched_requested_bits_set = requested_bits;
	return 0;
}

static uint32_t esdm_sched_entropylevel(uint32_t requested_bits)
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
	if (esdm_sched_set_entropy_rate(esdm_sched_requested_bits_set) < 0)
		return 0;

	/* Read entropy level */
	ret = ioctl(esdm_sched_entropy_fd, ESDM_SCHED_AVAIL_ENTROPY, &entropy);
	if (ret < 0)
		return 0;

	return entropy;
}

static int esdm_sched_initialize(void)
{
	uint32_t status[2];
	int ret, fd = esdm_sched_entropy_fd;

	/*
	 * We are not closing an available file descriptor as we may not have
	 * the privileges any more to do so.
	 */
	if (fd < 0)
		fd = open("/dev/esdm_es", O_RDONLY);

	if (fd < 0) {
		logger(esdm_config_es_sched_retry() ? LOGGER_VERBOSE :
						      LOGGER_WARN,
		       LOGGER_C_ES,
		       "Disabling scheduler-based entropy source which is not present in kernel\n") return 0;
	}

	ret = ioctl(fd, ESDM_SCHED_ENT_BUF_SIZE, &status);
	if (ret < 0) {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Failure to obtain scheduler entropy source status from kernel\n");
		close(fd);
		return -EAGAIN;
	}

	if (status[0] == sizeof(struct entropy_es)) {
		esdm_sched_data_size = esdm_es_data_equal;
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "Kernel entropy buffer has equal size as ESDM\n");
	} else if (status[0] == sizeof(struct entropy_es_small)) {
		esdm_sched_data_size = esdm_es_data_small;
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "Kernel entropy buffer has smaller size as ESDM - Scheduler ES alone will never be able to fully seed the ESDM\n");
	} else if (status[0] == sizeof(struct entropy_es_large)) {
		esdm_sched_data_size = esdm_es_data_large;
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "Kernel entropy buffer has larger size as ESDM\n");
	} else {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Kernel entropy buffer has different size\n");
		close(fd);
		return -EFAULT;
	}

	esdm_sched_entropy_fd = fd;

	return 0;
}

static int esdm_sched_seed_monitor(void)
{
	uint32_t ent;

	if (esdm_pool_all_nodes_seeded_get())
		return 0;

	logger(LOGGER_DEBUG, LOGGER_C_ES, "Scheduler ES monitor check\n");

	if (esdm_config_es_sched_retry() && esdm_sched_entropy_fd < 0) {
		int ret = esdm_sched_initialize();

		/* Return error */
		if (ret)
			return ret;

		if (esdm_sched_entropy_fd < 0) {
			if (getuid()) {
				logger(LOGGER_WARN, LOGGER_C_ES,
				       "Scheduler ES cannot initialize as privileges are missing!\n");
				return 0;
			}

			return -EAGAIN;
		}
	}

	if (esdm_sched_entropy_fd < 0)
		return 0;

	ent = esdm_sched_entropylevel(esdm_security_strength());

	if (!esdm_config_es_sched_entropy_rate())
		return 0;

	if (ent >= esdm_config_es_sched_entropy_rate()) {
		logger(LOGGER_DEBUG, LOGGER_C_ES,
		       "Full entropy of scheduler ES detected\n");
		esdm_es_add_entropy();
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
 */
static void esdm_sched_get(struct entropy_es *eb_es, uint32_t requested_bits,
			   bool __unused unused)
{
	unsigned int ioctl_cmd;

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

	esdm_sched_set_requested_bits(requested_bits);

	esdm_kernel_read(eb_es, esdm_sched_entropy_fd, ioctl_cmd,
			 esdm_sched_data_size, esdm_es_sched.name);

	return;

err:
	eb_es->e_bits = 0;
}

static void esdm_sched_es_state(char *buf, size_t buflen)
{
	char status[250], *status_p = (buflen < sizeof(status)) ? status : buf;

	if (esdm_sched_entropy_fd >= 0) {
		ssize_t ret;

		esdm_sched_set_entropy_rate(esdm_sched_requested_bits_set);

		ret = ioctl(esdm_sched_entropy_fd, ESDM_SCHED_STATUS, status_p);
		if (ret < 0) {
			snprintf(buf, buflen,
				 " failure in reading kernel status\n");
		} else if (buflen < sizeof(status)) {
			snprintf(buf, buflen, "%s", status_p);
		}
	} else {
		snprintf(buf, buflen, " disabled - missing kernel support\n");
	}
}

static void esdm_sched_es_state_json(struct json_object *obj)
{
	if (esdm_sched_entropy_fd >= 0) {
		json_object_object_add(obj, "active", json_object_new_boolean(true));
	} else {
		json_object_object_add(obj, "active", json_object_new_boolean(false));
		json_object_object_add(obj, "avail_entropy", json_object_new_int(0));
	}
}

static void esdm_sched_reset(void)
{
	uint32_t reset[2];

	reset[0] = ESDM_ES_MGR_RESET_BIT;
	reset[1] = 0;

	if (esdm_sched_entropy_fd >= 0) {
		int ret = ioctl(esdm_sched_entropy_fd, ESDM_SCHED_CONF, reset);

		if (ret < 0) {
			logger(LOGGER_ERR, LOGGER_C_ES,
			       "Reset of scheduler entropy source failed\n");
		}
	}
}

static bool esdm_sched_active(void)
{
	return esdm_config_es_sched_retry() || (esdm_sched_entropy_fd != -1);
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
	.state_json = esdm_sched_es_state_json,
	.reset = esdm_sched_reset,
	.active = esdm_sched_active,
	.switch_hash = NULL,
};
