/*
 * ESDM Slow Entropy Source: Scheduler-based
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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched.h"
#include "logger.h"
#include "memset_secure.h"
#include "test_pertubation.h"

static int esdm_sched_entropy_fd = -1;
static int esdm_sched_status_fd = -1;

static void esdm_sched_finalize(void)
{
	if (esdm_sched_entropy_fd >= 0)
		close(esdm_sched_entropy_fd);
	esdm_sched_entropy_fd = -1;

	if (esdm_sched_status_fd >= 0)
		close(esdm_sched_status_fd);
	esdm_sched_status_fd = -1;
}

bool esdm_sched_enabled(void)
{
	return (esdm_sched_entropy_fd != -1) &&
	       esdm_config_es_sched_entropy_rate();
}

static uint32_t esdm_sched_cap_entropylevel(uint32_t entropy,
					    uint32_t requested_bits)
{
	return esdm_fast_noise_entropylevel(
		min_t(uint32_t, entropy, esdm_config_es_sched_entropy_rate()),
		requested_bits);
}

static uint32_t esdm_sched_entropylevel(uint32_t requested_bits)
{
	uint32_t entropy;
	ssize_t readlen;

	if (esdm_sched_entropy_fd < 0)
		return 0;

	lseek(esdm_sched_entropy_fd, 0, SEEK_SET);
	readlen = read(esdm_sched_entropy_fd, &entropy, sizeof(entropy));
	if (readlen != sizeof(entropy))
		return 0;

	return esdm_sched_cap_entropylevel(entropy, requested_bits);
}

static int _esdm_sched_seed_init(void __unused *unused)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 1U<<28 };
	uint64_t i;
	uint32_t ent, sec_strength = esdm_security_strength();
	bool min_seeded_checked = false;

#define secs(x) ((uint64_t)(((uint64_t)1UL<<30) / ((uint64_t)ts.tv_nsec) * x))
	for (i = 0; i < secs(300); i++) {
		if (esdm_get_terminate())
			return 0;

		ent = esdm_sched_entropylevel(sec_strength);

		if (ent >= sec_strength) {
			logger(LOGGER_VERBOSE, LOGGER_C_ES,
			       "Full entropy of scheduler ES detected\n");
			esdm_es_add_entropy();
			esdm_test_seed_entropy(ent);
			return 0;
		}

		if (!min_seeded_checked && ent >= ESDM_MIN_SEED_ENTROPY_BITS) {
			logger(LOGGER_VERBOSE, LOGGER_C_ES,
			       "Minimum entropy of scheduler ES detected\n");
			esdm_es_add_entropy();
			esdm_test_seed_entropy(ent);
			min_seeded_checked = true;
		}

		nanosleep(&ts, NULL);
	}
#undef secs

	logger(LOGGER_WARN, LOGGER_C_ES,
	       "Full entropy of scheduler ES not detected within reasonable time\n");
	return 0;
}

static void esdm_sched_seed_init(void)
{
	int ret = thread_start(_esdm_sched_seed_init, NULL,
				       ESDM_THREAD_SCHED_INIT_GROUP, NULL);

	if (ret) {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Starting the scheduler ES seed thread failed: %d\n",
		       ret);
	}
}

static int esdm_sched_initialize(void)
{
	uint32_t status[2], sec_strength = esdm_security_strength();
	ssize_t readlen;

	esdm_sched_entropy_fd = open("/sys/kernel/debug/esdm_es/entropy_sched",
				     O_RDWR);
	if (esdm_sched_entropy_fd < 0) {
		logger(LOGGER_WARN, LOGGER_C_ES,
		       "Disabling scheduler-based entropy source which is not present in kernel\n")
		return 0;
	}

	readlen = read(esdm_sched_entropy_fd, &status, sizeof(status));
	if (readlen != sizeof(status)) {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Failure to obtain scheduler entropy source status from kernel\n");
		esdm_sched_finalize();
		return -EFAULT;
	}

	if (status[0] != sizeof(struct entropy_es)) {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Kernel entropy buffer has different size\n");
		esdm_sched_finalize();
		return -EFAULT;
	}

	if (esdm_sched_entropylevel(sec_strength) < sec_strength)
		esdm_sched_seed_init();

	esdm_sched_status_fd = open("/sys/kernel/debug/esdm_es/status_sched",
				    O_RDWR);
	if (esdm_sched_entropy_fd < 0) {
		esdm_sched_finalize();
		return 0;
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
	size_t buflen;
	ssize_t ret;
	uint8_t *buf;
	static uint32_t requested_bits_set = 0;

	if (esdm_sched_entropy_fd < 0)
		goto err;

	if (requested_bits_set != requested_bits) {
		lseek(esdm_sched_entropy_fd, 0, SEEK_SET);
		ret = write(esdm_sched_entropy_fd, &requested_bits,
			    sizeof(requested_bits));
		if (ret == sizeof(requested_bits))
			requested_bits_set = requested_bits;
	}

	buf = (uint8_t *)eb_es;
	buflen = sizeof(struct entropy_es);
	do {
		lseek(esdm_sched_entropy_fd, 0, SEEK_SET);
		ret = read(esdm_sched_entropy_fd, buf, buflen);
		if (ret > 0) {
			buflen -= (size_t)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno) && buflen);

	if (buflen)
		goto err;

	eb_es->e_bits = esdm_sched_cap_entropylevel(eb_es->e_bits,
						    requested_bits);

	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "obtained %u bits of entropy from scheduler-based entropy source\n",
	       eb_es->e_bits);

	return;

err:
	eb_es->e_bits = 0;
}

static void esdm_sched_es_state(char *buf, size_t buflen)
{
	if (esdm_sched_status_fd >= 0) {
		ssize_t ret;

		do {
			lseek(esdm_sched_status_fd, 0, SEEK_SET);
			ret = read(esdm_sched_status_fd, buf, buflen);
			if (ret > 0) {
				buflen -= (size_t)ret;
				buf += ret;
			}
		} while ((0 < ret || EINTR == errno) && buflen);
	} else {
		snprintf(buf, buflen, " disabled - missing kernel support\n");
	}
}

#define ESDM_ES_MGR_RESET_BIT		0x10000
static void esdm_sched_reset(void)
{
	uint32_t reset = ESDM_ES_MGR_RESET_BIT;

	if (esdm_sched_entropy_fd >= 0) {
		ssize_t ret;

		lseek(esdm_sched_entropy_fd, 0, SEEK_SET);
		ret = write(esdm_sched_entropy_fd, &reset, sizeof(reset));

		if (ret != sizeof(reset)) {
			logger(LOGGER_ERR, LOGGER_C_ES,
			       "Reset of scheduler entropy source failed\n");
		} else {
			esdm_sched_seed_init();
		}
	}
}

struct esdm_es_cb esdm_es_sched = {
	.name			= "Scheduler",
	.init			= esdm_sched_initialize,
	.fini			= esdm_sched_finalize,
	.get_ent		= esdm_sched_get,
	.curr_entropy		= esdm_sched_entropylevel,
	.max_entropy		= esdm_sched_poolsize,
	.state			= esdm_sched_es_state,
	.reset			= esdm_sched_reset,
	.switch_hash		= NULL,
};
