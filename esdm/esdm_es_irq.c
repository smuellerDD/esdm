/*
 * ESDM Slow Entropy Source: Interrupt-based
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
#include "esdm_es_irq.h"
#include "logger.h"
#include "memset_secure.h"
#include "test_pertubation.h"

static int esdm_irq_entropy_fd = -1;
static int esdm_irq_status_fd = -1;
static uint32_t esdm_irq_requested_bits_set = 0;

static void esdm_irq_finalize(void)
{
	if (esdm_irq_entropy_fd >= 0)
		close(esdm_irq_entropy_fd);
	esdm_irq_entropy_fd = -1;

	if (esdm_irq_status_fd >= 0)
		close(esdm_irq_status_fd);
	esdm_irq_status_fd = -1;
}

bool esdm_irq_enabled(void)
{
	return (esdm_irq_entropy_fd != -1) &&
	       esdm_config_es_irq_entropy_rate();
}

/* Only set requested bit size */
static void esdm_irq_set_requested_bits(uint32_t requested_bits)
{
	if (esdm_irq_requested_bits_set != requested_bits) {
		uint32_t data[2];
		ssize_t ret;

		data[0] = requested_bits;
		data[1] = 0;
		lseek(esdm_irq_entropy_fd, 0, SEEK_SET);
		ret = write(esdm_irq_entropy_fd, &data, sizeof(data));
		if (ret == sizeof(requested_bits))
			esdm_irq_requested_bits_set = requested_bits;
	}
}

/* Set requested bit size and entropy rate */
static int esdm_irq_set_entropy_rate(uint32_t requested_bits)
{
	uint32_t entropy[2];
	ssize_t writelen;

	if (esdm_irq_requested_bits_set != requested_bits)
		entropy[0] = requested_bits;
	else
		entropy[0] = 0;

	entropy[1] = esdm_config_es_irq_entropy_rate();
	/* Convert into events */
	if (!entropy[1])
		entropy[1] = 0xffffffff;
	else {
		entropy[1] = ESDM_DRNG_SECURITY_STRENGTH_BITS *
			     ESDM_DRNG_SECURITY_STRENGTH_BITS / entropy[1];
	}

	/* Set current entropy rate */
	lseek(esdm_irq_entropy_fd, 0, SEEK_SET);

	writelen = write(esdm_irq_entropy_fd, &entropy, sizeof(entropy));
	if (writelen != sizeof(entropy))
		return -EINVAL;

	esdm_irq_requested_bits_set = requested_bits;
	return 0;
}

static uint32_t esdm_irq_entropylevel(uint32_t requested_bits)
{
	uint32_t entropy;
	ssize_t readlen;

	(void)requested_bits;

	if (esdm_irq_entropy_fd < 0)
		return 0;

	/* Set current entropy rate */
	if (esdm_irq_set_entropy_rate(esdm_irq_requested_bits_set) < 0)
		return 0;

	/* Read entropy level */
	lseek(esdm_irq_entropy_fd, 0, SEEK_SET);
	readlen = read(esdm_irq_entropy_fd, &entropy, sizeof(entropy));
	if (readlen != sizeof(entropy))
		return 0;

	return entropy;
}

/*
 * Thread to monitor the initial seeding state of the entropy source. This
 * thread may disable the entropy source if the kernel driver cannot detect
 * sufficient entropy.
 */
static int _esdm_irq_seed_init(void __unused *unused)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 1U<<28 };
	uint64_t i;
	uint32_t ent, sec_strength = esdm_security_strength();
	bool min_seeded_checked = false;

	thread_set_name(irq_seed, 0);

#define secs(x) ((uint64_t)(((uint64_t)1UL<<30) / ((uint64_t)ts.tv_nsec) * x))
	for (i = 0; i < secs(900); i++) {
		if (esdm_get_terminate())
			return 0;

		if (esdm_pool_all_nodes_seeded_get()) {
			logger(LOGGER_VERBOSE, LOGGER_C_ES,
			       "Stopping interrupt ES entropy poll\n");
			return 0;
		}

		ent = esdm_irq_entropylevel(sec_strength);

		if (ent >= esdm_config_es_irq_entropy_rate()) {
			logger(LOGGER_VERBOSE, LOGGER_C_ES,
			       "Full entropy of interrupt ES detected\n");
			esdm_es_add_entropy();
			esdm_test_seed_entropy(ent);
			continue;
		}

		if (!min_seeded_checked && ent >= ESDM_MIN_SEED_ENTROPY_BITS) {
			logger(LOGGER_VERBOSE, LOGGER_C_ES,
			       "Minimum entropy of interrupt ES detected\n");
			esdm_es_add_entropy();
			esdm_test_seed_entropy(ent);
			min_seeded_checked = true;
		}

		nanosleep(&ts, NULL);
	}
#undef secs

	logger(LOGGER_WARN, LOGGER_C_ES,
	       "Full entropy of interrupt ES not detected within reasonable time\n");
	return 0;
}

static void esdm_irq_seed_init(void)
{
	int ret = thread_start(_esdm_irq_seed_init, NULL,
			       ESDM_THREAD_IRQ_INIT_GROUP, NULL);

	if (ret) {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Starting the interrupt ES seed thread failed: %d\n",
		       ret);
	}
}

static int esdm_irq_initialize(void)
{
	uint32_t status[2];
	ssize_t readlen;

	esdm_irq_entropy_fd = open("/sys/kernel/debug/esdm_es/entropy_irq",
				     O_RDWR);
	if (esdm_irq_entropy_fd < 0) {
		logger(LOGGER_WARN, LOGGER_C_ES,
		       "Disabling interrupt-based entropy source which is not present in kernel\n")
		return 0;
	}

	readlen = read(esdm_irq_entropy_fd, &status, sizeof(status));
	if (readlen != sizeof(status)) {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Failure to obtain interrupt entropy source status from kernel\n");
		esdm_irq_finalize();
		return -EFAULT;
	}

	if (status[0] != sizeof(struct entropy_es)) {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Kernel entropy buffer has different size\n");
		esdm_irq_finalize();
		return -EFAULT;
	}

	/* Try asynchronously to check for entropy */
	if (esdm_config_es_irq_entropy_rate() &&
	    !esdm_pool_all_nodes_seeded_get()) {
		logger(LOGGER_DEBUG, LOGGER_C_ES,
		       "Initializing interrupt ES monitoring thread\n");
		esdm_irq_seed_init();
	} else {
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "Full entropy of interrupt ES detected\n");
	}

	esdm_irq_status_fd = open("/sys/kernel/debug/esdm_es/status_irq",
				  O_RDWR);
	if (esdm_irq_entropy_fd < 0) {
		esdm_irq_finalize();
		return 0;
	}

	return 0;
}

static uint32_t esdm_irq_poolsize(void)
{
	return esdm_irq_entropylevel(esdm_security_strength());
}

/*
 * esdm_get_irq() - Get interrupt entropy
 *
 * @eb: entropy buffer to store entropy
 * @requested_bits: requested entropy in bits
 */
static void esdm_irq_get(struct entropy_es *eb_es, uint32_t requested_bits,
			 bool __unused unused)
{
	size_t buflen;
	ssize_t ret;
	uint8_t *buf;

	if (esdm_irq_entropy_fd < 0)
		goto err;

	esdm_irq_set_requested_bits(requested_bits);

	buf = (uint8_t *)eb_es;
	buflen = sizeof(struct entropy_es);
	do {
		lseek(esdm_irq_entropy_fd, 0, SEEK_SET);
		ret = read(esdm_irq_entropy_fd, buf, buflen);
		if (ret > 0) {
			buflen -= (size_t)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno) && buflen);

	if (buflen)
		goto err;

	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "obtained %u bits of entropy from interrupt-based entropy source\n",
	       eb_es->e_bits);

	return;

err:
	eb_es->e_bits = 0;
}

static void esdm_irq_es_state(char *buf, size_t buflen)
{
	if (esdm_irq_status_fd >= 0) {
		ssize_t ret;

		esdm_irq_set_entropy_rate(esdm_irq_requested_bits_set);

		lseek(esdm_irq_status_fd, 0, SEEK_SET);
		do {
			ret = read(esdm_irq_status_fd, buf, buflen);
			if (ret > 0) {
				buflen -= (size_t)ret;
				buf += ret;
			}
		} while ((0 < ret || EINTR == errno) && buflen);
	} else {
		snprintf(buf, buflen, " disabled - missing kernel support\n");
	}
}

static void esdm_irq_reset(void)
{
	uint32_t reset[2];

	reset[0] = ESDM_ES_MGR_RESET_BIT;
	reset[1] = 0;

	if (esdm_irq_entropy_fd >= 0) {
		ssize_t ret;

		lseek(esdm_irq_entropy_fd, 0, SEEK_SET);
		ret = write(esdm_irq_entropy_fd, &reset, sizeof(reset));

		if (ret != sizeof(reset)) {
			logger(LOGGER_ERR, LOGGER_C_ES,
			       "Reset of interrupt entropy source failed\n");
		} else {
			esdm_irq_seed_init();
		}
	}
}

struct esdm_es_cb esdm_es_irq = {
	.name			= "Interrupt",
	.init			= esdm_irq_initialize,
	.fini			= esdm_irq_finalize,
	.get_ent		= esdm_irq_get,
	.curr_entropy		= esdm_irq_entropylevel,
	.max_entropy		= esdm_irq_poolsize,
	.state			= esdm_irq_es_state,
	.reset			= esdm_irq_reset,
	.switch_hash		= NULL,
};
