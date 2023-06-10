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
#include <unistd.h>

#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_irq.h"
#include "helper.h"
#include "logger.h"
#include "memset_secure.h"
#include "test_pertubation.h"

static int esdm_irq_entropy_fd = -1;
static int esdm_irq_status_fd = -1;
static uint32_t esdm_irq_requested_bits_set = 0;
static enum esdm_es_data_size esdm_irq_data_size = esdm_es_data_equal;

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
	esdm_kernel_set_requested_bits(&esdm_irq_requested_bits_set,
				       requested_bits, esdm_irq_entropy_fd);
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

static int esdm_irq_seed_monitor(void)
{
	uint32_t ent = esdm_irq_entropylevel(esdm_security_strength());

	if (!esdm_config_es_irq_entropy_rate())
		return 0;

	if (ent >= esdm_config_es_irq_entropy_rate()) {
		logger(LOGGER_DEBUG, LOGGER_C_ES,
			"Full entropy of interrupt ES detected\n");
		esdm_es_add_entropy();
		esdm_test_seed_entropy(ent);

		return 0;
	}
	return -EAGAIN;
}

static int esdm_irq_initialize(void)
{
	uint32_t status[2];
	ssize_t readlen;

	/* Allow the init function to be called multiple times */
	esdm_irq_finalize();

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

	if (status[0] == sizeof(struct entropy_es)) {
		esdm_irq_data_size = esdm_es_data_equal;
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "Kernel entropy buffer has equal size as ESDM\n");
	} else if (status[0] == sizeof(struct entropy_es_small)) {
		esdm_irq_data_size = esdm_es_data_small;
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "Kernel entropy buffer has smaller size as ESDM - IRQ ES alone will never be able to fully seed the ESDM\n");
	} else if (status[0] == sizeof(struct entropy_es_large)) {
		esdm_irq_data_size = esdm_es_data_large;
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "Kernel entropy buffer has larger size as ESDM\n");
	} else {
		logger(LOGGER_ERR, LOGGER_C_ES,
		       "Kernel entropy buffer has different size\n");
		esdm_irq_finalize();
		return -EFAULT;
	}

	esdm_irq_status_fd = open("/sys/kernel/debug/esdm_es/status_irq",
				  O_RDWR);
	if (esdm_irq_entropy_fd < 0) {
		esdm_irq_finalize();
		return 0;
	}

	/*
	 * The presence of the interrupt entropy source implies that the main
         * entropy source of the kernel random.c is being taken away.
	 */
	esdm_config_es_krng_entropy_rate_set(
		ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY);

	esdm_es_add_entropy();

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
	if (esdm_irq_entropy_fd < 0)
		goto err;

	esdm_irq_set_requested_bits(requested_bits);

	esdm_kernel_read(eb_es, esdm_irq_entropy_fd, esdm_irq_data_size,
			 esdm_es_irq.name);

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
		}
	}
}

static bool esdm_irq_active(void)
{
	return (esdm_irq_entropy_fd != -1);
}

struct esdm_es_cb esdm_es_irq = {
	.name			= "Interrupt",
	.init			= esdm_irq_initialize,
	.monitor_es		= esdm_irq_seed_monitor,
	.fini			= esdm_irq_finalize,
	.get_ent		= esdm_irq_get,
	.curr_entropy		= esdm_irq_entropylevel,
	.max_entropy		= esdm_irq_poolsize,
	.state			= esdm_irq_es_state,
	.reset			= esdm_irq_reset,
	.active			= esdm_irq_active,
	.switch_hash		= NULL,
};
