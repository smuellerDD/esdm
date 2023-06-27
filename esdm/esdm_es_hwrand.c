/*
 * ESDM Fast Entropy Source: Linux /dev/hwrng-based entropy source
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
#define ESDM_ES_HWRAND_IF    "/dev/hwrng"

static int esdm_hwrand_fd = -1;

static void esdm_hwrand_finalize(void)
{
	if (esdm_hwrand_fd >= 0)
		close(esdm_hwrand_fd);
	esdm_hwrand_fd = -1;
}

static int esdm_hwrand_init(void)
{
	char buf[1];
	size_t buflen = 1;
	int fd;

	/* Allow the init function to be called multiple times */
	esdm_hwrand_finalize();

	esdm_hwrand_fd = open(ESDM_ES_HWRAND_IF, O_RDONLY);
	if (esdm_hwrand_fd < 0) {
		logger(LOGGER_WARN, LOGGER_C_ES,
		       "Disabling /dev/hwrng-based entropy source as device not present, error opening %s: %s\n",
		       ESDM_ES_HWRAND_IF, strerror(errno));
		return 0;
	}

	/* Check the presence of RNG-providers */
	fd = open(ESDM_ES_HWRAND_AVAIL, O_RDONLY);
	if (fd >= 0) {
		if (esdm_safe_read(fd, (uint8_t *)buf, buflen) &&
	            buf[0] == '\n') {
			logger(LOGGER_WARN, LOGGER_C_ES,
			       "Disabling /dev/hwrng-based entropy source as it has no backing device\n");
			close(esdm_hwrand_fd);
			esdm_hwrand_fd = -1;
		}
		close(fd);
	}

	return 0;
}

static uint32_t esdm_hwrand_entropylevel(uint32_t requested_bits)
{
	if (esdm_hwrand_fd < 0)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_hwrand_entropy_rate(), requested_bits);
}

static uint32_t esdm_hwrand_poolsize(void)
{
	if (esdm_hwrand_fd < 0)
		return 0;

	return esdm_hwrand_entropylevel(esdm_security_strength());
}

static void esdm_hwrand_get(struct entropy_es *eb_es, uint32_t requested_bits,
			    bool __unused unsused)
{
	if (esdm_hwrand_fd < 0)
		goto err;

	if (esdm_safe_read(esdm_hwrand_fd, eb_es->e, requested_bits >> 3))
		goto err;

	eb_es->e_bits = esdm_hwrand_entropylevel(requested_bits);
	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "obtained %u bits of entropy from /dev/hwrng RNG entropy source\n",
	       eb_es->e_bits);

	return;

err:
	eb_es->e_bits = 0;
}

static void esdm_hwrand_es_state(char *buf, size_t buflen)
{
	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n",
		 esdm_hwrand_poolsize(),
		 esdm_hwrand_entropylevel(256));
}

static bool esdm_hwrand_active(void)
{
	return (esdm_hwrand_fd != -1);
}

struct esdm_es_cb esdm_es_hwrand = {
	.name			= "LinuxHWRand",
	.init			= esdm_hwrand_init,
	.fini			= esdm_hwrand_finalize,
	.monitor_es		= NULL,
	.get_ent		= esdm_hwrand_get,
	.curr_entropy		= esdm_hwrand_entropylevel,
	.max_entropy		= esdm_hwrand_poolsize,
	.state			= esdm_hwrand_es_state,
	.reset			= NULL,
	.active			= esdm_hwrand_active,
	.switch_hash		= NULL,
};
