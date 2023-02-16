/*
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
#include "inttypes.h"
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_node.h"
#include "logger.h"
#include "test_pertubation.h"

int main(int argc, char *argv[])
{
	uint64_t buf[512 / sizeof(uint64_t)];
	uint64_t buf2;
	uint64_t size;
	uint32_t cpu;
	int ret;
	ssize_t rc;
	unsigned long val;
	unsigned int force_fips = 0;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	if (argc != 2)
		return 1;

	val = strtoul(argv[1], NULL, 10);
	if (val == ULONG_MAX)
		return errno;

	if (val) {
		esdm_config_force_fips_set(esdm_config_force_fips_enabled);
		force_fips = 1;
	} else
		esdm_config_force_fips_set(esdm_config_force_fips_disabled);

	logger_set_verbosity(LOGGER_DEBUG);
	ret = esdm_init();
	if (ret)
		return ret;

	rc = esdm_get_seed(&buf2, 1, ESDM_GET_SEED_NONBLOCK);
	if (rc != -EINVAL) {
		printf("esdm_get_seed does not indicate that the buffer is too small\n");
		ret = 1;
		goto out;
	}

	rc = esdm_get_seed(&size, sizeof(size), ESDM_GET_SEED_NONBLOCK);
	if (rc != -EMSGSIZE) {
		printf("esdm_get_seed does not indicate that the buffer is too small\n");
		ret = 1;
		goto out;
	}
	if (size > sizeof(buf)) {
		printf("esdm_get_seed specifies a buffer that is too large: %" PRIu64 "\n", size);
		ret = 1;
		goto out;
	}

	/*
	 * get_seed only returns data after all DRNGs are seeded, but each
	 * request only seeds one DRNG - thus allow requests up to the allowed
	 * number of DRNGs.
	 */
	for_each_online_node(cpu) {
		rc = esdm_get_seed(buf, sizeof(buf),
				   ESDM_GET_SEED_NONBLOCK |
				   ESDM_GET_SEED_FULLY_SEEDED);
		if (rc != -EAGAIN)
			break;

	}
	if (rc < 0) {
		printf("esdm_get_seed returned an error %zd\n", rc);
		ret = 1;
		goto out;
	}

	if (rc == 0) {
		printf("esdm_get_seed was unable to produce entropy\n");
		ret = 77;
		goto out;
	}

	if (buf[0] > sizeof(buf)) {
		printf("esdm_get_seed returned a strange size value %" PRIu64 "\n",
		       buf[0]);
		ret = 1;
		goto out;
	}

	if (buf[1] < (force_fips ? 384 : 128)) {
		printf("esdm_get_seed returned insufficient seed: %" PRIu64 "\n", buf[1]);
		ret = 1;
		goto out;
	} else {
		printf("esdm_get_seed returned proper seed size value %" PRIu64 " bytes and entropy value %" PRIu64 " bits\n",
		       buf[0], buf[1]);
	}

	rc = esdm_get_seed(buf, sizeof(buf), ESDM_GET_SEED_NONBLOCK);
	if (rc < 0) {
		printf("esdm_get_seed returned an error %zd\n", rc);
		ret = 1;
		goto out;
	}

	if (rc == 0) {
		printf("esdm_get_seed was unable to produce entropy\n");
		ret = 77;
		goto out;
	}

	if (buf[1] < (force_fips ? 256 : 128)) {
		printf("esdm_get_seed returned insufficient seed: %" PRIu64 "\n", buf[1]);
		ret = 1;
		goto out;
	} else {
		printf("esdm_get_seed returned proper seed size value %" PRIu64 " bytes and entropy value %" PRIu64 " bits\n",
		       buf[0], buf[1]);
	}

out:
	esdm_fini();
	return ret;
}
