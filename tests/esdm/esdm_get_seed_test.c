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
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "logger.h"
#include "test_pertubation.h"

int main(int argc, char *argv[])
{
	uint8_t buf[2048];
	uint8_t buf2;
	int ret;
	ssize_t rc;
	size_t len;
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

	len = sizeof(buf2);
	rc = esdm_get_seed(&buf2, &len, ESDM_GET_SEED_NONBLOCK);
	if (rc != -EMSGSIZE) {
		printf("esdm_get_seed does not indicate that the buffer is too small\n");
		ret = 1;
		goto out;
	}
	if (len <= sizeof(buf2)) {
		printf("esdm_get_seed does not return seed buffer size\n");
		ret = 1;
		goto out;
	}
	if (len > sizeof(buf)) {
		printf("esdm_get_seed specifies a buffer that is too large: %zu\n", len);
		ret = 1;
		goto out;
	}

	len = sizeof(buf);
	rc = esdm_get_seed(buf, &len,
			   ESDM_GET_SEED_NONBLOCK | ESDM_GET_SEED_FULLY_SEEDED);
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

	if (rc < (force_fips ? 384 : 128)) {
		printf("esdm_get_seed returned insufficient seed: %zd\n", rc);
		ret = 1;
		goto out;
	}

	len = sizeof(buf);
	rc = esdm_get_seed(buf, &len, ESDM_GET_SEED_NONBLOCK);
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

	if (rc < (force_fips ? 256 : 128)) {
		printf("esdm_get_seed returned insufficient seed: %zd\n", rc);
		ret = 1;
		goto out;
	}

out:
	esdm_fini();
	return ret;
}
