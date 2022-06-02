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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "env.h"
#include "privileges.h"

static int esdm_cuse_fips_enabled(void)
{
	static char fipsflag[1] = { 'A' };
	size_t n = 0;

	if (fipsflag[0] == 'A') {
#ifdef HAVE_SECURE_GETENV
		if (secure_getenv("ESDM_SERVER_FORCE_FIPS")) {
#else
		if (getenv("ESDM_SERVER_FORCE_FIPS")) {
#endif
			fipsflag[0] = 1;
		} else {
			FILE *fipsfile = NULL;

			fipsfile = fopen("/proc/sys/crypto/fips_enabled", "r");
			if (!fipsfile) {
				if (errno == ENOENT) {
					/* FIPS support not enabled in kernel */
					return 0;
				} else {
					printf("FIPS: Cannot open fips_enabled file: %s\n",
					       strerror(errno));
					return -EIO;
				}
			}

			n = fread((void *)fipsflag, 1, 1, fipsfile);
			fclose(fipsfile);
			if (n != 1) {
				printf("FIPS: Cannot read FIPS flag\n");
				return 0;
			}
		}
	}

	return (fipsflag[0] == '1');
}

/******************************************************************************/

/**
 * Test RNDADDENTROPY IOCTL with its operation and the privilege checks
 *
 * Expected: When called with UID 0 -> IOCTL succeeds, otherwise fails
 */
static int addent_ioctl(int fd, int exp)
{
	struct rand_pool_info *rpi;
	uint32_t ent_count_bits, ent_count_bits2;
	int ret = 1;

	rpi = calloc(1, (sizeof(struct rand_pool_info) + 20 * sizeof(char)));
	if (!rpi)
		return 1;
	rpi->entropy_count = 64 + 10;
	rpi->buf_size = 20 * sizeof(char);

	ret = ioctl(fd, RNDADDENTROPY, rpi);
	if (ret != exp) {
		printf("RNDADDENTROPY IOCTL failed: expected result %d, returned result %d\n", exp, ret);
		ret = 1;
		goto out;
	}

	printf("RNDADDENTROPY: passed\n");

	if (exp == -1) {
		ret = 0;
		goto out;
	}

	ret = ioctl(fd, RNDCLEARPOOL);
	if (ret != 0) {
		printf("RNDCLEARPOOL IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}
	ret = ioctl(fd, RNDGETENTCNT, &ent_count_bits);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}
	ret = ioctl(fd, RNDADDENTROPY, rpi);
	if (ret != 0) {
		printf("RNDADDENTROPY IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}
	ret = ioctl(fd, RNDGETENTCNT, &ent_count_bits2);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}

	if (esdm_cuse_fips_enabled()) {
		/* Note, we have to account for oversampling of entropy */
		if (ent_count_bits2 - ent_count_bits < 10) {
			printf("RNDADDENTROPY failed to add entropy: %u %u\n",
			ent_count_bits2, ent_count_bits);
			ret = 1;
			goto out;
		}
	} else {
		if (ent_count_bits2 != ent_count_bits) {
			printf("RNDADDENTROPY failed: added in normal mode: %u %u\n",
			ent_count_bits2, ent_count_bits);
			ret = 1;
			goto out;
		}
	}

	printf("RNDADDENTROPY: passed to add entropy\n");
	ret = 0;

out:
	if (rpi)
		free(rpi);
	return ret;
}

static int test_ioctl(const char *path, int exp)
{
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = errno;
		printf("Cannot open file %s: %d\n", path, ret);
		return -ret;
	}

	ret = addent_ioctl(fd, exp);

	if (fd >= 0)
		close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = env_init(1);
	if (ret)
		return ret;

	ret = check_priv();
	if (ret)
		return ret;

	drop_privileges();
	printf("============== Unprivileged Tests ============================\n");
	ret = test_ioctl(argv[1], -1);
	raise_privilege();
	printf("============== Privileged Tests ============================\n");
	ret += test_ioctl(argv[1], 0);
	drop_privileges();
	printf("============== Unprivileged Tests ============================\n");
	ret += test_ioctl(argv[1], -1);

	env_fini();

	return ret;
}
