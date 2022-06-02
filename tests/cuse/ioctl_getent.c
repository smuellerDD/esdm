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

/**
 * Test RNDGETENTCNT IOCTL with its operation and the privilege checks
 *
 * Expected: Returns status irrespective of caller's UID
 */
static int getent_ioctl(int fd)
{
	uint32_t ent_count_bits;
	int ret = 0;

	ret = ioctl(fd, RNDGETENTCNT, &ent_count_bits);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		return 1;
	}

	printf("RNDGETENTCNT: passed - returned entropy %d\n", ent_count_bits);

	return 0;
}

static int test_ioctl(const char *path)
{
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = errno;
		printf("Cannot open file %s: %d\n", path, ret);
		return -ret;
	}

	ret = getent_ioctl(fd);

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
	ret = test_ioctl(argv[1]);
	raise_privilege();
	printf("============== Privileged Tests ============================\n");
	ret += test_ioctl(argv[1]);
	drop_privileges();
	printf("============== Unprivileged Tests ============================\n");
	ret += test_ioctl(argv[1]);

	env_fini();

	return ret;
}
