/*
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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "env.h"
#include "privileges.h"

static void create_sched_entropy(void)
{
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		pid_t pid = fork();

		if (pid == 0)
			exit(0);
		else if (pid > 0)
			waitpid(pid, NULL, 0);
	}
}

/**
 * Test RNDADDTOENTCNT IOCTL with its operation and the privilege checks
 *
 * Expected: When called with UID 0 -> IOCTL succeeds, otherwise fails
 */
static int clear_ioctl(int fd, int exp)
{
	uint32_t ent_count_bits, ent_count_bits2, bits = 64 + 10;
	int ret = 0;

	ret = ioctl(fd, RNDCLEARPOOL, &bits);
	if (ret != exp) {
		printf("RNDADDTOENTCNT IOCTL failed: expected result %d, returned result %d\n",
		       exp, ret);
		return 1;
	}

	printf("RNDCLEARPOOL: passed\n");

	if (exp == -1)
		return 0;

	ret = ioctl(fd, RNDADDTOENTCNT, &bits);
	if (ret != 0) {
		printf("RNDADDTOENTCNT IOCTL failed: with %d\n", errno);
		return 1;
	}

	/*
	 * Fill all slow entropy sources such that they cannot violate this
	 * test by adding new entropy intermittently.
	 */
	create_sched_entropy();

	ret = ioctl(fd, RNDGETENTCNT, &ent_count_bits);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		return 1;
	}

	ret = ioctl(fd, RNDCLEARPOOL, &bits);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		return 1;
	}
	ret = ioctl(fd, RNDGETENTCNT, &ent_count_bits2);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		return 1;
	}
	if (ent_count_bits2 >= ent_count_bits) {
		printf("RNDCLEARPOOL failed to clear entropy: before %u, after %u\n",
		       ent_count_bits, ent_count_bits2);
		return 1;
	}

	printf("RNDCLEARPOOL: passed to clear entropy\n");

	return 0;
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

	ret = clear_ioctl(fd, exp);

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
