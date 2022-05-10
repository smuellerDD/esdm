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
 * Test poll system call to wait for not fully seeded ESDM
 *
 * Expected: poll waits
 */
static int test_poll_read(const char *path)
{
	struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
	fd_set fds;
	uint32_t bits = 64 + 512;
	int ret = 0, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = errno;
		printf("Cannot open file %s: %d\n", path, ret);
		return -ret;
	}

	/* Ensure we are fully seeded - no write poll should be needed */
	ret = ioctl(fd, RNDADDTOENTCNT, &bits, sizeof(bits));
	if (ret != 0) {
		printf("RNDADDTOENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	/* ESDM is fully seeded - select should succeed */
	ret = select((fd + 1), &fds, NULL, NULL, &timeout);
	if (ret == 0) {
		printf("Poll - failed: read select timed out for full ESDM\n");
		ret = 1;
		goto out;
	} else if (ret == -1) {
		printf("Poll - failed: write select returns unexpected error code for empty ESDM: %u\n",
		       errno);
		ret = 1;
		goto out;
	} else {
		printf("Poll - passed: read select returned available FD for full ESDM!\n");
	}

	/* Clear the entropy pool */
	ret = ioctl(fd, RNDCLEARPOOL, &bits, sizeof(bits));
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}

	/*
	 * Cause reseed 3 times - after 2nd call the ESDM should become
	 * unseeded.
	 */
	ret = ioctl(fd, RNDRESEEDCRNG);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}
	ret = ioctl(fd, RNDCLEARPOOL, &bits, sizeof(bits));
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}
	ret = ioctl(fd, RNDRESEEDCRNG);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}
	ret = ioctl(fd, RNDCLEARPOOL, &bits, sizeof(bits));
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}
	ret = ioctl(fd, RNDRESEEDCRNG);
	if (ret != 0) {
		printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	/*
	 * As we have no entropy, the select should immediately return to
	 * tell us it wants new entropy.
	 */
	ret = select((fd + 1), &fds, NULL, NULL, &timeout);
	if (ret == 0) {
		printf("Poll - passed: read select with unseeded ESDM times out\n");
	} else if (ret == -1) {
		printf("Poll - failed: write select returns unexpected error code: %u\n",
		       errno);
		ret = 1;
		goto out;
	} else {
		printf("Poll - failed: read select returned available FD for unseeded ESDM!\n");
		ret = 1;
		goto out;
	}

	/* Ensure we are fully seeded - no write poll should be needed */
	ret = ioctl(fd, RNDADDTOENTCNT, &bits, sizeof(bits));
	if (ret != 0) {
		printf("RNDADDTOENTCNT IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	/* Test again to verify that ESDM correctly unblocks again */
	ret = select((fd + 1), &fds, NULL, NULL, &timeout);
	if (ret == 0) {
		printf("Poll - failed: read select timed out for full ESDM\n");
		ret = 1;
		goto out;
	} else if (ret == -1) {
		printf("Poll - failed: write select returns unexpected error code for empty ESDM: %u\n",
		       errno);
		ret = 1;
		goto out;
	} else {
		printf("Poll - passed: read select returned available FD for full ESDM!\n");
	}

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = env_init();
	if (ret)
		return ret;

	ret = check_priv();
	if (ret)
		return ret;

	ret = test_poll_read(argv[1]);

	env_fini();

	return ret;
}
