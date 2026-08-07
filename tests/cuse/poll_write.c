/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include "esdm_rpc_service.h"
#include "privileges.h"

/*
 * Read a numeric field out of the ESDM status report.
 *
 * The write poll reports "entropy wanted" for as long as esdm_need_entropy()
 * holds, which compares the aux pool against esdm_write_wakeup_bits - a
 * threshold of ESDM_NUM_AUX_POOLS * digestsize, so it scales with the
 * configuration. Ask the ESDM rather than assume a single-pool value.
 */
static int status_value(int fd, const char *field, uint32_t *value)
{
	char status[ESDM_SHM_STATUS_INFO_SIZE + 1];
	const char *p;

	memset(status, 0, sizeof(status));
	if (ioctl(fd, 42, status, ESDM_SHM_STATUS_INFO_SIZE) < 0) {
		printf("Status IOCTL failed with %d\n", errno);
		return 1;
	}
	status[ESDM_SHM_STATUS_INFO_SIZE] = '\0';

	p = strstr(status, field);
	if (!p) {
		printf("Status report contains no \"%s\" field\n", field);
		return 1;
	}

	if (sscanf(p + strlen(field), "%u", value) != 1) {
		printf("Cannot parse the \"%s\" field of the status report\n",
		       field);
		return 1;
	}

	return 0;
}

/*
 * Supply entropy until the ESDM holds as much as its write wakeup threshold
 * demands, i.e. until it stops asking for more.
 *
 * RNDADDENTROPY rather than RNDADDTOENTCNT: the latter reaches
 * esdm_pool_set_entropy(), which only ever touches the first aux pool and sets
 * rather than accumulates, so it cannot lift the total above one pool's worth
 * while the threshold covers all of them. RNDADDENTROPY inserts into whichever
 * pool has the most unused capacity and so fills them all.
 */
static int fill_aux_pool(int fd)
{
	struct rand_pool_info *rpi;
	uint32_t threshold, digestsize, ent = 0;
	unsigned int i, max_rounds;
	size_t buflen;
	int ret = 1;

	if (status_value(fd, "Write wakeup threshold: ", &threshold))
		return 1;
	if (status_value(fd, "Digestsize: ", &digestsize))
		return 1;
	if (!digestsize) {
		printf("Status report claims a digest size of zero\n");
		return 1;
	}

	/* A single insertion is capped at one digest worth of entropy */
	buflen = digestsize / 8;
	rpi = calloc(1, sizeof(struct rand_pool_info) + buflen);
	if (!rpi)
		return 1;
	rpi->entropy_count = (int)digestsize;
	rpi->buf_size = (int)buflen;
	memset(rpi->buf, 0xa5, buflen);

	/*
	 * One round per pool would do, but an insertion also triggers a reseed
	 * which consumes entropy again, so leave generous room. The loop exits
	 * on the pool level rather than on a round count either way.
	 */
	max_rounds = (threshold / digestsize + 2) * 4 + 64;

	for (i = 0; i < max_rounds; i++) {
		if (ioctl(fd, RNDADDENTROPY, rpi) != 0) {
			printf("RNDADDENTROPY IOCTL failed: with %d\n", errno);
			goto out;
		}

		if (ioctl(fd, RNDGETENTCNT, &ent) != 0) {
			printf("RNDGETENTCNT IOCTL failed: with %d\n", errno);
			goto out;
		}

		if (ent >= threshold) {
			ret = 0;
			goto out;
		}
	}

	printf("Poll - failed: aux pool stalled at %u bits after %u rounds, write wakeup threshold is %u\n",
	       ent, max_rounds, threshold);

out:
	free(rpi);
	return ret;
}

/**
 * Test poll system call to wait for insufficient entropy
 *
 * Expected: poll waits
 */
static int test_poll_write(const char *path)
{
	struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
	fd_set fds;
	int ret = 0, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = errno;
		printf("Cannot open file %s: %d\n", path, ret);
		return -ret;
	}

	/*
	 * The write poll only sleeps once all DRNGs are seeded and the aux pool
	 * holds what the write wakeup threshold asks for.
	 */
	ret = fill_aux_pool(fd);
	if (ret)
		goto out;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	/* ESDM is fully seeded - select should block */
	ret = select((fd + 1), NULL, &fds, NULL, &timeout);
	if (ret == 0) {
		printf("Poll - passed: write select with fully seeded ESDM times out\n");
	} else if (ret == -1) {
		printf("Poll - failed: write select returns unexpected error code: %u\n",
		       errno);
		ret = 1;
		goto out;
	} else {
		printf("Poll - failed: write select returned available FD for fully seeded ESDM!\n");
		ret = 1;
		goto out;
	}

	/* Clear the entropy pool */
	ret = ioctl(fd, RNDCLEARPOOL);
	if (ret != 0) {
		printf("RNDCLEARPOOL IOCTL failed: with %d\n", errno);
		ret = 1;
		goto out;
	}

	/*
	 * As we have no entropy, the select should immediately return to
	 * tell us it wants new entropy.
	 */
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	ret = select((fd + 1), NULL, &fds, NULL, &timeout);
	if (ret == 0) {
		printf("Poll - failed: write select timed out for empty ESDM\n");
		ret = 1;
		goto out;
	} else if (ret == -1) {
		printf("Poll - failed: write select returns unexpected error code for empty ESDM: %u\n",
		       errno);
		ret = 1;
		goto out;
	} else {
		printf("Poll - passed: write select returned available FD for empty ESDM!\n");
	}

	/* Refill so no write poll should be needed any more */
	ret = fill_aux_pool(fd);
	if (ret)
		goto out;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	/* Test again to verify that ESDM correctly blocks again */
	ret = select((fd + 1), NULL, &fds, NULL, &timeout);
	if (ret == 0) {
		printf("Poll - passed: write select with fully seeded ESDM times out\n");
	} else if (ret == -1) {
		printf("Poll - failed: write select returns unexpected error code: %u\n",
		       errno);
		ret = 1;
		goto out;
	} else {
		printf("Poll - failed: write select returned available FD for fully seeded ESDM!\n");
		ret = 1;
		goto out;
	}

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	char devfile[20];
	int ret;

	(void)argc;
	(void)argv;

	if (!argc)
		return 1;

	esdm_cuse_dev_file(devfile, sizeof(devfile), argv[1]);

	ret = env_init(1);
	if (ret)
		return ret;

	ret = check_priv();
	if (ret)
		return ret;

	ret = test_poll_write(devfile);

	env_fini();

	return ret;
}
