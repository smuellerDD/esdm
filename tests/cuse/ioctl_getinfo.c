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
#include <unistd.h>

#include "env.h"
#include "esdm_rpc_service.h"
#include "privileges.h"

/******************************************************************************/

/**
 * Test get information IOCTL with its operation
 *
 * Expected: When called with UID 0 -> IOCTL succeeds, otherwise fails
 */
static int getinfo_ioctl(int fd)
{
	char buf[ESDM_SHM_STATUS_INFO_SIZE];
	size_t len;
	char *buf_p;
	int ret = 1;

	buf[0] = '\0';

	ret = ioctl(fd, 42, buf, sizeof(buf));
	if (ret < 0) {
		printf("get info IOCTL failed: returned result %d\n", ret);
		ret = 1;
		goto out;
	}

	printf("RNDADDENTROPY: passed\n");

	len = strlen(buf);
	if (len == 0 || len > sizeof(buf)) {
		printf("get info IOCTL failed: unexpected data buffer received\n");
		ret = 1;
		goto out;
	}

	buf_p = strstr(buf, "ESDM");
	if (!buf_p) {
		if (len == 0 || len > sizeof(buf)) {
			printf("get info IOCTL failed: unexpected data contents received\n");
			ret = 1;
			goto out;
		}
	}

	printf("get info IOCTL: passed to obtain status\n");
	ret = 0;

out:
	return ret;
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

	ret = getinfo_ioctl(fd);

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
