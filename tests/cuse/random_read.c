
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

#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "env.h"
#include "privileges.h"
#include "test_pertubation.h"

static int read_complete(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	if (buflen > INT_MAX)
		return 1;

	do {
		ret = read(fd, buf, buflen);
		if (0 < ret) {
			buflen -= (size_t)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno) && buflen);

	if (buflen == 0)
		return 0;
	return 1;
}

static int read_random(const char *path, uint8_t *buf, size_t buflen)
{
	int fd;
	int ret = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (0 > fd)
		return fd;

	ret = read_complete(fd, buf, buflen);
	close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	char devfile[20];
	uint8_t buf[1024 * 1024];
	uint8_t zero[sizeof(buf)];
	size_t len = sizeof(buf);
	int ret;

	if (!argc)
		return 1;

	esdm_cuse_dev_file(devfile, sizeof(devfile), argv[1]);

	ret = env_init(1);
	if (ret)
		return ret;

	drop_privileges();

	memset(zero, 0, sizeof(zero));

	while (len) {
		unsigned short val;

		memset(buf, 0, len);
		ret = read_random(devfile, buf, len);
		if (ret)
			goto out;

		if (!memcmp(zero, buf, len)) {
			printf("output buffer is zero!\n");
			ret = 1;
			goto out;
		}

#ifdef ESDM_TESTMODE
		if (len != esdm_test_shm_status_get_rpc_client_written()) {
			printf("ERROR: amount of client data requested (%zu) does not match received data (%zu)\n",
			       len,
			       esdm_test_shm_status_get_rpc_client_written());
			ret = 1;
			goto out;
		} else {
			printf("PASS: amount of client data requested matches received data (%zu)\n",
			       len);
		}

		if (len != esdm_test_shm_status_get_rpc_server_written()) {
			printf("ERROR: amount of generated server data (%zu) does not match received data (%zu)\n",
			       esdm_test_shm_status_get_rpc_server_written(),
			       len);
			ret = 1;
			goto out;
		} else {
			printf("PASS: amount of generated server data matches written data (%zu)\n",
			       len);
		}
		esdm_test_shm_status_reset();
#endif

		val = (unsigned short)buf[0];
		val |= (unsigned short)(buf[1] << 8);
		len = (len > val) ? len - val : 0;
	}

out:
	env_fini();
	return ret;
}
