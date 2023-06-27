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

static int write_complete(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	if (buflen > INT_MAX)
		return 1;

	do {
		ret = write(fd, buf, buflen);
		if (0 < ret) {
			buflen -= (size_t)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno) && buflen);

	if (buflen == 0)
		return 0;

	printf("Error code from write system call: %d\n", errno);
	return 1;
}

static int write_random(const char *path, uint8_t *buf, size_t buflen)
{
	int fd;
	int ret = 0;

	fd = open(path, O_WRONLY|O_CLOEXEC);
	if (0 > fd)
		return fd;

	ret = write_complete(fd, buf, buflen);
	close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	uint8_t buf[1024 * 1024];
	size_t len = sizeof(buf);
	int ret;

	if (!argc)
		return 1;

	ret = env_init(1);
	if (ret)
		return ret;

	drop_privileges();

	memset(buf, 1, len);

	while (len) {
		unsigned short val;

		ret = write_random(argv[1], buf, len);
		if (ret)
			goto out;

#ifdef ESDM_TESTMODE
		if (len != esdm_test_shm_status_get_rpc_client_written()) {
			printf("ERROR: amount of client data written (%zu) does not match written data (%zu)\n",
			       len,
			       esdm_test_shm_status_get_rpc_client_written());
			ret = 1;
			goto out;
		} else {
			printf("PASS: amount of client data written matches written data (%zu)\n", len);
		}

		if (len != esdm_test_shm_status_get_rpc_server_written()) {
			printf("ERROR: amount of server data written (%zu) does not match written data (%zu)\n",
			       len,
			       esdm_test_shm_status_get_rpc_server_written());
			ret = 1;
			goto out;
		} else {
			printf("PASS: amount of server data written matches written data (%zu)\n", len);
		}
		esdm_test_shm_status_reset();
#endif

		val = 7777;
		len = (len > val) ? len - val : 0;
	}

out:
	env_fini();
	return ret;

}
