
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

#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

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

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "env.h"
#include "privileges.h"

static int read_random(const char *path, uint8_t *buf, size_t buflen)
{
	int fd;
	int ret = 0;

	fd = open(path, O_RDONLY|O_CLOEXEC);
	if (0 > fd)
		return fd;

	ret = read_complete(fd, buf, buflen);
	close(fd);
	return ret;
}


int main(int argc, char *argv[])
{
	uint8_t buf[1024];
	uint8_t zero[sizeof(buf)];
	size_t len = sizeof(buf);
	unsigned int read_ops = 0;
	int ret;

	if (!argc)
		return 1;

	ret = env_init(0);
	if (ret)
		return ret;

	drop_privileges();

	/* Establish server connection */
	read_random(argv[1], buf, len);

	env_kill_server();

	memset(zero, 0, sizeof(zero));

	while (len) {
		if (read_ops >= 5)
			break;
		read_ops++;

		memset(buf, 0, len);
		ret = read_random(argv[1], buf, len);
		if (ret)
			goto out;

		if (!memcmp(zero, buf, len)) {
			printf("output buffer is zero!\n");
			ret = 1;
			goto out;
		}
	}

out:
	env_fini();
	return ret;

}
