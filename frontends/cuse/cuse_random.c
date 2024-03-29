/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cuse_device.h"
#include "cuse_helper.h"
#include "esdm_rpc_service.h"
#include "esdm_logger.h"
#include "ret_checkers.h"

static int random_fd = -1;

static void esdm_cuse_random_ioctl(fuse_req_t req, unsigned long cmd, void *arg,
				   struct fuse_file_info *fi, unsigned flags,
				   const void *in_buf, size_t in_bufsz,
				   size_t out_bufsz)
{
	esdm_cuse_ioctl(random_fd, req, cmd, arg, fi, flags, in_buf, in_bufsz,
			out_bufsz);
}

static void esdm_cuse_read_block(fuse_req_t req, size_t size, off_t off,
				 struct fuse_file_info *fi)
{
	esdm_cuse_read_internal(req, size, off, fi,
				esdm_rpcc_get_random_bytes_full_int, random_fd);
}

static void esdm_cuse_random_write(fuse_req_t req, const char *buf, size_t size,
				   off_t off, struct fuse_file_info *fi)
{
	esdm_cuse_write_internal(req, buf, size, off, fi, random_fd);
}

/* The ioctl defines the cmd as int, but in fact, it is unsigned long */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
static const struct cuse_lowlevel_ops esdm_dev_clop = {
	.init_done = esdm_cuse_init_done,
	.open = esdm_cuse_open,
	.read = esdm_cuse_read_block,
	.write = esdm_cuse_random_write,
	.ioctl = esdm_cuse_random_ioctl,
	.poll = esdm_cuse_poll,
	.release = esdm_cuse_release,
};
#pragma GCC diagnostic pop

int main(int argc, char *argv[])
{
	char devfile[20];
	unsigned int ctr = 0;
	int ret, errsv = 0;

	/* Open the fallback of the kernel device before overlaying it */
	do {
		random_fd = open("/dev/random", O_RDWR);
		if (random_fd < 0)
			errsv = errno;
		umount("/dev/random");
		ctr++;
	} while (errsv == ENXIO && ctr < 3);

	if (random_fd == -1) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Cannot open /dev/random: %s\n", strerror(errsv));
		return errsv;
	}

	CKINT(esdm_cuse_dev_file(devfile, sizeof(devfile), "random"));
	ret = main_common("esdm", devfile, ESDM_SEM_RANDOM_NAME, &esdm_dev_clop,
			  argc, argv);

out:
	close(random_fd);
	return ret;
}
