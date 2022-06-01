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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cuse_device.h"
#include "logger.h"

static int urandom_fd = -1;

static void esdm_cuse_urandom_ioctl(fuse_req_t req,
				    unsigned long cmd, void *arg,
				    struct fuse_file_info *fi, unsigned flags,
				    const void *in_buf, size_t in_bufsz,
				    size_t out_bufsz)
{
	esdm_cuse_ioctl(urandom_fd, req, cmd, arg, fi, flags, in_buf, in_bufsz,
			out_bufsz);
}

static void esdm_cuse_read_nonblock(fuse_req_t req, size_t size, off_t off,
				    struct fuse_file_info *fi)
{
	esdm_cuse_read_internal(req, size, off, fi, esdm_rpcc_get_random_bytes,
				urandom_fd);
}

static void esdm_cuse_urandom_write(fuse_req_t req, const char *buf,
				    size_t size, off_t off,
				    struct fuse_file_info *fi)
{
	esdm_cuse_write_internal(req, buf, size, off, fi, urandom_fd);
}

/* The ioctl defines the cmd as int, but in fact, it is unsigned long */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
static const struct cuse_lowlevel_ops esdm_dev_clop = {
	.init_done	= esdm_cuse_init_done,
	.open		= esdm_cuse_open,
	.read		= esdm_cuse_read_nonblock,
	.write		= esdm_cuse_urandom_write,
	.ioctl		= esdm_cuse_urandom_ioctl,
	.poll		= esdm_cuse_poll,
};
#pragma GCC diagnostic pop

int main(int argc, char *argv[])
{
	unsigned int ctr = 0;
	int ret, errsv = 0;

	/* Open the fallback of the kernel device before overlaying it */
	urandom_fd = open("/dev/urandom", O_RDONLY);
	do {
		urandom_fd = open("/dev/urandom", O_RDWR);
		if (urandom_fd < 0)
			errsv = errno;
		umount("/dev/urandom");
		ctr++;
	} while (errsv == ENXIO && ctr < 3);

	if (urandom_fd == -1) {
		errsv = errno;
		logger(LOGGER_ERR, LOGGER_C_CUSE,
		       "Cannot open /dev/urandom: %s\n", strerror(errsv));
		return errsv;
	}

	ret = main_common("uesdm", "/dev/urandom", &esdm_dev_clop, argc, argv);

	close(urandom_fd);

	return ret;
}
