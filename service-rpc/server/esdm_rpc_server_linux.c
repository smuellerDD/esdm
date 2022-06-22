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
#include <linux/random.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_rpc_server_linux.h"
#include "helper.h"
#include "logger.h"
#include "memset_secure.h"
#include "threading_support.h"

static int esdm_rpcs_linux_insert_entropy(struct rand_pool_info *rpi)
{
	struct stat statfs;
	unsigned long esdm_rpcs_linux_ioctl = RNDADDENTROPY;
	int esdm_rpcs_linux_fd = -1;
	int errsv = 0;

	/* TODO: The name "esdm" must be synchronized with cuse_random.c */

	/*
	 * First we attempt to access /dev/esdm. If this exists, we know
	 * that the CUSE /dev/random server is active. In this case we
	 * give the data to the CUSE /dev/random server which sends the
	 * data to the kernel. Otherwise we use /dev/random directly.
	 */
	if (stat("/dev/esdm", &statfs) < 0) {
		if (errno == ENOENT) {
			/*
			 * If /dev/esdm does not exist, we assume we can open
			 * /dev/random directly.
			 */
			if (stat("/dev/random", &statfs) < 0) {
				errsv = errno;

				logger(LOGGER_ERR, LOGGER_C_SERVER,
				       "Error in accessing /dev/random: %s\n", strerror(errsv));
				return -errsv;
			}

			esdm_rpcs_linux_fd = open("/dev/random", 0);
			if (esdm_rpcs_linux_fd < 0) {
				errsv = errno;

				logger(LOGGER_ERR, LOGGER_C_SERVER,
				       "Error in opening /dev/random: %s\n", strerror(errsv));
				return -errsv;
			}
			logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			       "/dev/random opened to insert entropy\n");
		} else if (errno) {
			errsv = errno;

			logger(LOGGER_ERR, LOGGER_C_SERVER,
			       "Error in accessing /dev/esdm: %s\n",
			       strerror(errsv));
			return -errsv;
		}
	} else {
		esdm_rpcs_linux_fd = open("/dev/esdm", 0);
		if (esdm_rpcs_linux_fd < 0) {
			errsv = errno;

			logger(LOGGER_ERR, LOGGER_C_SERVER,
			       "Error in opening /dev/esdm: %s\n", strerror(errsv));
			return -errsv;
		}
		logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		       "/dev/esdm opened to insert entropy\n");

		/* Use the special IOCTL from the CUSE server */
		esdm_rpcs_linux_ioctl = 43;
	}

	errsv = ioctl(esdm_rpcs_linux_fd, esdm_rpcs_linux_ioctl, rpi);
	if (errsv != 0) {
		errsv = errno;
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "Error in adding entropy: %s\n", strerror(errsv));
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		       "Entropy data with rate %u bits added\n",
		       rpi->entropy_count);
	}

	close(esdm_rpcs_linux_fd);

	return -errsv;
}

static int esdm_rpcs_linux_feed_kernel(void __unused *unused)
{
#define ESDM_SERVER_LINUX_ENTROPY_BYTES	32

	uint8_t rpi_buf[sizeof(struct rand_pool_info) +
			ESDM_SERVER_LINUX_ENTROPY_BYTES]
						__aligned(sizeof(uint32_t));
	struct rand_pool_info *rpi = (struct rand_pool_info *)rpi_buf;
	struct esdm_status_st status;

	/* Wake up every 2 minutes */
	struct timespec ts = { .tv_sec = 120, .tv_nsec = 0 };
	ssize_t ret;

	rpi->buf_size = ESDM_SERVER_LINUX_ENTROPY_BYTES;

	for (;;) {
		/* Only keep going if the IRQ entropy source is available */
		esdm_status_machine(&status);
		if (!status.es_irq_enabled)
			break;

		ret = esdm_get_random_bytes_full((uint8_t *)rpi->buf,
						 (size_t)rpi->buf_size);
		if (ret < 0) {
			logger(LOGGER_ERR, LOGGER_C_SERVER,
			       "Failure in generating random bits: %zd\n", ret);
		} else {
			rpi->entropy_count = (int)((ret) << 3);
			esdm_rpcs_linux_insert_entropy(rpi);
		}

		memset_secure(rpi->buf, 0, (size_t)rpi->buf_size);
		rpi->entropy_count = 0;

		nanosleep(&ts, NULL);
	}

	return 0;
}

int esdm_rpcs_linux_init_feeder(void)
{
	/*
	 * Re-purpose ESDM_THREAD_CUSE_POLL_GROUP which is not used otherwise
	 * in RPC server process.
	 */
	int ret = thread_start(esdm_rpcs_linux_feed_kernel, NULL,
			       ESDM_THREAD_CUSE_POLL_GROUP, NULL);

	if (ret) {
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "Starting the Linux kernel feeder thread failed: %d\n",
		       ret);
	}

	return ret;
}
