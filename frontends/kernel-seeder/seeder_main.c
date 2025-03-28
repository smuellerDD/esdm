/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include <esdm_rpc_client.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/random.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "atomic_bool.h"
#include "esdm_logger.h"
#include "memset_secure.h"

static atomic_bool_t should_run = ATOMIC_BOOL_INIT(true);

/* modern Linux kernels have a 256 Bit entropy pool, always fill the whole state
 * at once, to loose less entropy in leftover hashing on pool updates.
 */
#define ESDM_SERVER_LINUX_ENTROPY_BYTES 32

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

				esdm_logger(
					LOGGER_ERR, LOGGER_C_SEEDER,
					"Error in accessing /dev/random: %s\n",
					strerror(errsv));
				return -errsv;
			}

			esdm_rpcs_linux_fd = open("/dev/random", O_RDONLY);
			if (esdm_rpcs_linux_fd < 0) {
				errsv = errno;

				esdm_logger(
					LOGGER_ERR, LOGGER_C_SEEDER,
					"Error in opening /dev/random: %s\n",
					strerror(errsv));
				return -errsv;
			}
			esdm_logger(LOGGER_DEBUG, LOGGER_C_SEEDER,
				    "/dev/random opened to insert entropy\n");
		} else if (errno) {
			errsv = errno;

			esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
				    "Error in accessing /dev/esdm: %s\n",
				    strerror(errsv));
			return -errsv;
		}
	} else {
		esdm_rpcs_linux_fd = open("/dev/esdm", O_RDONLY);
		if (esdm_rpcs_linux_fd < 0) {
			errsv = errno;

			esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
				    "Error in opening /dev/esdm: %s\n",
				    strerror(errsv));
			return -errsv;
		}
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SEEDER,
			    "/dev/esdm opened to insert entropy\n");

		/* Use the special IOCTL from the CUSE server */
		esdm_rpcs_linux_ioctl = 43;
	}

	errsv = ioctl(esdm_rpcs_linux_fd, esdm_rpcs_linux_ioctl, rpi);
	if (errsv != 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
			    "Error in adding entropy: %s\n", strerror(errsv));
	} else {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SEEDER,
			    "Entropy data with rate %u bits added\n",
			    rpi->entropy_count);
	}

	close(esdm_rpcs_linux_fd);

	return -errsv;
}

static void usage(void)
{
	printf("esdm-kernel-seeder [-i --interval SECS] [-h --help] [-v --verbosity]\n");
}

static int handle_reseeding(int64_t seeding_interval_secs)
{
	uint8_t rpi_buf[sizeof(struct rand_pool_info) +
			ESDM_SERVER_LINUX_ENTROPY_BYTES];
	struct rand_pool_info *rpi = (struct rand_pool_info *)rpi_buf;

	/* Wake up every 2 minutes by default */
	struct timespec ts = { .tv_sec = seeding_interval_secs, .tv_nsec = 0 };
	ssize_t ret;

	rpi->buf_size = ESDM_SERVER_LINUX_ENTROPY_BYTES;

	while (atomic_bool_read(&should_run)) {
		ret = esdm_rpcc_get_random_bytes_full((uint8_t *)rpi->buf,
						      (size_t)rpi->buf_size);
		if (ret < 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
				    "Failure in generating random bits: %zd\n",
				    ret);
		} else {
			rpi->entropy_count = ESDM_LINUX_RESEED_ENTROPY_COUNT;
			esdm_rpcs_linux_insert_entropy(rpi);
		}

		memset_secure(rpi->buf, 0, (size_t)rpi->buf_size);
		rpi->entropy_count = 0;
		nanosleep(&ts, NULL);
	}

	return EXIT_SUCCESS;
}

/* terminate the daemon cleanly */
static void sig_term(int sig)
{
	(void)sig;
	esdm_logger(LOGGER_STATUS, LOGGER_C_SEEDER, "Shutting down cleanly\n");

	/* Prevent the kernel from interfering with the shutdown */
	signal(SIGALRM, SIG_IGN);

	/* If we got another termination signal, just get killed */
	signal(SIGHUP, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	atomic_bool_set_false(&should_run);
}

static void install_term(void)
{
	esdm_logger(LOGGER_STATUS, LOGGER_C_SEEDER,
		    "Install termination signal handler\n");
	signal(SIGHUP, sig_term);
	signal(SIGINT, sig_term);
	signal(SIGQUIT, sig_term);
	signal(SIGTERM, sig_term);
}

/*
 * Helper tool to insert entropy into the kernel RNG occasionally. When the IRQ ES
 * is present, this is required as the kernel RNG is deprived of its main ES.
 * But also in any other case it is good to insert data into the kernel RNG
 * to provide data that is gathered from other entropy sources. Basically
 * the ESDM acts as an RNGd to top up the entropy in the kernel.
 */
int main(int argc, char **argv)
{
	int c = 0;
	int64_t seeding_interval_secs = ESDM_LINUX_RESEED_INTERVAL_SEC;
	bool help = false;
	int tool_ret = EXIT_SUCCESS;
	int verbosity = 0;

	while (1) {
		int opt_index = 0;
		static struct option opts[] = { { "interval", 1, 0, 0 },
						{ "help", 0, 0, 0 },
						{ "verbosity", 0, 0, 0 },
						{ "syslog", 0, 0, 0 },
						{ 0, 0, 0, 0 } };
		c = getopt_long(argc, argv, "i:hvs", opts, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* seeding interval */
				seeding_interval_secs =
					strtoll(optarg, NULL, 10);
				break;
			case 1:
				/* help */
				help = true;
				break;
			case 2:
				/* verbosity */
				verbosity++;
				break;
			case 3:
				/* syslog */
				esdm_logger_enable_syslog("esdm-kernel-seeder");
				break;
			}
			break;
		case 'i':
			seeding_interval_secs = strtoll(optarg, NULL, 10);
			break;
		case 'h':
			help = true;
			break;
		case 'v':
			verbosity++;
			break;
		case 's':
			esdm_logger_enable_syslog("esdm-kernel-seeder");
			break;
		}
	}

	esdm_logger_set_verbosity(verbosity);

	if (help) {
		usage();
		tool_ret = EXIT_FAILURE;
		goto out;
	}

	if (geteuid()) {
		esdm_logger_inc_verbosity();
		esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
			    "Program must start as root!\n");
		tool_ret = EXIT_FAILURE;
		goto out;
	}

	if (esdm_rpcc_init_unpriv_service(NULL) != 0) {
		printf("unable to initialize unprivileged ESDM service, exiting!");
		tool_ret = EXIT_FAILURE;
		goto out;
	}

	install_term();

	esdm_logger(LOGGER_STATUS, LOGGER_C_SEEDER,
		    "Start kernel (re-)seeding with %li s interval!\n",
		    seeding_interval_secs);

	tool_ret = handle_reseeding(seeding_interval_secs);

	esdm_rpcc_fini_unpriv_service();

out:
	return tool_ret;
}
