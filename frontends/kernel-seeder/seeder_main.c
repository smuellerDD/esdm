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

#define _GNU_SOURCE

#include <esdm_rpc_client.h>

#include <poll.h>

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
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "atomic_bool.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"
#include "systemd_support.h"

static atomic_bool_t should_run = ATOMIC_BOOL_INIT(true);
static int notify_fd = -1; /* event fd used to notify in case of termination */
static bool force_pr = false; /* force seeding kernel from pr instance of esdm */
static bool had_one_sucessful_seed = false; /* used for ready notification */

/*
 * modern Linux kernels have a 256 Bit entropy pool, always provide
 * twice the amount for full entropy inside the pool after leftover hashing
 * on pool updates.
 */
#define ESDM_SERVER_LINUX_ENTROPY_BYTES (2 * 32)

static bool pr_mode() {
#if defined(ESDM_AIS2031_NTG1_SEEDING_STRATEGY) || defined(ESDM_JENT_NTG1)
	return true;
#else
	return force_pr;
#endif
}

static int esdm_rpcs_linux_insert_entropy(struct rand_pool_info *rpi, bool force_crng_reseed)
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

	if (force_crng_reseed) {
		/* need to use ESDM cuse interface? */
		if (esdm_rpcs_linux_ioctl == 43)
			esdm_rpcs_linux_ioctl = 44;
		else {
			esdm_rpcs_linux_ioctl = RNDRESEEDCRNG;
		}

		errsv = ioctl(esdm_rpcs_linux_fd, esdm_rpcs_linux_ioctl);
		if (errsv != 0) {
			errsv = errno;
			esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
					"Error during forced Linux kernel CRNG reseed: %s\n", strerror(errsv));
		} else {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_SEEDER,
					"Linux kernel CRNG forcefully reseeded\n");
		}
	}

	close(esdm_rpcs_linux_fd);

	return -errsv;
}

static void usage(void)
{
	printf("esdm-kernel-seeder [-i --interval SECS] [-h --help] [-v --verbosity] [-p --force-pr]\n");
}

static int handle_reseeding(int64_t seeding_interval_secs)
{
	uint8_t rpi_buf[sizeof(struct rand_pool_info) +
			ESDM_SERVER_LINUX_ENTROPY_BYTES]
			__aligned(sizeof(uint32_t));
	struct rand_pool_info *rpi = (struct rand_pool_info *)rpi_buf;

	struct timespec ts;
	struct pollfd pfd;
	ssize_t ret;
	int pret;
	int fn_ret = EXIT_SUCCESS;

	rpi->buf_size = ESDM_SERVER_LINUX_ENTROPY_BYTES;

	while (atomic_bool_read(&should_run)) {
		if (pr_mode()) {
			ret = esdm_rpcc_get_random_bytes_pr(
				(uint8_t *)rpi->buf,
				(size_t)rpi->buf_size
			);
		} else {
			ret = esdm_rpcc_get_random_bytes_full(
				(uint8_t *)rpi->buf,
				(size_t)rpi->buf_size
			);
		}

		if (ret < 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
				    "Failure in generating random bits: %zd\n",
				    ret);
		} else {
			rpi->entropy_count = ESDM_LINUX_RESEED_ENTROPY_COUNT;
			if (pr_mode()) {
				/*
				 * Immediately force CRNG reseed in NTG.1/PR mode
				 *
				 * While not strictly necessary, this enables you
				 * to better reason, when your seeds take effect
				 * and allows control via the reseeding interval in secs,
				 * without using another small daemon.
				 */
				ret = esdm_rpcs_linux_insert_entropy(rpi, true);
			} else {
				ret = esdm_rpcs_linux_insert_entropy(rpi, false);
			}
		}

		memset_secure(rpi->buf, 0, (size_t)rpi->buf_size);
		rpi->entropy_count = 0;

		if (ret == 0 && !had_one_sucessful_seed) {
			(void)systemd_notify_ready();
			systemd_notify_status("Running");
			had_one_sucessful_seed = true;
		}

		pfd.fd = notify_fd;
		pfd.events = POLL_IN;
		pfd.revents = 0;

		/* Wake up every 2 minutes by default */
		ts.tv_sec = seeding_interval_secs;
		ts.tv_nsec = 0;

		pret = ppoll(&pfd, 1,&ts, NULL);

		/* error */
		if (pret == -1 && errno != EINTR) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
					"ppoll returned with error %s\n",
					strerror(errno));
			goto out;
		}

		/* activity */
		if (pret > 0) {
			uint64_t event;
			ssize_t read_ret;

			/* make compiler happy */
			read_ret = read(notify_fd, &event, sizeof(event));
			(void) read_ret;
			fn_ret = EXIT_FAILURE;
			goto out;
		}
	}

out:
	return fn_ret;
}

/* terminate the daemon cleanly */
static void sig_term(int sig)
{
	static const uint64_t event_inc = 1;

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
	if (notify_fd > 0) {
		ssize_t write_ret;

		/* make compiler happy */
		write_ret = write(notify_fd, &event_inc, sizeof(event_inc));
		(void) write_ret;
	}
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
						{ "force-pr", 0, 0, 0 },
						{ 0, 0, 0, 0 } };
		c = getopt_long(argc, argv, "i:hvsp", opts, &opt_index);
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
			case 4:
				/* force_pr */
				force_pr = true;
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
		case 'p':
			force_pr = true;
			break;
		}
	}

	esdm_logger_set_verbosity((enum esdm_logger_verbosity)verbosity);

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

	systemd_notify_status("Starting");

	notify_fd = eventfd(0, EFD_CLOEXEC);
	if (notify_fd < 0) {
		esdm_logger_inc_verbosity();
		esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
			    "Unable to create event fd for termination notification!\n");
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
	if (pr_mode()) {
		esdm_logger(LOGGER_STATUS, LOGGER_C_SEEDER,
		    "Using prediction resistant mode to seed kernel!\n");
	}

	systemd_notify_status("Waiting for initial kernel seed operation");

	tool_ret = handle_reseeding(seeding_interval_secs);

	esdm_rpcc_fini_unpriv_service();

	systemd_notify_stopping();

out:
	if (notify_fd > 0)
		close(notify_fd);
	notify_fd = -1;
	return tool_ret;
}
