/*
 * Copyright (C) 2025, Markus Theil <theil.markus@gmail.com>
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

#include "tool.h"
#include "config.h"
#include "esdm_logger.h"
#include "math_helper.h"

#include <errno.h>
#include <esdm_rpc_client.h>
#include <esdm_rpc_service.h>
#ifdef ESDM_HAS_AUX_CLIENT
#include <esdm_aux_client.h>
#endif
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define xstr(s) str(s)
#define str(s) #s

enum RANDOM_MODE {
	RAND_MODE_NONE = 0,
	RAND_MODE_MIN,
	RAND_MODE_FULL,
	RAND_MODE_FULL_TIMEOUT,
	RAND_MODE_PR,
};

/*
 * Commands
 */
static void handle_usage(void)
{
	fprintf(stderr, "\nesdm-tool\n\n");
	fprintf(stderr, "Version: " xstr(VERSION) "\n\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-h --help\t\t\tThis help information\n");
	fprintf(stderr,
		"\t-s --status\t\t\tShow status string of all entropy sources.\n");
	fprintf(stderr,
		"\t-S --is-fully-seeded\t\tCheck if ESDM is ready to return random bytes\n");
	fprintf(stderr,
		"\t-r --get-random BYTE\t\tGet BYTE random bytes (hex formatted)\n");
	fprintf(stderr,
		"\t-e --entropy-count\t\tGet number of accounted bits in entropy aux. pool\n");
	fprintf(stderr,
		"\t-E --entropy-level\t\tGet number of accounted bits in internal state\n");
	fprintf(stderr,
		"\t-w --wait-until-seeded TRIES\tRepeatedly check if fully seeded level is reached and sleep for 1s. Exit afterwards.\n");
	fprintf(stderr,
		"\t-W --write-to-aux-pool BYTES\tWrite BYTES to the aux. pool. (needs root)\n");
	fprintf(stderr,
		"\t-B --write-entropy-bits BITS\tSet number of bits to account the write to aux. pool with.\n");
	fprintf(stderr,
		"\t-b --benchmark\t\t\tRun a small speed test in _full and _pr mode with different buffer sizes.\n");
	fprintf(stderr,
		"\t-v --verbose\t\t\tIncrease logging verbosity (can be used multiple times).\n");
	fprintf(stderr,
		"\t-V --decrease-verbosity\t\tDecrease logging verbosity (can be used multiple times).\n");
	fprintf(stderr,
		"\t--use-syslog\t\t\tLog to syslog instead of stdout/stderr.\n");
	fprintf(stderr,
		"\t--stress-delay\t\t\tRun single threaded delay measurement\n");
	fprintf(stderr,
		"\t--stress-process\t\tRun delay stress test on all cores in processes\n");
	fprintf(stderr,
		"\t--stress-thread\t\t\tRun delay stress test on all cores in threads\n");
	fprintf(stderr,
		"\t--stress-duration\t\tSet timeout of stress tests to SECS, Default: 65.0\n");
	fprintf(stderr,
		"\t--stress-request-size BYTE\tUse BYTE sized buffers for stress test, Default: 4\n");
	fprintf(stderr,
		"\t--stress-cpu-usage\t\tShow CPU usage during stress test.\n");
	fprintf(stderr,
		"\t--clear-pool\t\t\tClear the entropy pool for testing (needs root)\n");
	fprintf(stderr,
		"\t--reseed-crng\t\t\tReseed the CRNGs for testing (needs root)\n");
	fprintf(stderr,
		"\t--use-pr\t\t\tFetch random bytes in predication resistance mode.\n");
	fprintf(stderr,
		"\t--raw-bytes\t\t\tWrite random bytes without hex formatting.\n");
	fprintf(stderr,
		"\t--min-seeded\t\t\tUse get-random in minimal seeded mode.\n");
	fprintf(stderr,
		"\t--timeout-msec MSEC\t\tUse get-random in timeout mode.\n");
	fprintf(stderr,
		"\t--allow-unseeded\t\tUse get-random or get_seed in allowed not fully seeded mode.\n");
	fprintf(stderr,
		"\t--is-running\t\t\tCheck if esdm-server is running\n");
	fprintf(stderr,
		"\t--get-seed\t\t\tPerform a get seed operation. Use with --raw-bytes to get raw output instead of hex.\n");
	fprintf(stderr,
		"\t--endless-stress\t\tPerform another stress test. esdm-server can be stopped and started if used together with --continue-on-failure\n");
	fprintf(stderr,
		"\t--continue-on-failure\t\tContinue in some tests, after failures happened.\n");
#ifdef ESDM_HAS_AUX_CLIENT
	fprintf(stderr,
		"\t--seed-via-os\t\t\tDO NOT USE IN PRODUCTION: Testing helper for auxiliary pool. Single shot seeding via getentropy/getrandom. (needs root)\n");
	fprintf(stderr,
		"\t--reseed-via-os\t\t\tDO NOT USE IN PRODUCTION: Testing helper for auxiliary pool. Automatic reseeding via getentropy/getrandom. (needs root)\n");
	fprintf(stderr,
		"\t--reseed-delay-ms\t\tDO NOT USE IN PRODUCTION: Set delay before each reseed to ESDM from OS. Can be used to emulate effects of smartcards or TPMs.\n");
#endif
}

static void handle_status()
{
	char status_buffer[ESDM_RPC_MAX_MSG_SIZE];
	memset(&status_buffer[0], 0, ESDM_RPC_MAX_MSG_SIZE);
	int ret;
	esdm_invoke(esdm_rpcc_status(&status_buffer[0], ESDM_RPC_MAX_MSG_SIZE));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Fetching ESDM status failed!\n");
	} else {
		esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL, "Status --\n%s",
			    status_buffer);
	}
}

static int handle_is_fully_seeded()
{
	int ret = 0;
	bool fully_seeded = false;
	esdm_invoke(esdm_rpcc_is_fully_seeded(&fully_seeded));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Fetching ESDM fully seeded status failed!");
		return EXIT_FAILURE;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL, "ESDM fully seeded: %i\n",
		    (int)fully_seeded);
	return fully_seeded ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int handle_get_random(size_t num_rand_bytes, enum RANDOM_MODE mode,
			     bool raw, long timeout_msec)
{
	struct timespec sleep_time;
	size_t bytes_to_fetch = num_rand_bytes;
	const size_t BUFFER_SIZE = 8192;
	uint8_t bytes[BUFFER_SIZE];
	ssize_t ret = 0;

	while (bytes_to_fetch > 0) {
		size_t chunk_size = min_size(BUFFER_SIZE, bytes_to_fetch);
		ret = 0;
		switch (mode) {
		case RAND_MODE_NONE:
			esdm_invoke(
				esdm_rpcc_get_random_bytes(bytes, chunk_size));
			break;
		case RAND_MODE_MIN:
			esdm_invoke(esdm_rpcc_get_random_bytes_min(bytes,
								   chunk_size));
			break;
		case RAND_MODE_FULL:
			esdm_invoke(esdm_rpcc_get_random_bytes_full(
				bytes, chunk_size));
			break;
		case RAND_MODE_FULL_TIMEOUT:
			sleep_time.tv_sec = timeout_msec / 1000;
			sleep_time.tv_nsec = (timeout_msec % 1000) * 1000000;
			esdm_invoke(esdm_rpcc_get_random_bytes_full_timeout(
				bytes, chunk_size, &sleep_time));
			break;
		case RAND_MODE_PR:
			esdm_invoke(esdm_rpcc_get_random_bytes_pr(bytes,
								  chunk_size));
			break;
		}
		if (ret == (ssize_t)chunk_size) {
			if (raw) {
				ret = write(1, bytes, chunk_size);
				if (ret != (ssize_t)chunk_size) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_TOOL,
						"error writing bytes to stdout\n");
					return EXIT_FAILURE;
				}
			} else {
				for (size_t i = 0; i < chunk_size; ++i) {
					/* don't log via esdm_logger to make it directly consumable for other tools */
					printf("%02hhX", bytes[i]);
				}
			}
		} else {
			esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
				    "fetching random data failed, exiting\n");
			return EXIT_FAILURE;
		}
		bytes_to_fetch -= chunk_size;
	}
	/* don't log via esdm_logger to make it directly consumable for other tools */
	if (!raw)
		printf("\n");

	return EXIT_SUCCESS;
}

static int handle_entropy_count()
{
	int ret = 0;
	unsigned int ent_cnt = 0;

	esdm_invoke(esdm_rpcc_rnd_get_ent_cnt(&ent_cnt));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "fetching entropy count failed\n");
		return EXIT_FAILURE;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL, "Entropy count: %u\n",
		    ent_cnt);

	return EXIT_SUCCESS;
}

static int handle_entropy_level()
{
	int ret = 0;
	unsigned int ent_lvl = 0;

	esdm_invoke(esdm_rpcc_get_ent_lvl(&ent_lvl));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "fetching entropy level failed\n");
		return EXIT_FAILURE;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL, "Entropy level: %u\n",
		    ent_lvl);

	return EXIT_SUCCESS;
}

static int handle_wait_until_seeded(long seed_test_tries)
{
	struct timespec before, after;
	struct timespec sleep_time;
	bool fully_seeded = false;
	uint8_t b;

	/* run forever with negative argument, stop at 0 with positive argument */
	while (seed_test_tries != 0) {
		{
			int ret;

			esdm_invoke(esdm_rpcc_is_fully_seeded(&fully_seeded));
			if (ret == 0 && fully_seeded) {
				esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
					    "ESDM is fully seeded!\n");
				return EXIT_SUCCESS;
			}
		}

		esdm_logger(
			LOGGER_STATUS, LOGGER_C_TOOL,
			"%lu: Waiting another round for ESDM to become fully seeded.\n",
			seed_test_tries);

		/*
		 * we have to trigger seeding by fetching bytes,
		 * if no other tool does it
		 */
		{
			long sleep_diff_ns;
			ssize_t ret;

			sleep_time.tv_sec = 1;
			sleep_time.tv_nsec = 0;
			clock_gettime(CLOCK_MONOTONIC, &before);
			esdm_invoke(esdm_rpcc_get_random_bytes_full_timeout(
				&b, sizeof(b), &sleep_time));
			clock_gettime(CLOCK_MONOTONIC, &after);

			sleep_diff_ns = timespec_diff_ns(&before, &after);
			/* test if we slept less than 0.95s */
			if (ret != sizeof(b) && sleep_diff_ns < 950000000) {
				sleep_time.tv_sec = 0;
				sleep_time.tv_nsec = 1000000000 - sleep_diff_ns;
				clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_time,
						NULL);
			}
		}

		/* run forever with negative argument */
		if (seed_test_tries > 0)
			seed_test_tries--;
	}

	return EXIT_FAILURE;
}

static int handle_write_to_aux_pool(const char *aux_data,
				    uint32_t write_entropy_bits)
{
	if (geteuid()) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Program must start as root!\n");
		return EXIT_FAILURE;
	}

	esdm_rpcc_init_priv_service(NULL);
	int ret = 0;
	size_t len = strlen(aux_data);
	esdm_invoke(esdm_rpcc_rnd_add_entropy((const uint8_t *)aux_data, len,
					      write_entropy_bits));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "unable to write entropy to aux pool\n");
		exit(EXIT_FAILURE);
	}

	esdm_rpcc_fini_priv_service();

	return EXIT_SUCCESS;
}

static const size_t MAX_BENCHMARK_BUFFER_EXP = 12;

static int do_benchmark_single(bool pr, size_t buffer_size)
{
	struct timespec before, after;
	size_t num_iterations;
	uint8_t *buffer = malloc(buffer_size);

	if (buffer == NULL) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Failed to allocate buffer, exiting!\n");
		return EXIT_FAILURE;
	}

	if (pr) {
		num_iterations = 20;
	} else {
		num_iterations = 10000;
	}

	clock_gettime(CLOCK_MONOTONIC, &before);

	ssize_t ret = 0;
	for (size_t i = 0; i < num_iterations; ++i) {
		if (pr) {
			esdm_invoke(esdm_rpcc_get_random_bytes_pr(buffer,
								  buffer_size));
		} else {
			esdm_invoke(esdm_rpcc_get_random_bytes_full(
				buffer, buffer_size));
		}
	}

	if (ret != (ssize_t)buffer_size) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Failed to get bytes from ESDM, exiting!\n");
		free(buffer);
		buffer = NULL;
		return EXIT_FAILURE;
	}

	clock_gettime(CLOCK_MONOTONIC, &after);

	double duration =
		(double)after.tv_sec + (double)after.tv_nsec / 1E9 -
		((double)before.tv_sec + (double)before.tv_nsec / 1E9);
	double bytes_total = (double)num_iterations * (double)buffer_size;
	double data_rate_b_s = bytes_total / duration;
	double iteration_rate = (double)num_iterations / duration;

	char *data_rate = format_byte_sec(data_rate_b_s);

	printf("PR: %i | Req. Size: %4zu | Iter. Rate: %9.2lf 1/s | Data Rate: %s\n",
	       pr, buffer_size, iteration_rate, data_rate);

	free(data_rate);

	free(buffer);
	buffer = NULL;

	return EXIT_SUCCESS;
}

static int do_benchmark(void)
{
	for (int pr = 0; pr < 2; ++pr) {
		for (size_t exp = 0; exp < MAX_BENCHMARK_BUFFER_EXP; ++exp) {
			/* skip larger tests for prediction resistant mode, as this is mostly
			 * used for seeding purposes with <= 512 Bit */
			if (pr && (1 << exp) > 64)
				continue;
			if (do_benchmark_single(pr, 1 << exp) != EXIT_SUCCESS) {
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}

static int handle_clear_pool(void)
{
	int ret;

	esdm_rpcc_init_priv_service(NULL);
	esdm_invoke(esdm_rpcc_rnd_clear_pool());
	esdm_rpcc_fini_priv_service();

	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int handle_reseed_crng(void)
{
	int ret;

	esdm_rpcc_init_priv_service(NULL);
	esdm_invoke(esdm_rpcc_rnd_reseed_crng());
	esdm_rpcc_fini_priv_service();

	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int handle_is_running()
{
	int i;
	const char *files_to_check[] = { ESDM_RPC_UNPRIV_SOCKET,
					 ESDM_RPC_PRIV_SOCKET, NULL };
	uint8_t bytes[32];
	struct stat buffer;
	ssize_t ret;

	/* check for RPC files first */
	for (i = 0; files_to_check[i] != NULL; ++i) {
		if (stat(files_to_check[i], &buffer) != 0) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_TOOL,
				"ESDM not running, file: \"%s\" not existing.\n",
				files_to_check[i]);
			return EXIT_FAILURE;
		} else {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_TOOL,
				"ESDM path \"%s\" exists, continue with checks.\n",
				files_to_check[i]);
		}
	}

	/* do a liveness check */
	esdm_invoke(esdm_rpcc_get_random_bytes(bytes, sizeof(bytes)));
	if (ret != (ssize_t)sizeof(bytes)) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_TOOL,
			"ESDM is not running. Unable to fetch random bytes.\n");
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "ESDM is running. Checked paths and fetched bytes!.\n");

	return EXIT_SUCCESS;
}

static int handle_get_seed(bool allow_not_fully_seeded, bool raw)
{
	uint8_t *buffer = calloc(1, ESDM_RPC_MAX_DATA);
	unsigned int flags = 0;
	ssize_t ret;

	if (buffer == NULL) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Unable to get memory for seed buffer, exiting.\n");
		return EXIT_FAILURE;
	}

	if (allow_not_fully_seeded)
		flags |= ESDM_GET_SEED_FULLY_SEEDED;

	esdm_invoke(esdm_rpcc_get_seed(buffer, ESDM_RPC_MAX_DATA, flags));
	if (ret < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Unable to fetch seed, exiting.\n");
		free(buffer);
		return EXIT_FAILURE;
	}

	if (raw) {
		ssize_t written = write(1, buffer, (size_t)ret);
		if (written != ret) {
			esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
				    "error writing bytes to stdout\n");
			return EXIT_FAILURE;
		}
	} else {
		for (ssize_t i = 0; i < ret; ++i) {
			/* don't log via esdm_logger to make it directly consumable for other tools */
			printf("%02hhX", buffer[i]);
		}
	}

	free(buffer);
	return EXIT_SUCCESS;
}

/*
 * Purpose of this test is to induce stress in esdm-server
 * and test the effects of a stopped or restarted server.
 * set continue_on_failure to not stop on the first error.
 */
static int handle_endless_stress(bool continue_on_failure)
{
	const uint32_t entropy_cnt_bits = 512;
	uint8_t buffer[entropy_cnt_bits / 8];
	bool no_error = true;
	ssize_t ret;

	esdm_rpcc_init_priv_service(NULL);

	while (no_error || continue_on_failure) {
		esdm_invoke(esdm_rpcc_rnd_add_entropy(buffer, sizeof(buffer),
						      entropy_cnt_bits));
		if (ret != 0) {
			no_error = false;
			esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
				    "failed to add entropy count\n");
		}
		esdm_invoke(
			esdm_rpcc_get_random_bytes_pr(buffer, sizeof(buffer)));
		if (ret != (ssize_t)sizeof(buffer)) {
			no_error = false;
			esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
				    "failed to fetch random bytes\n");
		}
	}

	esdm_rpcc_fini_priv_service();
	return EXIT_SUCCESS;
}

#ifdef ESDM_HAS_AUX_CLIENT
static int handle_seed_via_os()
{
	uint8_t seed_buffer[512 / 8];
	int ret_val = EXIT_SUCCESS;
	int ret;

	if (esdm_rpcc_init_priv_service(NULL) != 0) {
		ret_val = EXIT_FAILURE;
		goto out_ret;
	}

	if (getentropy(seed_buffer, sizeof(seed_buffer)) != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "failed to get entropy from OS, exiting.\n");
		ret_val = EXIT_FAILURE;
		goto out_1;
	}

	esdm_invoke(esdm_rpcc_rnd_add_entropy(seed_buffer, sizeof(seed_buffer),
					      sizeof(seed_buffer) * 8));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "seeding ESDM failed, exiting!\n");
		ret_val = EXIT_FAILURE;
		goto out_1;
	}
	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_TOOL,
		"Inserted %li byte into ESDM, accounted with %li bit of entropy\n",
		sizeof(seed_buffer), sizeof(seed_buffer) * 8);

out_1:
	esdm_rpcc_fini_priv_service();

out_ret:
	return ret_val;
}

static int handle_reseed_via_os(long reseed_delay_ms)
{
	const uint32_t timeout_secs = 100;
	struct timespec start, wait, before, after;
	uint8_t reseed_buffer[512 / 8];
	int ret_val = EXIT_SUCCESS;
	bool should_finish = false;
	uint64_t wakeups = 0;
	char *t1 = NULL;
	char *t2 = NULL;
	int ret;

	if (esdm_rpcc_init_priv_service(NULL) != 0) {
		ret_val = EXIT_FAILURE;
		goto out_ret;
	}
	if (esdm_aux_init_wait_for_need_entropy() != 0) {
		ret_val = EXIT_FAILURE;
		goto out_2;
	}

	clock_gettime(CLOCK_MONOTONIC, &start);

	while (!should_finish) {
		clock_gettime(CLOCK_MONOTONIC, &wait);
		before = wait;
		wait.tv_sec += timeout_secs;
		ret = esdm_aux_timedwait_for_need_entropy(&wait);
		clock_gettime(CLOCK_MONOTONIC, &after);
		/* inc wakeups */
		++wakeups;
		t1 = format_time_sec(timespec_diff(&start, &after));
		t2 = format_time_sec(timespec_diff(&before, &after));
		if (ret == 0) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_TOOL,
				"Wakeup %li after %s: handling conditional wake after %s\n",
				wakeups, t1, t2);
		} else if (ret == -1 && errno == ETIMEDOUT) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_TOOL,
				"Wakeup %li after %s: handling timeout wake after %s\n",
				wakeups, t1, t2);
		} else {
			esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
				    "failure or signal, exiting!");
			should_finish = true;
		}
		free(t1);
		free(t2);
		t1 = NULL;
		t2 = NULL;

		if (getentropy(reseed_buffer, sizeof(reseed_buffer)) != 0) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_TOOL,
				"failed to get entropy from OS, exiting.\n");
			ret_val = EXIT_FAILURE;
			goto out_1;
		}

		if (reseed_delay_ms > 0) {
			ret = usleep((unsigned int)reseed_delay_ms * 1000);
			if (ret != 0 && errno == EINVAL) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_TOOL,
					"Invalid sleep timeout for reseed delay ms: %li, exiting!\n",
					reseed_delay_ms) ret_val = EXIT_FAILURE;
				goto out_1;
			}
		}

		esdm_invoke(esdm_rpcc_rnd_add_entropy(
			reseed_buffer, sizeof(reseed_buffer),
			sizeof(reseed_buffer) * 8));
		if (ret != 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
				    "reseeding ESDM failed, exiting!\n");
			ret_val = EXIT_FAILURE;
			goto out_1;
		}
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_TOOL,
			"Inserted %li byte into ESDM, accounted with %li bit of entropy\n",
			sizeof(reseed_buffer), sizeof(reseed_buffer) * 8);
	}

out_1:
	esdm_aux_fini_wait_for_need_entropy();

out_2:
	esdm_rpcc_fini_priv_service();

out_ret:
	return ret_val;
}
#endif /* ESDM_HAS_AUX_CLIENT */

int main(int argc, char **argv)
{
	int c = 0;
	bool status = false;
	bool help = false;
	bool is_fully_seeded = false;
	bool get_random = false;
	size_t num_rand_bytes = 0;
	bool entropy_count = false;
	bool entropy_level = false;
	bool wait_until_seeded = false;
	long seed_test_tries = 10;
	bool write_to_aux_pool = false;
	uint32_t write_entropy_bits = 0;
	bool benchmark = false;
	char *aux_data = NULL;
	bool stress_delay = false;
	bool stress_process = false;
	bool stress_thread = false;
	long stress_duration_sec = 65;
	bool clear_pool = false;
	bool reseed_crng = false;
	bool seed_via_os = false;
	bool reseed_via_os = false;
	int verbosity = 2;
	bool use_syslog = false;
	int return_val = EXIT_SUCCESS;
	/* can be used to simulate smartcards/TPMs in "--reseed-via-os" mode */
	long reseed_delay_ms = -1;
	bool raw_bytes = false;
	long timeout_msec = 1;
	enum RANDOM_MODE getrandom_mode = RAND_MODE_FULL;
	bool is_running = false;
	bool get_seed = false;
	bool endless_stress = false;
	bool continue_on_failure = false;
	uint32_t stress_request_size = 4;
	bool stress_cpu_usage = false;
	int i;

	/*
	 * parse CLI arguments
	 */
	while (1) {
		int opt_index = 0;
		static struct option opts[] = {
			{ "status", 0, 0, 0 },
			{ "help", 0, 0, 0 },
			{ "is-fully-seeded", 0, 0, 0 },
			{ "get-random", 1, 0, 0 },
			{ "entropy-count", 0, 0, 0 },
			{ "entropy-level", 0, 0, 0 },
			{ "wait-until-seeded", 1, 0, 0 },
			{ "write-to-aux-pool", 1, 0, 0 },
			{ "write-entropy-bits", 1, 0, 0 },
			{ "benchmark", 0, 0, 0 },
			{ "stress-delay", 0, 0, 0 },
			{ "stress-thread", 0, 0, 0 },
			{ "stress-process", 0, 0, 0 },
			{ "stress-duration", 1, 0, 0 },
			{ "clear-pool", 0, 0, 0 },
			{ "reseed-crng", 0, 0, 0 },
			{ "use-pr", 0, 0, 0 },
			{ "reseed-via-os", 0, 0, 0 },
			{ "verbose", 0, 0, 0 },
			{ "use-syslog", 0, 0, 0 },
			{ "raw-bytes", 0, 0, 0 },
			{ "reseed-delay-ms", 1, 0, 0 },
			{ "seed-via-os", 0, 0, 0 },
			{ "min-seeded", 0, 0, 0 },
			{ "timeout-msec", 1, 0, 0 },
			{ "allow-unseeded", 0, 0, 0 },
			{ "is-running", 0, 0, 0 },
			{ "get-seed", 0, 0, 0 },
			{ "endless-stress", 0, 0, 0 },
			{ "continue-on-failure", 0, 0, 0 },
			{ "decrease-verbosity", 0, 0, 0 },
			{ "stress-request-size", 1, 0, 0 },
			{ "stress-cpu-usage", 0, 0, 0 },
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "sSr:eEhw:W:B:bvV", opts,
				&opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* status */
				status = true;
				break;
			case 1:
				/* help */
				help = true;
				break;
			case 2:
				/* is-fully-seeded */
				is_fully_seeded = true;
				break;
			case 3:
				/* get-random */
				get_random = true;
				errno = 0;
				num_rand_bytes =
					(size_t)strtol(optarg, NULL, 10);
				if (errno) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_TOOL,
						"conversion of bytes failed, exiting: %s\n",
						strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 4:
				/* entropy-count */
				entropy_count = true;
				break;
			case 5:
				/* entropy-level */
				entropy_level = true;
				break;
			case 6:
				/* wait-until-seeded */
				wait_until_seeded = true;
				errno = 0;
				seed_test_tries = strtol(optarg, NULL, 10);
				if (errno) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_TOOL,
						"conversion of seed tries failed, exiting: %s\n",
						strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 7:
				/* write-to-aux-pool */
				write_to_aux_pool = true;
				if (aux_data != NULL)
					free(aux_data);
				aux_data = calloc(1, strlen(optarg) + 1);
				aux_data = strcpy(aux_data, optarg);
				break;
			case 8:
				/* write-entropy-bits */
				errno = 0;
				write_entropy_bits =
					(uint32_t)strtol(optarg, NULL, 10);
				if (errno) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_TOOL,
						"conversion of bytes failed, exiting: %s\n",
						strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 9:
				/* benchmark */
				benchmark = true;
				break;
			case 10:
				/* stress-delay */
				stress_delay = true;
				break;
			case 11:
				/* stress-thread */
				stress_thread = true;
				break;
			case 12:
				/* stress-process */
				stress_process = true;
				break;
			case 13:
				/* stress-duration */
				stress_duration_sec = strtol(optarg, NULL, 10);
				if (errno) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_TOOL,
						"conversion of stress-duration failed, exiting: %s\n",
						strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 14:
				/* clear-pool */
				clear_pool = true;
				break;
			case 15:
				/* reseed-crng */
				reseed_crng = true;
				break;
			case 16:
				/* use prediction resistance mode */
				getrandom_mode = RAND_MODE_PR;
				break;
			case 17:
				/* DO NOT USE IN PRODUCTION: reseed via OS kernel */
				reseed_via_os = true;
				break;
			case 18:
				/* verbose */
				verbosity++;
				break;
			case 19:
				/* use-syslog */
				use_syslog = true;
				break;
			case 20:
				/* raw-bytes */
				raw_bytes = true;
				break;
			case 21:
				/* reseed-delay-ms */
				reseed_delay_ms = strtol(optarg, NULL, 10);
				if (errno) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_TOOL,
						"conversion of reseed-delay-ms failed, exiting: %s\n",
						strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 22:
				/* seed-via-os */
				seed_via_os = true;
				break;
			case 23:
				/* min-seeded */
				getrandom_mode = RAND_MODE_MIN;
				break;
			case 24:
				/* timeout-msec */
				timeout_msec = strtol(optarg, NULL, 10);
				if (errno) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_TOOL,
						"conversion of timeout-msec failed, exiting: %s\n",
						strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 25:
				/* allow-unseeded */
				getrandom_mode = RAND_MODE_NONE;
				break;
			case 26:
				/* is-running */
				is_running = true;
				break;
			case 27:
				/* get-seed */
				get_seed = true;
				break;
			case 28:
				/* endless-stress */
				endless_stress = true;
				break;
			case 29:
				/* used in endless-stress mode, server can be stopped and restarted */
				continue_on_failure = true;
				break;
			case 30:
				/* decrease-verbosity */
				if (verbosity > 0)
					verbosity--;
				break;
			case 31:
				/* stress-request-size */
				stress_request_size =
					(uint32_t)strtol(optarg, NULL, 10);
				if (errno) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_TOOL,
						"conversion of stress-request-size failed, exiting: %s\n",
						strerror(errno));
					exit(EXIT_FAILURE);
				}
				break;
			case 32:
				/* stress-cpu-usage */
				stress_cpu_usage = true;
			}
			break;
		case 's':
			status = true;
			break;
		case 'S':
			is_fully_seeded = true;
			break;
		case 'h':
			help = true;
			break;
		case 'r':
			get_random = true;
			errno = 0;
			num_rand_bytes = (size_t)strtol(optarg, NULL, 10);
			if (errno) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_TOOL,
					"conversion of bytes failed, exiting: %s\n",
					strerror(errno));
				exit(EXIT_FAILURE);
			}
			break;
		case 'e':
			entropy_count = true;
			break;
		case 'E':
			entropy_level = true;
			break;
		case 'w':
			wait_until_seeded = true;
			errno = 0;
			seed_test_tries = strtol(optarg, NULL, 10);
			if (errno) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_TOOL,
					"conversion of seed tries failed, exiting: %s\n",
					strerror(errno));
				exit(EXIT_FAILURE);
			}
			break;
		case 'W':
			write_to_aux_pool = true;
			if (aux_data != NULL)
				free(aux_data);
			aux_data = calloc(1, strlen(optarg) + 1);
			aux_data = strcpy(aux_data, optarg);
			break;
		case 'B':
			errno = 0;
			write_entropy_bits = (uint32_t)strtol(optarg, NULL, 10);
			if (errno) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_TOOL,
					"conversion of bytes failed, exiting: %s\n",
					strerror(errno));
				exit(EXIT_FAILURE);
			}
			break;
		case 'b':
			benchmark = true;
			break;
		case 'v':
			verbosity++;
			break;
		case 'V':
			/* decrease-verbosity*/
			if (verbosity > 0)
				verbosity--;
			break;
		}
	}

	for (i = 0; i < verbosity; ++i) {
		esdm_logger_inc_verbosity();
	}

	if (use_syslog)
		esdm_logger_enable_syslog("esdm-tool");

	/* check for privileged commands */
	if (geteuid() && (write_to_aux_pool || clear_pool || reseed_crng ||
			  reseed_via_os || seed_via_os || endless_stress)) {
		esdm_logger_inc_verbosity();
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Program must start as root for this command!\n");
		return_val = EXIT_FAILURE;
		goto out;
	}

	/* initialized in child processes in this test */
	if (!stress_process) {
		esdm_rpcc_init_unpriv_service(NULL);
	}

	/*
	 * handle individual commands
	 */
	if (help) {
		handle_usage();
		return_val = EXIT_FAILURE;
	} else if (status) {
		handle_status();
	} else if (is_fully_seeded) {
		return_val = handle_is_fully_seeded();
	} else if (get_random) {
		handle_get_random(num_rand_bytes, getrandom_mode, raw_bytes,
				  timeout_msec);
	} else if (entropy_count) {
		return_val = handle_entropy_count();
	} else if (entropy_level) {
		return_val = handle_entropy_level();
	} else if (wait_until_seeded) {
		return_val = handle_wait_until_seeded(seed_test_tries);
	} else if (write_to_aux_pool) {
		return_val =
			handle_write_to_aux_pool(aux_data, write_entropy_bits);
		free(aux_data);
		aux_data = NULL;
	} else if (benchmark) {
		return_val = do_benchmark();
	} else if (stress_delay) {
		handle_stress_thread((double)stress_duration_sec, 1,
				     stress_request_size, stress_cpu_usage);
	} else if (stress_process) {
		handle_stress_process((double)stress_duration_sec,
				      stress_request_size, stress_cpu_usage);
	} else if (stress_thread) {
		/* -1 means not thread restriction (use number of cores online) */
		handle_stress_thread((double)stress_duration_sec, -1,
				     stress_request_size, stress_cpu_usage);
	} else if (is_running) {
		return_val = handle_is_running();
	} else if (get_seed) {
		/* allow to fetch seed in non fully-seeded mode when --allow-unseeded is set */
		return_val = handle_get_seed(getrandom_mode == RAND_MODE_NONE,
					     raw_bytes);
	} else if (endless_stress) {
		return_val = handle_endless_stress(continue_on_failure);
	} else if (clear_pool) {
		return_val = handle_clear_pool();
	} else if (reseed_crng) {
		return_val = handle_reseed_crng();
#ifdef ESDM_HAS_AUX_CLIENT
	} else if (reseed_via_os) {
		return_val = handle_reseed_via_os(reseed_delay_ms);
	} else if (seed_via_os) {
		return_val = handle_seed_via_os();
#endif
	} else if (errno) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Unknown mode or error: %s\n", strerror(errno));
		handle_usage();
		return_val = EXIT_FAILURE;
	} else {
		handle_usage();
		return_val = EXIT_FAILURE;
	}

	/* finished in child processes in this test */
	if (!stress_process) {
		esdm_rpcc_fini_unpriv_service();
	}

out:
	return return_val;
}
