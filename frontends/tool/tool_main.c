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
#include "helper.h"
#include "math_helper.h"
#include "memset_secure.h"
#include "fips_integrity.h"

#include <errno.h>
#include <esdm_rpc_client.h>
#include <esdm_rpc_service.h>
#ifdef ESDM_HAS_AUX_CLIENT
#include <esdm_aux_client.h>
#endif
#include <fcntl.h>
#include <getopt.h>
#include <json-c/json.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define xstr(s) str(s)
#define str(s) #s

enum RANDOM_MODE {
	RAND_MODE_NONE = 0,
	RAND_MODE_FULL,
	RAND_MODE_FULL_TIMEOUT,
	RAND_MODE_PR,
};

/*
 * Safe strtol wrapper: initializes errno, validates endptr, and exits on
 * conversion failure (trailing garbage, empty string, overflow).
 *
 * The complaint goes to stderr rather than through esdm_logger(), as does
 * every other command line error below. They are all raised while the option
 * loop is still running, so the -v counts it collects have not been applied
 * yet and a LOGGER_ERR record sits below the logger's default threshold: the
 * message would be swallowed and the exit that follows would carry no
 * explanation at all, with no way for the user to ask for one. A usage error
 * belongs on stderr anyway, next to usage() itself.
 */
static long parse_long_arg(const char *str, const char *name)
{
	char *endptr = NULL;
	long val;

	errno = 0;
	val = strtol(str, &endptr, 10);
	if (errno || endptr == str || (endptr && *endptr != '\0')) {
		fprintf(stderr, "esdm-tool: conversion of %s failed: %s\n",
			name, strerror(errno ? errno : EINVAL));
		exit(EXIT_FAILURE);
	}
	return val;
}

/*
 * Read a single line (without the trailing newline) from `fp` into a freshly
 * allocated buffer. The caller must memset_secure + free.
 *
 * If `fp` refers to a terminal, terminal echo is disabled for the duration of
 * the read so a typed PIN is not visible. Returns NULL on EOF/error.
 */
static char *read_secret_line(FILE *fp, const char *prompt)
{
	struct termios old_t, new_t;
	bool reset_termios = false;
	int fd = fileno(fp);
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;

	if (fd >= 0 && isatty(fd)) {
		if (tcgetattr(fd, &old_t) == 0) {
			new_t = old_t;
			new_t.c_lflag &= ~((tcflag_t)ECHO);
			new_t.c_lflag |= ECHONL;
			if (tcsetattr(fd, TCSAFLUSH, &new_t) == 0)
				reset_termios = true;
		}
		if (prompt) {
			fputs(prompt, stderr);
			fflush(stderr);
		}
	}

	n = getline(&line, &cap, fp);

	if (reset_termios)
		(void)tcsetattr(fd, TCSAFLUSH, &old_t);

	if (n < 0) {
		if (line) {
			memset_secure(line, 0, cap);
			free(line);
		}
		return NULL;
	}

	/* strip trailing newline if present */
	if (n > 0 && line[n - 1] == '\n')
		line[n - 1] = '\0';

	return line;
}

/*
 * Resolve the PIN argument supplied via --pkcs11-pin. The literal string "-"
 * means "read securely from stdin (or /dev/tty if available)". Caller must
 * memset_secure + free the returned buffer.
 */
static char *resolve_pkcs11_pin_arg(const char *arg)
{
	FILE *fp;
	char *pin;

	if (strcmp(arg, "-") != 0)
		return strdup(arg);

	fp = fopen("/dev/tty", "r+");
	if (fp) {
		pin = read_secret_line(fp, "Enter PKCS#11 PIN: ");
		fclose(fp);
	} else {
		pin = read_secret_line(stdin, NULL);
	}

	if (!pin) {
		fprintf(stderr,
			"esdm-tool: failed to read PKCS#11 PIN from stdin\n");
		return NULL;
	}

	return pin;
}

static int handle_set_pkcs11_config(const char *token_label, const char *pin)
{
	int ret = 0;

	esdm_rpcc_init_priv_service(NULL);
	esdm_invoke(esdm_rpcc_set_pkcs11_config(token_label, pin));
	esdm_rpcc_fini_priv_service();

	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "failed to update PKCS#11 configuration: %s\n",
			    strerror(-ret));
		return EXIT_FAILURE;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "PKCS#11 configuration updated.\n");
	return EXIT_SUCCESS;
}

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
		"\t--status-json\t\t\tShow status of all entropy sources as a JSON document.\n");
	fprintf(stderr,
		"\t--drng-status[=NODE|pr]\t\tShow the status of the DRNG instances as an indented JSON document.\n");
	fprintf(stderr,
		"\t\t\t\t\tOne instance with =NODE or =pr, all of them without.\n");
	fprintf(stderr,
		"\t--drng-status-json[=NODE|pr]\tThe same on a single line, for a JSON consumer.\n");
	fprintf(stderr,
		"\t-J --jent-status\t\t\tShow internal status string of jitterentropy source.\n");
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
		"\t--benchmark-mode MODE\t\tRestrict the benchmark to one request mode: full, pr or both (Default: both). Implies --benchmark.\n");
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
		"\t--stress-fork\t\t\tchecks fork handling on current platform\n");
	fprintf(stderr,
		"\t--stress-init-fini\t\tStress the RPC client library init/fini reference counting from multiple threads\n");
	fprintf(stderr,
		"\t--clear-pool\t\t\tClear the entropy pool for testing (needs root)\n");
	fprintf(stderr,
		"\t--reseed-crng\t\t\tReseed the CRNGs for testing (needs root)\n");
	fprintf(stderr,
		"\t--selftest\t\t\tRun the self tests of the crypto implementations and of the entropy sources now and report their outcome (needs root)\n");
	fprintf(stderr,
		"\t--max-reseed-secs SECS\t\tSet the maximum interval between two DRNG reseeds in seconds, zero to reseed before every request. The ESDM caps the value at its own upper bound. (needs root)\n");
	fprintf(stderr,
		"\t--use-pr\t\t\tFetch random bytes in predication resistance mode.\n");
	fprintf(stderr,
		"\t--raw-bytes\t\t\tWrite random bytes without hex formatting.\n");
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
	fprintf(stderr,
		"\t--pkcs11-pin PIN\t\tSet the PKCS#11 entropy source user PIN (needs root). Pass '-' to read the PIN securely from stdin (terminal echo is disabled). May be combined with --pkcs11-token-label.\n");
	fprintf(stderr,
		"\t--pkcs11-token-label LABEL\tSet the PKCS#11 entropy source token label and re-open the module (needs root). Pass an empty string to clear the override. May be combined with --pkcs11-pin.\n");
#ifdef ESDM_HAS_AUX_CLIENT
	fprintf(stderr,
		"\t--seed-via-os\t\t\tDO NOT USE IN PRODUCTION: Testing helper for auxiliary pool. Single shot seeding via getentropy/getrandom. (needs root)\n");
	fprintf(stderr,
		"\t--reseed-via-os\t\t\tDO NOT USE IN PRODUCTION: Testing helper for auxiliary pool. Automatic reseeding via getentropy/getrandom. (needs root)\n");
	fprintf(stderr,
		"\t--reseed-delay-ms\t\tDO NOT USE IN PRODUCTION: Set delay before each reseed to ESDM from OS. Can be used to emulate effects of smartcards or TPMs.\n");
#endif

#ifdef ESDM_FIPS140
	fprintf(stderr,
		"\t--fips-checkfile PATH\t\tCreates FIPS HMAC check file in path\n");
	fprintf(stderr,
		"\t--fips-targetfile PATH\t\tReads FIPS target file in PATH to create HMAC\n");
#endif
}

static void handle_status(void)
{
	char status_buffer[ESDM_RPC_MAX_DATA];
	memset(&status_buffer[0], 0, ESDM_RPC_MAX_DATA);
	int ret;
	esdm_invoke(esdm_rpcc_status(&status_buffer[0], ESDM_RPC_MAX_DATA));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Fetching ESDM status failed!\n");
	} else {
		esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL, "Status --\n%s",
			    status_buffer);
	}
}

static void handle_status_json(void)
{
	char status_buffer[ESDM_RPC_MAX_DATA];
	memset(&status_buffer[0], 0, ESDM_RPC_MAX_DATA);
	int ret;
	esdm_invoke(
		esdm_rpcc_status_json(&status_buffer[0], ESDM_RPC_MAX_DATA));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Fetching ESDM status failed!\n");
	} else {
		/*
		 * Written to stdout unadorned so that the document can be piped
		 * into a JSON consumer.
		 */
		printf("%s", status_buffer);
	}
}

/*
 * The DRNG instances a node is served by are asked for one at a time: there is
 * one per CPU, so the status document leaves them out rather than growing with
 * the size of the machine - see esdm_rpcc_drng_status_json().
 */
enum drng_status_target {
	/* Every instance the ESDM has, as a JSON array */
	DRNG_STATUS_ALL,
	/* One node instance */
	DRNG_STATUS_NODE,
	/* The prediction resistance instance */
	DRNG_STATUS_PR,
};

/* Fetch one instance and add it to @out, which may be an array or NULL */
static int drng_status_add(struct json_object *out, uint32_t node, bool pr,
			   struct json_object **obj)
{
	char status_buffer[ESDM_RPC_MAX_DATA];
	int ret;

	memset(&status_buffer[0], 0, sizeof(status_buffer));

	if (pr) {
		esdm_invoke(esdm_rpcc_drng_status_pr_json(
			&status_buffer[0], sizeof(status_buffer)));
	} else {
		esdm_invoke(esdm_rpcc_drng_status_json(node, &status_buffer[0],
						       sizeof(status_buffer)));
	}

	if (ret)
		return ret;

	*obj = json_tokener_parse(status_buffer);
	if (!*obj) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "DRNG status is not a JSON document\n");
		return -EINVAL;
	}

	if (out)
		json_object_array_add(out, *obj);

	return 0;
}

/* Print the status of one DRNG instance or of all of them. */
static int handle_drng_status(enum drng_status_target target, uint32_t node,
			      bool raw)
{
	struct json_object *doc = NULL, *obj = NULL;
	const char *out;
	int ret;

	switch (target) {
	case DRNG_STATUS_PR:
		ret = drng_status_add(NULL, 0, true, &doc);
		break;
	case DRNG_STATUS_NODE:
		ret = drng_status_add(NULL, node, false, &doc);
		if (ret == -ENODEV) {
			esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
				    "no DRNG instance serves node %u\n", node);
		}
		break;
	case DRNG_STATUS_ALL:
		doc = json_object_new_array();
		if (!doc)
			return -ENOMEM;

		/*
		 * The nodes are walked until the ESDM reports that there is no
		 * further one, which is how their number is learned without
		 * asking for it separately.
		 */
		for (node = 0;; node++) {
			ret = drng_status_add(doc, node, false, &obj);
			if (ret == -ENODEV) {
				ret = 0;
				break;
			}
			if (ret)
				goto out;
		}

		ret = drng_status_add(doc, 0, true, &obj);
		break;
	}

	if (ret)
		goto out;

	out = json_object_to_json_string_ext(
		doc, raw ? JSON_C_TO_STRING_PLAIN : JSON_C_TO_STRING_PRETTY);
	if (!out) {
		ret = -ENOMEM;
		goto out;
	}

	/* Unadorned, so that the document can be piped into a JSON consumer */
	printf("%s\n", out);

out:
	if (ret && ret != -ENODEV) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Fetching ESDM DRNG status failed: %d\n", ret);
	}
	json_object_put(doc);
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void handle_jent_status(void)
{
	char status_buffer[ESDM_RPC_MAX_DATA];
	memset(&status_buffer[0], 0, ESDM_RPC_MAX_DATA);
	int ret;
	esdm_invoke(
		esdm_rpcc_jent_status(&status_buffer[0], ESDM_RPC_MAX_DATA));
	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Fetching ESDM jitterentropy status failed!\n");
	} else {
		printf("%s", status_buffer);
	}
}

static int handle_is_fully_seeded(void)
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

static int handle_entropy_count(void)
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

static int handle_entropy_level(void)
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

static const size_t MAX_BENCHMARK_BUFFER_EXP = 16;

/* Which of the two request modes the benchmark exercises */
enum BENCHMARK_MODE {
	BENCH_MODE_BOTH = 0,
	BENCH_MODE_FULL,
	BENCH_MODE_PR,
};

static int do_benchmark_single(bool pr, size_t buffer_size)
{
	struct timespec before, after;
	size_t num_iterations;
	uint8_t *buffer = NULL;

	if (buffer_size > ESDM_RPC_MAX_DATA)
		buffer_size = ESDM_RPC_MAX_DATA;
	buffer = malloc(buffer_size);

	if (buffer == NULL) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Failed to allocate buffer, exiting!\n");
		return EXIT_FAILURE;
	}

	if (pr) {
		num_iterations = 20;
	} else if (buffer_size < 1000) {
		num_iterations = 5000;
	} else if (buffer_size > 5000) {
		num_iterations = 1000;
	} else {
		num_iterations = 250;
	}

	clock_gettime(CLOCK_MONOTONIC, &before);

	ssize_t ret = 0;
	for (size_t i = 0; i < num_iterations;) {
		if (pr) {
			esdm_invoke(esdm_rpcc_get_random_bytes_pr(buffer,
								  buffer_size));
		} else {
			esdm_invoke(esdm_rpcc_get_random_bytes_full(
				buffer, buffer_size));
		}
		if (ret != (ssize_t)buffer_size) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_TOOL,
				"Failed to get bytes from ESDM, exiting!\n");
			free(buffer);
			buffer = NULL;
			return EXIT_FAILURE;
		} else {
			++i;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &after);

	double duration =
		(double)after.tv_sec + (double)after.tv_nsec / 1E9 -
		((double)before.tv_sec + (double)before.tv_nsec / 1E9);
	double bytes_total = (double)num_iterations * (double)buffer_size;
	double data_rate_b_s = bytes_total / duration;
	double iteration_rate = (double)num_iterations / duration;

	char *data_rate = format_byte_sec(data_rate_b_s);

	printf("PR: %i | Req. Size: %5zu | Iter. Rate: %9.2lf 1/s | Data Rate: %s\n",
	       pr, buffer_size, iteration_rate, data_rate);

	free(data_rate);

	free(buffer);
	buffer = NULL;

	return EXIT_SUCCESS;
}

static int do_benchmark(enum BENCHMARK_MODE mode)
{
	for (int pr = 0; pr < 2; ++pr) {
		if (pr && mode == BENCH_MODE_FULL)
			continue;
		if (!pr && mode == BENCH_MODE_PR)
			continue;

		for (size_t exp = 0; exp <= MAX_BENCHMARK_BUFFER_EXP; ++exp) {
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

/* Set the maximum interval between two reseeds of the DRNGs. */
static int handle_set_max_reseed_secs(unsigned int seconds)
{
	unsigned int effective = 0;
	int ret;

	esdm_rpcc_init_priv_service(NULL);
	esdm_invoke(esdm_rpcc_set_min_reseed_secs(seconds));
	esdm_rpcc_fini_priv_service();

	if (ret != 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Setting the maximum reseed interval failed!\n");
		return EXIT_FAILURE;
	}

	esdm_invoke(esdm_rpcc_get_min_reseed_secs(&effective));
	if (ret != 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_TOOL,
			"Maximum reseed interval set, but reading it back failed\n");
		return EXIT_SUCCESS;
	}

	if (effective != seconds) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_TOOL,
			"Maximum reseed interval of %u seconds was adjusted by the ESDM to %u seconds\n",
			seconds, effective);
	} else if (!effective) {
		esdm_logger(
			LOGGER_STATUS, LOGGER_C_TOOL,
			"Maximum reseed interval: zero seconds - every request reseeds its DRNG\n");
	} else {
		esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
			    "Maximum reseed interval: %u seconds\n", effective);
	}

	return EXIT_SUCCESS;
}

/* Name of a self test state as the server reports it */
static const char *selftest_state_name(enum esdm_rpcc_selftest_state state)
{
	switch (state) {
	case esdm_rpcc_selftest_undone:
		return "undone";
	case esdm_rpcc_selftest_passed:
		return "passed";
	case esdm_rpcc_selftest_failed:
		return "failed";
	}

	return "unknown";
}

/* Run the self tests in the server now and report what they found. */
static int handle_selftest(void)
{
	struct esdm_rpcc_selftest_result result;
	int ret;

	esdm_rpcc_init_priv_service(NULL);
	esdm_invoke(esdm_rpcc_selftest(&result));
	esdm_rpcc_fini_priv_service();

	/*
	 * The server always runs both passes before it answers, so two undone
	 * states mean no answer arrived rather than an outcome worth printing.
	 */
	if (ret && result.crypto_state == esdm_rpcc_selftest_undone &&
	    result.es_state == esdm_rpcc_selftest_undone) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Running the self tests failed: %s\n",
			    strerror(ret < 0 ? -ret : ret));
		return EXIT_FAILURE;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "Self test of the crypto implementations: %s\n",
		    selftest_state_name(result.crypto_state));
	esdm_logger(
		LOGGER_STATUS, LOGGER_C_TOOL,
		"Self test of the entropy sources: %s (%u tested, %u failed)\n",
		selftest_state_name(result.es_state), result.es_sources,
		result.es_failures);

	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL, "Self test failed: %s\n",
			    strerror(ret < 0 ? -ret : ret));
		return EXIT_FAILURE;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL, "Self tests passed\n");

	return EXIT_SUCCESS;
}

static int handle_is_running(void)
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
		return EXIT_FAILURE;
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

	if (!allow_not_fully_seeded)
		flags |= ESDM_GET_SEED_FULLY_SEEDED;

	esdm_invoke(esdm_rpcc_get_seed(buffer, ESDM_RPC_MAX_DATA, flags));
	if (ret < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Unable to fetch seed, exiting.\n");
		memset_secure(buffer, 0, ESDM_RPC_MAX_DATA);
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

	memset_secure(buffer, 0, ESDM_RPC_MAX_DATA);
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

static int handle_stress_fork(void)
{
	const int max_fork_depth = 5;
	int fork_depth = 0;
	const size_t buf_len = 32;
	uint8_t buffer[buf_len];
	ssize_t ret;
	size_t i;

	while (fork_depth++ < max_fork_depth) {
		for (i = 0; i < 200; ++i) {
			esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer,
								    buf_len));
			if (ret == -EINTR || ret == -EPROTO ||
			    ret == -ECONNRESET || ret == -ETIMEDOUT)
				continue;

			if ((size_t)ret != buf_len) {
				printf("error in fork test: %s\n",
				       strerror((int)-ret));
			}

			assert((size_t)ret == buf_len);
		}
		/* don't care. Just check in all processes involved, that we can get random bytes */
		pid_t p = fork();
		assert(p != -1);
		(void)p;
	}

	while (wait(NULL) > 0) {
	}

	if (errno != ECHILD) {
		printf("error in some child occurred\n");
		fflush(stdout);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#ifdef ESDM_HAS_AUX_CLIENT
static int handle_seed_via_os(void)
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
			ret = usleep((useconds_t)min_size(
				(size_t)reseed_delay_ms * 1000, 999999));
			if (ret != 0 && errno == EINVAL) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_TOOL,
					"Invalid sleep timeout for reseed delay ms: %li, exiting!\n",
					reseed_delay_ms);
				ret_val = EXIT_FAILURE;
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
	enum BENCHMARK_MODE benchmark_mode = BENCH_MODE_BOTH;
	char *aux_data = NULL;
	bool stress_delay = false;
	bool stress_process = false;
	bool stress_thread = false;
	long stress_duration_sec = 65;
	bool clear_pool = false;
	bool reseed_crng = false;
	bool seed_via_os = false;
	bool reseed_via_os = false;
	bool jent_status = false;
	bool status_json = false;
	bool drng_status = false;
	bool drng_status_raw = false;
	enum drng_status_target drng_status_target = DRNG_STATUS_ALL;
	uint32_t drng_status_node = 0;
	bool selftest = false;
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
	bool stress_fork = false;
	bool stress_init_fini = false;
	char *fips_target_file = NULL;
	char *fips_check_file = NULL;
	bool set_pkcs11_config = false;
	bool set_max_reseed_secs = false;
	unsigned int max_reseed_secs = 0;
	char *pkcs11_pin = NULL;
	char *pkcs11_token_label = NULL;
	int i;

	may_enable_memory_debugging();

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
			{ "timeout-msec", 1, 0, 0 },
			{ "allow-unseeded", 0, 0, 0 },
			{ "is-running", 0, 0, 0 },
			{ "get-seed", 0, 0, 0 },
			{ "endless-stress", 0, 0, 0 },
			{ "continue-on-failure", 0, 0, 0 },
			{ "decrease-verbosity", 0, 0, 0 },
			{ "stress-request-size", 1, 0, 0 },
			{ "stress-cpu-usage", 0, 0, 0 },
			{ "stress-fork", 0, 0, 0 },
			{ "fips-targetfile", 1, 0, 0 },
			{ "fips-checkfile", 1, 0, 0 },
			{ "jent-status", 0, 0, 0 },
			{ "pkcs11-pin", 1, 0, 0 },
			{ "pkcs11-token-label", 1, 0, 0 },
			{ "stress-init-fini", 0, 0, 0 },
			{ "benchmark-mode", 1, 0, 0 },
			{ "status-json", 0, 0, 0 },
			{ "max-reseed-secs", 1, 0, 0 },
			{ "selftest", 0, 0, 0 },
			{ "drng-status", 2, 0, 0 },
			{ "drng-status-json", 2, 0, 0 },
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "sSr:eEhw:W:B:bvVF:C:J", opts,
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
				{
					long val =
						parse_long_arg(optarg, "bytes");

					if (val < 0) {
						fprintf(stderr,
							"esdm-tool: bytes must be non-negative\n");
						exit(EXIT_FAILURE);
					}
					num_rand_bytes = (size_t)val;
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
				seed_test_tries =
					parse_long_arg(optarg, "seed tries");
				break;
			case 7:
				/* write-to-aux-pool */
				write_to_aux_pool = true;
				if (aux_data != NULL)
					free(aux_data);
				aux_data = strdup(optarg);
				if (!aux_data) {
					fprintf(stderr,
						"esdm-tool: allocation failure\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 8:
				/* write-entropy-bits */
				{
					long val = parse_long_arg(
						optarg, "entropy bits");

					if (val < 0 ||
					    (unsigned long)val > UINT32_MAX) {
						fprintf(stderr,
							"esdm-tool: entropy bits out of range\n");
						exit(EXIT_FAILURE);
					}
					write_entropy_bits = (uint32_t)val;
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
				stress_duration_sec = parse_long_arg(
					optarg, "stress-duration");
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
				reseed_delay_ms = parse_long_arg(
					optarg, "reseed-delay-ms");
				break;
			case 22:
				/* seed-via-os */
				seed_via_os = true;
				break;
			case 23:
				/* timeout-msec */
				timeout_msec =
					parse_long_arg(optarg, "timeout-msec");
				getrandom_mode = RAND_MODE_FULL_TIMEOUT;
				break;
			case 24:
				/* allow-unseeded */
				getrandom_mode = RAND_MODE_NONE;
				break;
			case 25:
				/* is-running */
				is_running = true;
				break;
			case 26:
				/* get-seed */
				get_seed = true;
				break;
			case 27:
				/* endless-stress */
				endless_stress = true;
				break;
			case 28:
				/* used in endless-stress mode, server can be stopped and restarted */
				continue_on_failure = true;
				break;
			case 29:
				/* decrease-verbosity */
				if (verbosity > 0)
					verbosity--;
				break;
			case 30:
				/* stress-request-size */
				{
					long val = parse_long_arg(
						optarg, "stress-request-size");

					if (val < 0 ||
					    (unsigned long)val > UINT32_MAX) {
						fprintf(stderr,
							"esdm-tool: stress-request-size out of range\n");
						exit(EXIT_FAILURE);
					}
					stress_request_size = (uint32_t)val;
				}
				break;
			case 31:
				/* stress-cpu-usage */
				stress_cpu_usage = true;
				break;
			case 32:
				/* stress-fork */
				stress_fork = true;
				break;
			case 33:
				/* fips target file */
				fips_target_file = optarg;
				break;
			case 34:
				/* fips check file */
				fips_check_file = optarg;
				break;
			case 35:
				/* display jitterentropy source status */
				jent_status = true;
				break;
			case 36:
				/* pkcs11-pin: literal PIN, or "-" for stdin */
				set_pkcs11_config = true;
				if (pkcs11_pin) {
					memset_secure(pkcs11_pin,
						      0, strlen(pkcs11_pin));
					free(pkcs11_pin);
				}
				pkcs11_pin = resolve_pkcs11_pin_arg(optarg);
				if (!pkcs11_pin) {
					return_val = EXIT_FAILURE;
					goto out;
				}
				break;
			case 37:
				/* pkcs11-token-label */
				set_pkcs11_config = true;
				free(pkcs11_token_label);
				pkcs11_token_label = strdup(optarg);
				if (!pkcs11_token_label) {
					fprintf(stderr,
						"esdm-tool: allocation failure\n");
					return_val = EXIT_FAILURE;
					goto out;
				}
				break;
			case 38:
				/* stress-init-fini */
				stress_init_fini = true;
				break;
			case 39:
				/* benchmark-mode */
				benchmark = true;
				if (!strcmp(optarg, "full")) {
					benchmark_mode = BENCH_MODE_FULL;
				} else if (!strcmp(optarg, "pr")) {
					benchmark_mode = BENCH_MODE_PR;
				} else if (!strcmp(optarg, "both")) {
					benchmark_mode = BENCH_MODE_BOTH;
				} else {
					fprintf(stderr,
						"esdm-tool: benchmark mode must be one of full, pr or both\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 40:
				/* status-json */
				status_json = true;
				break;
			case 41:
				/* max-reseed-secs */
				{
					long val = parse_long_arg(
						optarg, "max reseed seconds");

					/*
					 * Zero is a value of its own - it asks
					 * for a reseed before every request -
					 * so only the range is checked here.
					 */
					if (val < 0 ||
					    (unsigned long)val > UINT32_MAX) {
						fprintf(stderr,
							"esdm-tool: max reseed seconds out of range\n");
						exit(EXIT_FAILURE);
					}
					set_max_reseed_secs = true;
					max_reseed_secs = (unsigned int)val;
				}
				break;
			case 42:
				/* selftest */
				selftest = true;
				break;
			case 43:
			case 44:
				/* drng-status / drng-status-json */
				drng_status = true;
				drng_status_raw = (opt_index == 44);

				/*
				 * Without an argument every instance is
				 * reported.
				 */
				if (!optarg) {
					drng_status_target = DRNG_STATUS_ALL;
					break;
				}

				if (!strcmp(optarg, "pr")) {
					drng_status_target = DRNG_STATUS_PR;
					break;
				}

				{
					long val = parse_long_arg(optarg,
								  "DRNG node");

					if (val < 0 ||
					    (unsigned long)val > UINT32_MAX) {
						fprintf(stderr,
							"esdm-tool: DRNG node out of range\n");
						exit(EXIT_FAILURE);
					}
					drng_status_target = DRNG_STATUS_NODE;
					drng_status_node = (uint32_t)val;
				}
				break;
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
			{
				long val = parse_long_arg(optarg, "bytes");

				if (val < 0) {
					fprintf(stderr,
						"esdm-tool: bytes must be non-negative\n");
					exit(EXIT_FAILURE);
				}
				num_rand_bytes = (size_t)val;
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
			seed_test_tries = parse_long_arg(optarg, "seed tries");
			break;
		case 'W':
			write_to_aux_pool = true;
			if (aux_data != NULL)
				free(aux_data);
			aux_data = strdup(optarg);
			if (!aux_data) {
				fprintf(stderr,
					"esdm-tool: allocation failure\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'B': {
			long val = parse_long_arg(optarg, "entropy bits");

			if (val < 0 || (unsigned long)val > UINT32_MAX) {
				fprintf(stderr,
					"esdm-tool: entropy bits out of range\n");
				exit(EXIT_FAILURE);
			}
			write_entropy_bits = (uint32_t)val;
		} break;
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
		case 'F':
			/* fips target file */
			fips_target_file = optarg;
			break;
		case 'C':
			/* fips check file */
			fips_check_file = optarg;
			break;
		case 'J':
			/* display jitterentropy source status */
			jent_status = true;
			break;
		}
	}

	for (i = 0; i < verbosity; ++i) {
		esdm_logger_inc_verbosity();
	}

	if (use_syslog)
		esdm_logger_enable_syslog("esdm-tool");

	/* check for privileged commands */
	if (geteuid() &&
	    (write_to_aux_pool || clear_pool || reseed_crng || reseed_via_os ||
	     seed_via_os || endless_stress || set_pkcs11_config ||
	     set_max_reseed_secs || selftest)) {
		esdm_logger_inc_verbosity();
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Program must start as root for this command!\n");
		return_val = EXIT_FAILURE;
		goto out;
	}

	/* initialized in child processes in this test */
	esdm_rpcc_init_unpriv_service(NULL);

	/*
	 * handle individual commands
	 */
	if (help) {
		handle_usage();
		return_val = EXIT_FAILURE;
#ifdef ESDM_FIPS140
	} else if (fips_target_file && fips_check_file) {
		if (fips_create_checkfile(fips_check_file, fips_target_file)) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_TOOL,
				"failed to create FIPS check file \"%s\" for \"%s\". Already existing?\n",
				fips_check_file, fips_target_file);
			return_val = EXIT_FAILURE;
		}
#else
	} else if (fips_target_file && fips_check_file) {
		(void)fips_check_file;
		(void)fips_target_file;
		esdm_logger(
			LOGGER_ERR, LOGGER_C_TOOL,
			"failed to create FIPS check file \"%s\" for \"%s\". FIPS disabled.\n",
			fips_check_file, fips_target_file);
		return_val = EXIT_FAILURE;
#endif
	} else if (status) {
		handle_status();
	} else if (status_json) {
		handle_status_json();
	} else if (drng_status) {
		return_val = handle_drng_status(
			drng_status_target, drng_status_node, drng_status_raw);
	} else if (jent_status) {
		handle_jent_status();
	} else if (is_fully_seeded) {
		return_val = handle_is_fully_seeded();
	} else if (get_random) {
		return_val = handle_get_random(num_rand_bytes, getrandom_mode,
					       raw_bytes, timeout_msec);
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
		return_val = do_benchmark(benchmark_mode);
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
	} else if (stress_fork) {
		return_val = handle_stress_fork();
	} else if (stress_init_fini) {
		/* -1 means no thread restriction (use number of cores online) */
		return_val = handle_stress_init_fini(
			(double)stress_duration_sec, -1);
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
	} else if (set_max_reseed_secs) {
		return_val = handle_set_max_reseed_secs(max_reseed_secs);
	} else if (selftest) {
		return_val = handle_selftest();
	} else if (set_pkcs11_config) {
		return_val = handle_set_pkcs11_config(pkcs11_token_label,
						      pkcs11_pin);
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

	esdm_rpcc_fini_unpriv_service();

out:
	if (pkcs11_pin) {
		memset_secure(pkcs11_pin, 0, strlen(pkcs11_pin));
		free(pkcs11_pin);
	}
	free(pkcs11_token_label);
	/*
	 * The command that consumes it frees it and clears the pointer, so this
	 * is what is left when one of the paths above jumped here instead -
	 * "-W" refused for want of root, most of all.
	 */
	free(aux_data);
	return return_val;
}
