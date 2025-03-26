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

#include "bits/time.h"
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <esdm_rpc_client.h>
#include <time.h>

#define xstr(s) str(s)
#define str(s) #s

#define min(a, b)                                                              \
	__extension__({                                                        \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _a : _b;                                             \
	})

static void usage(void)
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
		"\t-w --wait-until-seeded\t\tRepeatedly check if fully seeded level is reached. Exit afterwards.\n");
	fprintf(stderr,
		"\t-W --write-to-aux-pool BYTES\tWrite BYTES to the aux. pool.\n");
	fprintf(stderr,
		"\t-B --write-entropy-bits BITS\tSet number of bits to account the write to aux. pool with.\n");
	fprintf(stderr,
		"\t-b --benchmark\tRun a small speed test in _full and _pr mode with different buffer sizes.\n");
}

static const size_t MAX_BENCHMARK_BUFFER_EXP = 14;

static void do_benchmark_single(bool pr, size_t buffer_size)
{
	struct timespec before, after;
	size_t num_iterations;
	uint8_t *buffer = malloc(buffer_size);

	if (pr) {
		num_iterations = 500;
	} else {
		num_iterations = 20000;
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

	clock_gettime(CLOCK_MONOTONIC, &after);

	double duration =
		(double)after.tv_sec + (double)after.tv_nsec / 1E9 -
		((double)before.tv_sec + (double)before.tv_nsec / 1E9);
	double bytes_total = (double)num_iterations * (double)buffer_size;
	double data_rate_kb_s = bytes_total / duration / 1000;
	double iteration_rate = (double)num_iterations / duration;

	printf("PR: %i | Req. Size: %4zu | Data Rate: %11.3lf KB/s | Iter. Rate: %9.2lf 1/s\n",
	       pr, buffer_size, data_rate_kb_s, iteration_rate);

	free(buffer);
}

static void do_benchmark(void)
{
	for (int pr = 0; pr < 2; ++pr) {
		for (size_t exp = 0; exp < MAX_BENCHMARK_BUFFER_EXP; ++exp) {
			do_benchmark_single(pr, 1 << exp);
		}
	}
}

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
	size_t seed_test_tries = 10;
	bool write_to_aux_pool = false;
	uint32_t write_entropy_bits = 0;
	bool benchmark = false;
	char *aux_data = NULL;
	int return_val = EXIT_SUCCESS;

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
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "sSr:eEhw:W:B:b", opts, &opt_index);
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
					perror("conversion of bytes failed, exiting:");
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
				seed_test_tries =
					(size_t)strtol(optarg, NULL, 10);
				if (errno) {
					perror("conversion of seed tries failed, exiting:");
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
					perror("conversion of bytes failed, exiting:");
					exit(EXIT_FAILURE);
				}
				break;
			case 9:
				/* benchmark */
				benchmark = true;
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
			errno = 0;
			num_rand_bytes = (size_t)strtol(optarg, NULL, 10);
			if (errno) {
				perror("conversion of bytes failed, exiting:");
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
			seed_test_tries = (size_t)strtol(optarg, NULL, 10);
			if (errno) {
				perror("conversion of seed tries failed, exiting:");
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
				perror("conversion of bytes failed, exiting:");
				exit(EXIT_FAILURE);
			}
			break;
		case 'b':
			benchmark = true;
			break;
		}
	}

	esdm_rpcc_set_max_online_nodes(1);
	esdm_rpcc_init_unpriv_service(NULL);

	if (help) {
		usage();
		return_val = EXIT_FAILURE;
	} else if (status) {
		const size_t ESDM_RPC_MAX_MSG_SIZE = 65536;
		char status_buffer[ESDM_RPC_MAX_MSG_SIZE];
		memset(&status_buffer[0], 0, ESDM_RPC_MAX_MSG_SIZE);
		int ret;
		esdm_invoke(esdm_rpcc_status(&status_buffer[0],
					     ESDM_RPC_MAX_MSG_SIZE));
		if (ret != 0) {
			perror("Fetching ESDM status failed!");
		} else {
			printf("%s", status_buffer);
		}
	} else if (is_fully_seeded) {
		int ret = 0;
		bool fully_seeded = false;
		esdm_invoke(esdm_rpcc_is_fully_seeded(&fully_seeded));
		if (ret != 0) {
			perror("Fetching ESDM fully seeded status failed!");
		} else {
			printf("ESDM fully seeded: %i\n", (int)fully_seeded);
			return_val = fully_seeded ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	} else if (get_random) {
		size_t bytes_to_fetch = num_rand_bytes;
		const size_t BUFFER_SIZE = 8192;
		uint8_t bytes[BUFFER_SIZE];
		ssize_t ret = 0;
		while (bytes_to_fetch > 0) {
			size_t chunk_size = min(BUFFER_SIZE, bytes_to_fetch);
			ret = 0;
			esdm_invoke(esdm_rpcc_get_random_bytes_full(
				bytes, chunk_size));
			if (ret == (ssize_t)chunk_size) {
				for (size_t i = 0; i < chunk_size; ++i) {
					printf("%02hhX", bytes[i]);
				}
			} else {
				perror("fetching random data failed, exiting");
				exit(EXIT_FAILURE);
			}
			bytes_to_fetch -= chunk_size;
		}
		printf("\n");
	} else if (entropy_count) {
		int ret = 0;
		unsigned int ent_cnt = 0;
		esdm_invoke(esdm_rpcc_rnd_get_ent_cnt(&ent_cnt));
		if (ret == 0) {
			printf("Entropy count: %u\n", ent_cnt);
		} else {
			perror("fetching entropy count failed:");
			return_val = EXIT_FAILURE;
		}
	} else if (entropy_level) {
		int ret = 0;
		unsigned int ent_lvl = 0;
		esdm_invoke(esdm_rpcc_get_ent_lvl(&ent_lvl));
		if (ret == 0) {
			printf("Entropy level: %u\n", ent_lvl);
		} else {
			perror("fetching entropy level failed:");
			return_val = EXIT_FAILURE;
		}
	} else if (wait_until_seeded) {
		while (seed_test_tries > 0) {
			int ret = 0;
			bool fully_seeded = false;
			esdm_invoke(esdm_rpcc_is_fully_seeded(&fully_seeded));
			if (ret == 0 && fully_seeded) {
				printf("ESDM is fully seeded!\n");
				exit(EXIT_SUCCESS);
			} else {
				printf("Waiting another round for ESDM to become fully seeded.\n");
				struct timespec sleep_time;
				clock_gettime(CLOCK_MONOTONIC, &sleep_time);
				sleep_time.tv_sec += 1;
				clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
						&sleep_time, NULL);
			}
		}
	} else if (write_to_aux_pool) {
		esdm_rpcc_init_priv_service(NULL);
		int ret = 0;
		size_t len = strlen(aux_data);
		esdm_invoke(esdm_rpcc_rnd_add_entropy((const uint8_t *)aux_data,
						      len, write_entropy_bits));
		if (ret != 0) {
			perror("unable to write entropy to aux pool:");
			exit(EXIT_FAILURE);
		}
		free(aux_data);
		aux_data = NULL;
		esdm_rpcc_fini_priv_service();
	} else if (benchmark) {
		do_benchmark();
	} else if (errno) {
		perror("Unknown mode or error:");
		usage();
		return_val = EXIT_FAILURE;
	}

	esdm_rpcc_fini_unpriv_service();

	return return_val;
}