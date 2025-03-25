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

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esdm_rpc_client.h>

#define min(a, b)                                                              \
	__extension__({                                                        \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _a : _b;                                             \
	})

static void usage(void)
{
	fprintf(stderr, "esdm-tool [--help]\n"
			"   [--status]\n"
			"   [--is-fully-seeded]\n"
			"   [--is-fully-seeded]\n"
			"   [--get-random BYTE_COUNT]\n"
			"   [--entropy-count]\n"
			"   [--entropy-level]\n"
			"   [--wait-until-seeded TIMEOUT_SECS]\n"
			"   [--write-to-aux-pool ENTROPY_ESTIMATE_BITS]\n");
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
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "sSr:eEhw:W:B:", opts, &opt_index);
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
	} else if (errno) {
		perror("Unknown mode or error:");
		usage();
		return_val = EXIT_FAILURE;
	}

	esdm_rpcc_fini_unpriv_service();

	return return_val;
}