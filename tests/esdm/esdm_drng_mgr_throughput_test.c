/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

/*
 * Sustained generation across the reseed thresholds.
 *
 * Every request size here runs long enough to cross the point at which a DRNG
 * is due for a reseed many times over - under the DRG.4 limits that is every
 * few kilobytes - which is what puts the asynchronous reseed of the node DRNGs
 * under load. What is checked is that the ESDM keeps serving while that goes
 * on: every request is answered in full and the ESDM stays operational, so a
 * reseed that never lands, or one that takes its DRNG down with it, shows up
 * here rather than as a throughput number nobody reads.
 *
 * The rates are printed for the record. They are not asserted on - they are a
 * property of the machine, not of the code.
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "helper.h"

/* Long enough to cross the reseed thresholds repeatedly, short enough for CI */
#define TEST_SECONDS_PER_SIZE 1.0

/* Both ends of what consumers ask for: a key's worth, and a bulk read */
static const size_t test_sizes[] = { 32, 64, 256, 1024, 4096 };

/* Seconds the ESDM is given to reach the fully seeded state */
#define TEST_SEED_WAIT_SECONDS 30

static double test_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int test_wait_fully_seeded(void)
{
	unsigned int i;

	for (i = 0; i < TEST_SEED_WAIT_SECONDS * 10; i++) {
		if (esdm_state_fully_seeded())
			return 0;
		usleep(100 * 1000);
	}

	return 1;
}

static int test_one_size(size_t len)
{
	static uint8_t buf[4096];
	unsigned long requests = 0;
	double start, elapsed;

	if (len > sizeof(buf))
		return 1;

	start = test_now();

	do {
		if (esdm_get_random_bytes_full(buf, len) != (ssize_t)len) {
			printf("Request of %zu bytes was not answered in full\n",
			       len);
			return 1;
		}

		/*
		 * The initial DRNG going non-operational is how a reseed that
		 * cannot keep up surfaces, and it takes the whole ESDM with it.
		 * Checked per request rather than at the end: the state
		 * recovers on its own once entropy arrives, so a check after
		 * the loop would miss it.
		 */
		if (!esdm_state_operational()) {
			printf("ESDM left operational mode while generating\n");
			return 1;
		}

		requests++;
		elapsed = test_now() - start;
	} while (elapsed < TEST_SECONDS_PER_SIZE);

	printf("%5zu bytes | %10.0f requests/s | %8.3f MB/s\n", len,
	       (double)requests / elapsed,
	       (double)requests * (double)len / elapsed / 1e6);

	return 0;
}

int main(int argc, char *argv[])
{
	uint8_t buf[32];
	unsigned int i;
	int ret = 0;

	(void)argv;

	if (!argc)
		return 1;

	if (esdm_init()) {
		printf("Cannot initialize the ESDM\n");
		return 1;
	}

	/* The first request is what starts the seeding */
	esdm_get_random_bytes(buf, sizeof(buf));

	if (test_wait_fully_seeded()) {
		printf("ESDM did not reach the fully seeded state\n");
		ret = 77;
		goto out;
	}

	/*
	 * The instances actually allocated, not what the configuration would
	 * allow: zero means node support is off and every request lands on the
	 * initial DRNG, which is the one case the asynchronous reseed leaves
	 * alone.
	 */
	printf("DRNG node instances: %u\n", esdm_drng_node_count_get());

	for (i = 0; i < ARRAY_SIZE(test_sizes); i++) {
		ret = test_one_size(test_sizes[i]);
		if (ret)
			goto out;
	}

	printf("Sustained generation passed\n");

out:
	esdm_fini();
	return ret;
}
