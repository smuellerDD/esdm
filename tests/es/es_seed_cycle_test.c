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
 * What one seed cycle costs, entropy source by entropy source.
 *
 * A reseed asks every active entropy source for its share and cannot finish
 * before the slowest of them has answered, so the sum reported at the end is
 * the floor under a reseed - and with it under how often a DRNG can be
 * reseeded before the reseeding, rather than the generation, is what sets the
 * throughput. Which source dominates that sum is the thing worth knowing, and
 * it is not the same source on every machine: a TPM or a PKCS#11 token answers
 * in milliseconds where the CPU source answers in microseconds.
 *
 * The durations are printed rather than asserted on - they belong to the
 * hardware. What is checked is that every source reporting itself as available
 * answers at all, and answers within a bound generous enough that only a source
 * that is stuck can miss it.
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_mgr.h"
#include "esdm_es_mgr_cb.h"
#include "esdm_logger.h"

/*
 * Per source: enough repetitions to average out a scheduling hiccup, but
 * bounded in time as well - a TPM takes milliseconds per call and there is no
 * reason to spend a hundred of them on it.
 */
#define TEST_MAX_ROUNDS 32
#define TEST_BUDGET_SECONDS 1.0

/*
 * The longest a single request may take before the source counts as stuck.
 * Well above what even a slow token needs; this is a hang detector, not a
 * performance requirement.
 */
#define TEST_STUCK_SECONDS 30.0

static double test_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Whole microseconds are the wrong unit for both ends of the range measured */
static void test_print_duration(double seconds)
{
	if (seconds >= 1e-3)
		printf("%10.3f ms", seconds * 1e3);
	else
		printf("%10.3f us", seconds * 1e6);
}

/*
 * Time @es over as many requests as the budget allows. Returns the mean
 * duration of one request in seconds, or a negative value if the source did
 * not answer in time.
 */
static double test_time_es(struct esdm_es_cb *es, uint32_t *first_bits)
{
	struct entropy_es eb_es;
	unsigned int round;
	double total = 0.0;

	for (round = 0; round < TEST_MAX_ROUNDS; round++) {
		double start, duration;

		memset(&eb_es, 0, sizeof(eb_es));

		start = test_now();
		es->get_ent(&eb_es, ESDM_DRNG_SECURITY_STRENGTH_BITS, true);
		duration = test_now() - start;

		if (duration > TEST_STUCK_SECONDS) {
			printf("Entropy source %s did not answer within %.0f s\n",
			       es->name, TEST_STUCK_SECONDS);
			return -1.0;
		}

		/*
		 * The first request is the one reported: it is the only one
		 * served from a source that nothing has drained yet, which is
		 * the state a reseed finds it in.
		 */
		if (!round)
			*first_bits = eb_es.e_bits;

		total += duration;

		if (total >= TEST_BUDGET_SECONDS) {
			round++;
			break;
		}
	}

	memset(&eb_es, 0, sizeof(eb_es));

	return total / (double)round;
}

int main(int argc, char *argv[])
{
	double cycle = 0.0;
	unsigned int measured = 0;
	uint32_t i;
	int ret = 0;

	(void)argv;

	if (!argc)
		return 1;

	if (esdm_init()) {
		printf("Cannot initialize the ESDM\n");
		return 1;
	}

	printf("%-24s | %-13s | %s\n", "entropy source", "per request",
	       "entropy of first request");

	for_each_esdm_es (i) {
		struct esdm_es_cb *es = esdm_es[i];
		uint32_t bits = 0;
		double mean;

		if (!es || !es->active || !es->active())
			continue;

		if (!es->get_ent) {
			printf("Entropy source %s is active without a get_ent callback\n",
			       es->name ? es->name : "<unnamed>");
			ret = 1;
			goto out;
		}

		mean = test_time_es(es, &bits);
		if (mean < 0.0) {
			ret = 1;
			goto out;
		}

		printf("%-24s | ", es->name);
		test_print_duration(mean);
		printf(" | %u bits\n", bits);

		cycle += mean;
		measured++;
	}

	if (!measured) {
		printf("No entropy source is available\n");
		ret = 77;
		goto out;
	}

	printf("%-24s | ", "one seed cycle");
	test_print_duration(cycle);
	printf(" | %u sources\n", measured);

out:
	esdm_fini();
	return ret;
}
