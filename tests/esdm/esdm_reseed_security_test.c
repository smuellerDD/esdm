/*
 * The two conditions that reseed a DRNG: the reseed interval and the number of
 * generate requests served from one seed, lowered to 2^10 for this test
 *
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "ret_checkers.h"
#include "../test_plan.h"

#ifdef ESDM_TESTMODE

/* Generate requests after which a DRNG is reseeded, for the whole test */
#define ESDM_SEC_THRESH (1U << 10)

/* Requests made - twice the threshold */
#define ESDM_SEC_REQUESTS (1U << 11)

/*
 * Bytes per request. All requests stay below the SP800-90C output limit of a
 * seed, ESDM_DRNG_RESEED_THRESH_BITS, so it cannot cause a reseed.
 */
#define ESDM_SEC_REQSIZE 1

#if (ESDM_SEC_REQUESTS * ESDM_SEC_REQSIZE * 8 >= ESDM_DRNG_RESEED_THRESH_BITS)
#error "the requests reach the reseed threshold in bits"
#endif

/*
 * Reseed interval, and how much later the reseed may show up: the request has
 * to collect the seed first.
 */
#define ESDM_SEC_INTERVAL 5
#define ESDM_SEC_SLACK 25

/* Request every this many ms while the interval runs, below the threshold */
#define ESDM_SEC_POLL_MS 50

#if ((ESDM_SEC_INTERVAL + ESDM_SEC_SLACK) * 1000 / ESDM_SEC_POLL_MS >=         \
     ESDM_SEC_THRESH)
#error "the requests made while the interval runs reach the request threshold"
#endif

/*
 * How much earlier than the interval the second reseed may be seen: the first
 * is timed only once its request returned.
 */
#define ESDM_SEC_TOLERANCE_MS 500

/* Wait for the initial seeding at most this many 100ms slices */
#define ESDM_SEC_SEED_SLICES 100

/* The statistics of the DRNG instances serving ordinary requests */
struct esdm_sec_stats {
	unsigned int instances;
	long long seed_generation;
};

static void esdm_sec_stats_cb(const struct esdm_drng_stats *drng_stats,
			      void *priv)
{
	struct esdm_sec_stats *stats = (struct esdm_sec_stats *)priv;

	if (!strcmp(drng_stats->type, "prediction resistance"))
		return;

	stats->instances++;
	stats->seed_generation = drng_stats->seed_generation;
}

static struct esdm_sec_stats esdm_sec_stats_get(void)
{
	struct esdm_sec_stats stats = { .instances = 0, .seed_generation = 0 };

	esdm_drng_stats_foreach(esdm_sec_stats_cb, &stats);

	return stats;
}

/* Check that the one DRNG serving ordinary requests is at @expected */
static int esdm_sec_generation_check(long long expected)
{
	struct esdm_sec_stats stats;

	TEST_STEP("read the seed generation of the DRNG from its statistics");
	stats = esdm_sec_stats_get();

	TEST_REQUIRE("exactly one DRNG instance serves ordinary requests");
	if (!TEST_CHECK(stats.instances == 1, "%u", stats.instances))
		return 1;

	TEST_REQUIRE("the seed generation of the DRNG is %lld", expected);
	if (!TEST_CHECK(stats.seed_generation == expected, "%lld",
			stats.seed_generation))
		return 1;

	printf("the DRNG is at seed generation %lld\n", stats.seed_generation);

	return 0;
}

static void esdm_sec_sleep(time_t sec, long nsec)
{
	struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };

	nanosleep(&ts, NULL);
}

/* Milliseconds on CLOCK_MONOTONIC */
static long long esdm_sec_now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		return 0;

	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / (1000 * 1000);
}

/*
 * Request every poll slice until the seed generation moves past @from or a
 * request returns less, for at most @max_ms. Returns the generation, in
 * @seen_ms when it was seen and in @rc what the last request returned.
 */
static long long esdm_sec_request_until_next(long long from, long long max_ms,
					     long long *seen_ms, ssize_t *rc)
{
	long long start = esdm_sec_now_ms();
	uint8_t buf[ESDM_SEC_REQSIZE];
	long long gen;

	TEST_RUNUNTIL(
		"request %zu bytes every %d ms until the seed generation moves past %lld or a request returns less, for at most %lld ms",
		sizeof(buf), ESDM_SEC_POLL_MS, from, max_ms);
	for (;;) {
		*rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		if (*rc != (ssize_t)sizeof(buf))
			return from;
		gen = esdm_sec_stats_get().seed_generation;
		*seen_ms = esdm_sec_now_ms();
		if (gen != from || *seen_ms - start > max_ms)
			return gen;
		esdm_sec_sleep(0, ESDM_SEC_POLL_MS * 1000 * 1000);
	}
}

static int esdm_reseed_security_test(void)
{
	uint8_t buf[ESDM_SEC_REQSIZE];
	long long seeded_ms, reseeded_ms = 0, gen;
	unsigned int i;
	ssize_t rc = 0;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* One DRNG instance, the one whose seed generation is followed */
	TEST_STEP("use a single DRNG instance");
	esdm_config_max_nodes_set(1);

	TEST_STEP("set the reseed threshold to %u generate requests",
		  ESDM_SEC_THRESH);
	esdm_config_drng_reseed_thresh_set(ESDM_SEC_THRESH);

	TEST_STEP("initialize the ESDM");
	TEST_REQUIRE("the ESDM initializes");
	ret = esdm_init();
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto out;

	TEST_RUNUNTIL(
		"wait 100 ms until the ESDM is fully seeded, at most %u times",
		ESDM_SEC_SEED_SLICES);
	for (i = 0; i < ESDM_SEC_SEED_SLICES && !esdm_state_fully_seeded(); i++)
		esdm_sec_sleep(0, 100 * 1000 * 1000);

	TEST_REQUIRE("the ESDM is fully seeded");
	if (!TEST_CHECK(esdm_state_fully_seeded(), "%d",
			esdm_state_fully_seeded()))
		goto err;

	/* Seeded once, by the initialization */
	if (esdm_sec_generation_check(1))
		goto err;

	/* The interval is measured from a seeding this test sees happen */
	TEST_STEP("set the reseed interval to %d seconds", ESDM_SEC_INTERVAL);
	esdm_set_reseed_max_time(ESDM_SEC_INTERVAL);
	TEST_STEP(
		"force a reseed of the DRNGs and request %zu bytes from esdm_get_random_bytes_full_noblock",
		sizeof(buf));
	esdm_drng_force_reseed();
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	seeded_ms = esdm_sec_now_ms();
	TEST_REQUIRE("the request returns %zu bytes", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc))
		goto err;
	if (esdm_sec_generation_check(2))
		goto err;

	gen = esdm_sec_request_until_next(
		2, (ESDM_SEC_INTERVAL + ESDM_SEC_SLACK) * 1000, &reseeded_ms,
		&rc);
	TEST_REQUIRE("every request returns %zu bytes", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc))
		goto err;

	TEST_REQUIRE("a request reseeds the DRNG within %d seconds",
		     ESDM_SEC_INTERVAL + ESDM_SEC_SLACK);
	if (!TEST_CHECK(gen != 2, "%lld", gen))
		goto err;
	if (esdm_sec_generation_check(3))
		goto err;

	/*
	 * Seed times are whole seconds and a reseed is due a full second past
	 * the interval, so the reseeds are more than the interval apart.
	 */
	TEST_REQUIRE(
		"the DRNG is not reseeded before the interval of %d seconds elapsed",
		ESDM_SEC_INTERVAL);
	if (!TEST_CHECK(reseeded_ms - seeded_ms >=
				ESDM_SEC_INTERVAL * 1000 -
					ESDM_SEC_TOLERANCE_MS,
			"%lld ms", reseeded_ms - seeded_ms))
		goto err;

	/* Out of the way of the requests that follow */
	TEST_STEP("set the reseed interval to 3600 seconds");
	esdm_set_reseed_max_time(3600);

	TEST_STEP(
		"request %zu bytes from esdm_get_random_bytes_full_noblock, %u times",
		sizeof(buf), ESDM_SEC_REQUESTS);
	for (i = 0; i < ESDM_SEC_REQUESTS; i++) {
		rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		if (rc != (ssize_t)sizeof(buf))
			break;
	}

	TEST_REQUIRE("every request returns %zu bytes", sizeof(buf));
	if (!TEST_CHECK(i == ESDM_SEC_REQUESTS,
			"%u requests served, the last returned %zd", i, rc))
		goto err;

	/*
	 * A seed serves the threshold of requests, including the one it was
	 * made for: seed 3 served one, the requests take seed 4 and, with the
	 * last, seed 5.
	 */
	if (esdm_sec_generation_check(5))
		goto err;

	ret = 0;

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif /* ESDM_TESTMODE */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_reseed_security_test();
#else
	printf("test mode not compiled in\n");
	return 77;
#endif
}
