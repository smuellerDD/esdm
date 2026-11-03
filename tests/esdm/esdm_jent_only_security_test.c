/*
 * The Jitter RNG as the only credited entropy source, and what the ESDM does
 * when it loses it
 *
 * Every other source is credited with zero bits. The loss is a Jitter RNG
 * rate of zero, which is what failing its SP800-90B health tests amounts to
 * for the accounting. The prediction resistance interface then stops at once,
 * the ordinary one once it spent its budget of generate operations without a
 * full reseed (ESDM_DRNG_MAX_WITHOUT_RESEED), which the test lowers to end the
 * output on every interface.
 *
 * Reseeds are forced, not waited for: the reseed interval stays far longer
 * than the test runs.
 *
 * NTG.1 seeding needs a second source unless the Jitter RNG runs in its own
 * NTG.1 mode, so the auxiliary pool is then credited with one seed, which the
 * initial seeding spends.
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

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_jent.h"
#include "esdm_logger.h"
#include "es_rates.h"
#include "ret_checkers.h"
#include "../test_plan.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT)

/*
 * Wait for the initial seeding at most this many 100ms slices, room for a
 * sanitizer build. Running out is a failure, not a skip.
 */
#define ESDM_SEC_SEED_SLICES 900

/*
 * Requests before the output has to have stopped: the PR DRNG may hold one
 * seed from before the loss, the ordinary DRNG stops at the second forced
 * reseed at the latest.
 */
#define ESDM_SEC_MAX_REQUESTS 2

/* Rounds of requests on every interface showing that the output stays off */
#define ESDM_SEC_STOPPED_ROUNDS 8

/* NTG.1 seeding wants a second source - see esdm_fully_seeded() */
static bool esdm_sec_needs_second_source(void)
{
	return esdm_ntg1_2024_compliant() && !esdm_jent_ntg1();
}

/*
 * One seed's worth plus the oversampling of the conditioning, so the auxiliary
 * pool counts as a source. Only into an empty pool, so that nothing is left
 * once the initial seeding collected it.
 */
static void esdm_sec_feed_aux(void)
{
	uint8_t seed[2 * ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	size_t i;

	if (esdm_avail_entropy_aux())
		return;

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;
	esdm_pool_insert_aux(seed, sizeof(seed),
			     ESDM_DRNG_SECURITY_STRENGTH_BITS +
				     esdm_compress_osr());
}

/* The counters of the DRNG serving ordinary requests */
struct esdm_sec_counters {
	unsigned int instances;
	uint32_t requests_since_fully_seeded;
};

static void esdm_sec_counters_cb(const struct esdm_drng_stats *stats,
				 void *priv)
{
	struct esdm_sec_counters *counters = (struct esdm_sec_counters *)priv;

	if (!strcmp(stats->type, "prediction resistance"))
		return;

	counters->instances++;
	counters->requests_since_fully_seeded =
		stats->requests_since_fully_seeded;
}

static struct esdm_sec_counters esdm_sec_counters_get(void)
{
	struct esdm_sec_counters counters = { .instances = 0,
					      .requests_since_fully_seeded =
						      0 };

	esdm_drng_stats_foreach(esdm_sec_counters_cb, &counters);

	return counters;
}

static void esdm_sec_sleep(time_t sec, long nsec)
{
	struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };

	nanosleep(&ts, NULL);
}

static bool esdm_sec_buf_is_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return false;
	}

	return true;
}

static int esdm_jent_only_security_test(void)
{
	struct esdm_sec_counters counters;
	uint8_t buf[32];
	unsigned int i;
	uint32_t budget;
	ssize_t rc, max_rc = 0;
	size_t max_rc_if = 0;
	bool written = false, jent_active;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* One DRNG instance, so that every request spends the same budget */
	TEST_STEP("use a single DRNG instance");
	esdm_config_max_nodes_set(1);

	/* So that the ESDM is seeded by, and loses, this one source alone */
	TEST_STEP(
		"credit the Jitter RNG with %u bits, every other entropy source with 0 bits",
		ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_test_es_rates_zero();
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	TEST_STEP("initialize the ESDM");
	TEST_REQUIRE("the ESDM initializes");
	ret = esdm_init();
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto out;

	/*
	 * Without a working Jitter RNG there is nothing to lose. That is known
	 * once initialized, a working one that does not seed is a failure.
	 */
	TEST_REQUIRE(
		"the Jitter RNG works on this machine (test skipped otherwise)");
	jent_active = esdm_es_jent.active && esdm_es_jent.active();
	if (!TEST_CHECK(jent_active, "%d", jent_active)) {
		printf("the Jitter RNG is not usable on this machine, skipping test\n");
		ret = 77;
		goto out;
	}

	if (esdm_sec_needs_second_source()) {
		TEST_RUNUNTIL(
			"credit the auxiliary pool with %u bits whenever it is empty and wait 100 ms until the ESDM is fully seeded, at most %u times",
			ESDM_DRNG_SECURITY_STRENGTH_BITS + esdm_compress_osr(),
			ESDM_SEC_SEED_SLICES);
	} else {
		TEST_RUNUNTIL(
			"wait 100 ms until the ESDM is fully seeded, at most %u times",
			ESDM_SEC_SEED_SLICES);
	}
	for (i = 0; i < ESDM_SEC_SEED_SLICES && !esdm_state_fully_seeded();
	     i++) {
		if (esdm_sec_needs_second_source())
			esdm_sec_feed_aux();
		esdm_sec_sleep(0, 100 * 1000 * 1000);
	}

	TEST_REQUIRE("the ESDM is fully seeded with the Jitter RNG credited");
	if (!TEST_CHECK(esdm_state_fully_seeded(), "%d",
			esdm_state_fully_seeded()))
		goto err;

	/* That would be a second source once the Jitter RNG is gone */
	TEST_REQUIRE("no entropy is left in the auxiliary pool");
	if (!TEST_CHECK(!esdm_avail_entropy_aux(), "%u",
			esdm_avail_entropy_aux()))
		goto err;

	TEST_STEP("request %zu bytes from esdm_get_random_bytes_full_noblock",
		  sizeof(buf));
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc))
		goto err;

	TEST_REQUIRE("the returned buffer is not all zero");
	if (!TEST_CHECK(!esdm_sec_buf_is_zero(buf, sizeof(buf)), "%d",
			!esdm_sec_buf_is_zero(buf, sizeof(buf))))
		goto err;

	printf("%zu bytes obtained with the Jitter RNG as the only credited source\n",
	       sizeof(buf));

	TEST_STEP("fail the Jitter RNG by crediting it with 0 bits");
	esdm_config_es_jent_entropy_rate_set(0);

	/*
	 * The PR DRNG seeds itself for each output, only one can come from a
	 * seed collected before the loss.
	 */
	TEST_RUNUNTIL(
		"request %zu bytes from esdm_get_random_bytes_pr_noblock until it returns no bytes, at most %u times",
		sizeof(buf), ESDM_SEC_MAX_REQUESTS);
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		memset(buf, 0, sizeof(buf));
		rc = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		if (rc <= 0)
			break;
	}

	TEST_REQUIRE(
		"esdm_get_random_bytes_pr_noblock returns no bytes within %u requests",
		ESDM_SEC_MAX_REQUESTS);
	if (!TEST_CHECK(rc <= 0, "%zd", rc))
		goto err;

	TEST_REQUIRE("the buffer of the refused request is left all zero");
	if (!TEST_CHECK(esdm_sec_buf_is_zero(buf, sizeof(buf)), "%d",
			esdm_sec_buf_is_zero(buf, sizeof(buf))))
		goto err;

	printf("the prediction resistance generator hands out nothing after %u request(s) (%zd)\n",
	       i + 1, rc);

	/* A reseed that collects nothing does not stop it within its budget */
	TEST_STEP(
		"force a reseed of the DRNGs and request %zu bytes from esdm_get_random_bytes_full_noblock",
		sizeof(buf));
	esdm_drng_force_reseed();
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc))
		goto err;

	TEST_REQUIRE("the returned buffer is not all zero");
	if (!TEST_CHECK(!esdm_sec_buf_is_zero(buf, sizeof(buf)), "%d",
			!esdm_sec_buf_is_zero(buf, sizeof(buf))))
		goto err;

	TEST_REQUIRE("the ESDM is operational");
	if (!TEST_CHECK(esdm_state_operational(), "%d",
			esdm_state_operational()))
		goto err;

	TEST_STEP(
		"read the generate operations since the last full reseed from the DRNG statistics");
	counters = esdm_sec_counters_get();
	TEST_REQUIRE("exactly one DRNG instance serves ordinary requests");
	if (!TEST_CHECK(counters.instances == 1, "%u", counters.instances))
		goto err;
	budget = counters.requests_since_fully_seeded + 1;
	TEST_STEP(
		"limit the generate operations without a full reseed to %u (spent + 1)",
		budget);
	esdm_config_drng_max_wo_reseed_set(budget);

	/*
	 * Spent operations are only added up by a reseed without full entropy,
	 * so the lowered budget holds nothing back until the next one.
	 */
	TEST_STEP("request %zu bytes from esdm_get_random_bytes_full_noblock",
		  sizeof(buf));
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc))
		goto err;

	TEST_REQUIRE("the ESDM is operational");
	if (!TEST_CHECK(esdm_state_operational(), "%d",
			esdm_state_operational()))
		goto err;

	/*
	 * Reseeds it cannot satisfy, as esdm-tool --reseed-crng or an elapsed
	 * interval cause - one per request, so every request is added up.
	 */
	TEST_RUNUNTIL(
		"force a reseed of the DRNGs and request %zu bytes from esdm_get_random_bytes_full_noblock until it returns no bytes, at most %u times",
		sizeof(buf), ESDM_SEC_MAX_REQUESTS);
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		esdm_drng_force_reseed();
		memset(buf, 0, sizeof(buf));
		rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		if (rc <= 0)
			break;
	}

	TEST_REQUIRE(
		"esdm_get_random_bytes_full_noblock returns no bytes within %u requests",
		ESDM_SEC_MAX_REQUESTS);
	if (!TEST_CHECK(rc <= 0, "%zd", rc))
		goto err;

	TEST_REQUIRE("the buffer of the refused request is left all zero");
	if (!TEST_CHECK(esdm_sec_buf_is_zero(buf, sizeof(buf)), "%d",
			esdm_sec_buf_is_zero(buf, sizeof(buf))))
		goto err;

	TEST_REQUIRE("the ESDM is not operational");
	if (!TEST_CHECK(!esdm_state_operational(), "%d",
			!esdm_state_operational()))
		goto err;

	TEST_STEP(
		"read the generate operations since the last full reseed from the DRNG statistics");
	counters = esdm_sec_counters_get();
	TEST_REQUIRE(
		"exactly one DRNG instance has spent at least %u generate operations",
		budget);
	if (!TEST_CHECK(counters.instances == 1, "%u", counters.instances) ||
	    !TEST_CHECK(counters.requests_since_fully_seeded >= budget,
			"%u of %u", counters.requests_since_fully_seeded,
			budget))
		goto err;

	printf("no output %u request(s) after reseeds that collected nothing (%zd), %u of %u spent\n",
	       i + 1, rc, counters.requests_since_fully_seeded, budget);

	/* And it stays that way, on every interface */
	TEST_STEP(
		"request %zu bytes from esdm_get_random_bytes_full_noblock, esdm_get_random_bytes_pr_noblock and esdm_get_random_bytes, %u times",
		sizeof(buf), ESDM_SEC_STOPPED_ROUNDS);
	for (i = 0; i < ESDM_SEC_STOPPED_ROUNDS; i++) {
		ssize_t rcs[3];
		size_t j;

		memset(buf, 0, sizeof(buf));
		rcs[0] = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		rcs[1] = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		rcs[2] = esdm_get_random_bytes(buf, sizeof(buf));

		/* Check the largest return value */
		for (j = 0; j < 3; j++) {
			if ((!i && !j) || rcs[j] > max_rc) {
				max_rc = rcs[j];
				max_rc_if = j;
			}
		}

		if (!esdm_sec_buf_is_zero(buf, sizeof(buf)))
			written = true;
	}

	TEST_REQUIRE("no interface returns any bytes");
	if (!TEST_CHECK(max_rc <= 0, "%zd from interface %zu", max_rc,
			max_rc_if))
		goto err;

	TEST_REQUIRE("the buffer is left all zero");
	if (!TEST_CHECK(!written, "%d", written))
		goto err;

	printf("nothing is handed out on any interface afterwards\n");

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif /* ESDM_TESTMODE && ESDM_ES_JENT */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT)
	return esdm_jent_only_security_test();
#else
	printf("test mode or the Jitter RNG entropy source not compiled in\n");
	return 77;
#endif
}
