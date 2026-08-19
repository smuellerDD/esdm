/*
 * The Jitter RNG as the only credited entropy source, and what the ESDM does
 * when it loses it
 *
 * The ESDM is brought up with every other source declared to deliver nothing,
 * so the seed it hands out comes from this one source. It then loses that
 * source - the entropy rate is set to zero, which is what a Jitter RNG failing
 * its SP800-90B health tests amounts to for the accounting - and what each
 * interface does about it is pinned down here.
 *
 * The reseed interval elapsing is deliberately not the end of the output: it
 * asks for a reseed, and a reseed that collects nothing leaves the DRNG
 * producing from the state it has. See ESDM_DRNG_MAX_WITHOUT_RESEED in
 * esdm_definitions.h - the number of generate operations without a full
 * reseed is what bounds this, and reaching it is what takes the ESDM out of
 * operation - which is reached here by moving the DRNGs into a reseed that
 * comes back empty, with the budget sized from the statistics beforehand so
 * that it is that reseed and nothing else that crosses it.
 *
 * The prediction resistance interface stops without a budget to spend: it
 * hands out the state it was seeded with while the source still worked and
 * has nothing to collect for the request after it.
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
#include "esdm_logger.h"
#include "es_rates.h"
#include "ret_checkers.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT)

/* Seconds between two reseeds of the DRNG once the source is gone */
#define ESDM_SEC_RESEED_INTERVAL 3

/* Wait for the initial seeding at most this many 100ms slices */
#define ESDM_SEC_SEED_SLICES 100

/*
 * Requests granted before the ESDM has to be out of operation, once the budget
 * of generate operations without a full reseed is set to its minimum.
 */
#define ESDM_SEC_MAX_REQUESTS 8

/*
 * The counters of the DRNG serving ordinary requests, read back from the
 * statistics.
 */
struct esdm_sec_counters {
	unsigned int found;
	uint32_t requests_since_fully_seeded;
	bool fully_seeded;
};

static void esdm_sec_counters_cb(const struct esdm_drng_stats *stats,
				 void *priv)
{
	struct esdm_sec_counters *counters = (struct esdm_sec_counters *)priv;

	if (!strcmp(stats->type, "prediction resistance"))
		return;

	counters->found++;
	counters->requests_since_fully_seeded =
		stats->requests_since_fully_seeded;
	counters->fully_seeded = stats->fully_seeded;
}

static struct esdm_sec_counters esdm_sec_counters_get(void)
{
	struct esdm_sec_counters counters = { .found = 0,
					      .requests_since_fully_seeded = 0,
					      .fully_seeded = false };

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
	ssize_t rc;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * One DRNG, so that the requests below all land on the same instance
	 * and spend the same budget - with a DRNG per node they would be
	 * spread over instances that each have their own.
	 */
	esdm_config_max_nodes_set(1);

	/*
	 * Everything but the Jitter RNG is declared to deliver no entropy, so
	 * the ESDM can only reach the fully seeded level through that one
	 * source - and loses it with that source alone.
	 */
	esdm_test_es_rates_zero();
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	CKINT(esdm_init());

	for (i = 0; i < ESDM_SEC_SEED_SLICES && !esdm_state_fully_seeded(); i++)
		esdm_sec_sleep(0, 100 * 1000 * 1000);

	if (!esdm_state_fully_seeded()) {
		/*
		 * No working Jitter RNG on this machine, so the source this
		 * test is about never delivered - there is nothing to observe
		 * losing.
		 */
		printf("the ESDM is not fully seeded from the Jitter RNG alone, skipping test\n");
		ret = 77;
		goto out;
	}

	/* The Jitter RNG on its own carries the ESDM */
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	if (rc != (ssize_t)sizeof(buf)) {
		printf("cannot obtain %zu bytes with the Jitter RNG credited: %zd\n",
		       sizeof(buf), rc);
		goto err;
	}

	if (esdm_sec_buf_is_zero(buf, sizeof(buf))) {
		printf("the ESDM handed out an all zero buffer\n");
		goto err;
	}

	printf("%zu bytes obtained with the Jitter RNG as the only credited source\n",
	       sizeof(buf));

	/*
	 * The source fails: a Jitter RNG whose SP800-90B health tests trip
	 * stops being credited, which is what a rate of zero expresses.
	 */
	esdm_config_es_jent_entropy_rate_set(0);
	esdm_set_reseed_max_time(ESDM_SEC_RESEED_INTERVAL);

	/* Sit out the interval, so the DRNG is due for a reseed it cannot get */
	esdm_sec_sleep(ESDM_SEC_RESEED_INTERVAL + 1, 0);

	/*
	 * The interval elapsing asks for a reseed, it does not stop the DRNG:
	 * one that cannot be reseeded keeps producing from the state it has
	 * until it has spent the generate operations it is allowed without a
	 * full reseed.
	 */
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	if (rc != (ssize_t)sizeof(buf)) {
		printf("the ESDM stopped after %d seconds without a credited entropy source: %zd\n",
		       ESDM_SEC_RESEED_INTERVAL, rc);
		goto err;
	}

	if (!esdm_state_operational()) {
		printf("the ESDM left operational mode on the reseed interval alone\n");
		goto err;
	}

	printf("still %zd bytes after the reseed interval elapsed, as documented\n",
	       rc);

	/*
	 * The prediction resistance interface is the one that stops without a
	 * budget to spend: the entropy behind its output has to be collected
	 * for the request it serves, and there is none to collect.
	 */
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		memset(buf, 0, sizeof(buf));
		rc = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		if (rc <= 0)
			break;
	}

	if (rc > 0) {
		printf("the prediction resistance generator still hands out random bits after %u requests without a credited entropy source\n",
		       ESDM_SEC_MAX_REQUESTS);
		goto err;
	}

	if (!esdm_sec_buf_is_zero(buf, sizeof(buf))) {
		printf("the prediction resistance generator wrote into the buffer while reporting %zd\n",
		       rc);
		goto err;
	}

	printf("the prediction resistance generator hands out nothing after %u request(s) (%zd)\n",
	       i + 1, rc);

	/*
	 * What stops the ordinary interface is the budget of generate
	 * operations without a full reseed.
	 */
	esdm_set_reseed_max_time(3600);

	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	if (rc != (ssize_t)sizeof(buf)) {
		printf("the ESDM stopped before its budget was touched: %zd\n",
		       rc);
		goto err;
	}

	/* Size the budget to what the DRNG has spent, plus one */
	counters = esdm_sec_counters_get();
	if (counters.found != 1) {
		printf("%u DRNG instances serve ordinary requests, expected 1\n",
		       counters.found);
		goto err;
	}
	budget = counters.requests_since_fully_seeded + 1;
	esdm_config_drng_max_wo_reseed_set(budget);

	/*
	 * One generate operation below the budget, so the budget by itself
	 * holds nothing back - the ESDM produces as before.
	 */
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	if (rc != (ssize_t)sizeof(buf)) {
		printf("the ESDM stopped below its budget of %u: %zd\n", budget,
		       rc);
		goto err;
	}

	if (!esdm_state_operational()) {
		printf("the ESDM left operational mode below its budget of %u\n",
		       budget);
		goto err;
	}

	printf("still %zd bytes with %u of %u generate operations spent without a full reseed\n",
	       rc, counters.requests_since_fully_seeded, budget);

	/*
	 * Now move the DRNGs into a reseed they cannot satisfy - the operator
	 * action behind esdm-tool --reseed-crng, and what the ESDM does on its
	 * own once the reseed interval elapses.
	 */
	esdm_drng_force_reseed();

	/*
	 * The request that carries the reseed still produces: the budget is
	 * spent while it runs and acted upon at the start of a generate, so it
	 * is the request after it that finds the ESDM out of operation.
	 */
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		memset(buf, 0, sizeof(buf));
		rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		if (rc <= 0)
			break;
	}

	if (rc > 0) {
		printf("the ESDM still hands out random bits %u requests after a reseed it could not satisfy\n",
		       ESDM_SEC_MAX_REQUESTS);
		goto err;
	}

	if (!esdm_sec_buf_is_zero(buf, sizeof(buf))) {
		printf("the ESDM wrote into the buffer while reporting %zd\n",
		       rc);
		goto err;
	}

	if (esdm_state_operational()) {
		printf("the ESDM reports itself operational after refusing to hand out random bits\n");
		goto err;
	}

	counters = esdm_sec_counters_get();
	if (counters.found != 1 ||
	    counters.requests_since_fully_seeded < budget) {
		printf("the DRNG is out of operation with %u of %u generate operations spent\n",
		       counters.requests_since_fully_seeded, budget);
		goto err;
	}

	printf("no output %u request(s) after a reseed that collected nothing (%zd), %u of %u spent\n",
	       i + 1, rc, counters.requests_since_fully_seeded, budget);

	/* And it stays that way, on every interface that produces output */
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		ssize_t rcs[3];
		size_t j;

		memset(buf, 0, sizeof(buf));
		rcs[0] = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		rcs[1] = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		rcs[2] = esdm_get_random_bytes(buf, sizeof(buf));

		for (j = 0; j < 3; j++) {
			if (rcs[j] > 0) {
				printf("the ESDM resumed handing out random bits: interface %zu returned %zd\n",
				       j, rcs[j]);
				goto err;
			}
		}

		if (!esdm_sec_buf_is_zero(buf, sizeof(buf))) {
			printf("the ESDM wrote into the buffer while reporting %zd / %zd / %zd\n",
			       rcs[0], rcs[1], rcs[2]);
			goto err;
		}
	}

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
