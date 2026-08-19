/*
 * Test of the asynchronous reseed worker
 *
 * Its jobs are observed here, all without a single request being made: a DRNG
 * that never reached the fully seeded level is brought up - nothing else does
 * that for an instance no request lands on - the prediction resistance
 * instance, which sits on the seed of the request it last served, is reseeded
 * before that seed ages, once nothing is due the worker waits for the reseed
 * it knows is coming instead of looking again every second, and a reseed
 * interval set while it waits reaches it there. A reseed interval of zero
 * seconds sends the worker home, since the requests reseed themselves then,
 * and an interval that grows again brings one back.
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

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "ret_checkers.h"
#include "threading_support.h"

#ifdef ESDM_TESTMODE

/* Reseed interval the test operates the ESDM with */
#define ESDM_RSD_INTERVAL 1

/* Number of DRNG instances asked for - the ESDM caps this to its node count */
#define ESDM_RSD_NODES 4

/* Wait for the worker at most this many 100ms slices */
#define ESDM_RSD_SLICES 200

/* Reseed interval the worker's wait is observed with. */
#define ESDM_RSD_LONG_INTERVAL 120

/* Slices the worker is watched over while nothing is due */
#define ESDM_RSD_IDLE_SLICES 30

/* Slices the worker gets to notice a shortened reseed interval. */
#define ESDM_RSD_WAKE_SLICES 30

/* What the statistics say about the DRNGs, as one snapshot */
struct rsd_state {
	/* Instances serving ordinary requests */
	unsigned int nodes;
	unsigned int nodes_unseeded;
	/* The prediction resistance instance */
	bool pr_found;
	long long pr_seed_generation;
	/* The earliest reseed any of them reports */
	long long soonest_reseed;
};

static void rsd_state_cb(const struct esdm_drng_stats *stats, void *priv)
{
	struct rsd_state *state = (struct rsd_state *)priv;

	if (stats->seconds_until_reseed < state->soonest_reseed)
		state->soonest_reseed = stats->seconds_until_reseed;

	if (!strcmp(stats->type, "prediction resistance")) {
		state->pr_found = true;
		state->pr_seed_generation = stats->seed_generation;
		return;
	}

	state->nodes++;
	if (!stats->fully_seeded)
		state->nodes_unseeded++;
}

static struct rsd_state rsd_state_get(void)
{
	struct rsd_state state;

	memset(&state, 0, sizeof(state));
	state.soonest_reseed = LLONG_MAX;
	esdm_drng_stats_foreach(rsd_state_cb, &state);

	return state;
}

static void rsd_sleep_slice(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/*
 * What the worker does once every DRNG is seeded and nothing is due: it waits
 * for the reseed it knows is coming rather than looking again every second.
 */
static int rsd_idle_check(void)
{
	struct rsd_state state;
	uint64_t next = 0, passes, later;
	unsigned int i;

	esdm_set_reseed_max_time(ESDM_RSD_LONG_INTERVAL);

	/* Setting the interval wakes the worker - let it complete a pass */
	for (i = 0; i < ESDM_RSD_SLICES; i++) {
		if (esdm_drng_mgr_reseed_worker_next_pass(&next) && next > 1)
			break;
		rsd_sleep_slice();
	}

	if (!esdm_drng_mgr_reseed_worker_next_pass(&next)) {
		printf("the reseed worker has no pass scheduled - it is not waiting for a reseed\n");
		return 1;
	}

	if (next <= 1) {
		printf("the reseed worker looks at the DRNGs again in %" PRIu64
		       " seconds - it is not waiting for a reseed\n",
		       next);
		return 1;
	}

	printf("the reseed worker waits %" PRIu64
	       " seconds before it looks again\n",
	       next);

	/* Which is what the DRNGs themselves report */
	state = rsd_state_get();
	if (state.soonest_reseed <= 0 ||
	    state.soonest_reseed > ESDM_RSD_LONG_INTERVAL) {
		printf("the DRNG statistics report the next reseed in %lld seconds, outside the interval of %u seconds\n",
		       state.soonest_reseed, ESDM_RSD_LONG_INTERVAL);
		return 1;
	}

	printf("the earliest reseed the DRNG statistics report is %lld seconds out\n",
	       state.soonest_reseed);

	/* And the worker stays where it is. */
	passes = esdm_drng_mgr_reseed_worker_passes();
	for (i = 0; i < ESDM_RSD_IDLE_SLICES; i++)
		rsd_sleep_slice();
	later = esdm_drng_mgr_reseed_worker_passes();

	if (later != passes) {
		printf("the reseed worker ran %" PRIu64
		       " pass(es) while no reseed was due\n",
		       later - passes);
		return 1;
	}

	printf("the reseed worker ran no pass over %u slices, still at pass %" PRIu64
	       "\n",
	       ESDM_RSD_IDLE_SLICES, later);

	return 0;
}

/* A reseed interval set while the worker waits. */
static int rsd_shorten_check(void)
{
	uint64_t passes = esdm_drng_mgr_reseed_worker_passes();
	unsigned int i;

	esdm_set_reseed_max_time(ESDM_RSD_INTERVAL);

	for (i = 0; i < ESDM_RSD_WAKE_SLICES; i++) {
		if (esdm_drng_mgr_reseed_worker_passes() > passes)
			break;
		rsd_sleep_slice();
	}

	if (esdm_drng_mgr_reseed_worker_passes() <= passes) {
		printf("the reseed worker slept through the interval of %u second(s) it was given, still at pass %" PRIu64
		       "\n",
		       ESDM_RSD_INTERVAL, passes);
		return 1;
	}

	printf("the reseed worker took up the interval of %u second(s) after %u slice(s)\n",
	       ESDM_RSD_INTERVAL, i + 1);

	return 0;
}

/*
 * A reseed interval of zero seconds is the request that every generate
 * operation reseeds first - which leaves the worker nothing to do ahead of
 * them, so it goes home until the interval grows again.
 */
static int rsd_zero_interval_check(void)
{
	uint64_t passes, next;
	unsigned int i;

	esdm_set_reseed_max_time(0);

	for (i = 0; i < ESDM_RSD_WAKE_SLICES; i++) {
		if (!esdm_drng_mgr_reseed_worker_running())
			break;
		rsd_sleep_slice();
	}

	if (esdm_drng_mgr_reseed_worker_running()) {
		printf("the reseed worker stayed on duty over %u slice(s) of a reseed interval of zero seconds\n",
		       ESDM_RSD_WAKE_SLICES);
		return 1;
	}

	printf("the reseed worker left after %u slice(s) when the reseed interval became zero\n",
	       i + 1);

	/* And it left nothing scheduled behind it */
	if (esdm_drng_mgr_reseed_worker_next_pass(&next)) {
		printf("a pass is still scheduled in %" PRIu64
		       " seconds with no worker on duty\n",
		       next);
		return 1;
	}

	/* The interval grows again - and a worker is back on it */
	passes = esdm_drng_mgr_reseed_worker_passes();
	esdm_set_reseed_max_time(ESDM_RSD_INTERVAL);

	for (i = 0; i < ESDM_RSD_WAKE_SLICES; i++) {
		if (esdm_drng_mgr_reseed_worker_running() &&
		    esdm_drng_mgr_reseed_worker_passes() > passes)
			break;
		rsd_sleep_slice();
	}

	if (!esdm_drng_mgr_reseed_worker_running() ||
	    esdm_drng_mgr_reseed_worker_passes() <= passes) {
		printf("no reseed worker took up the interval of %u second(s) again, still at pass %" PRIu64
		       "\n",
		       ESDM_RSD_INTERVAL, passes);
		return 1;
	}

	printf("a reseed worker is back on duty after %u slice(s), at pass %" PRIu64
	       "\n",
	       i + 1, esdm_drng_mgr_reseed_worker_passes());

	return 0;
}

static int esdm_reseed_worker_test(void)
{
	struct rsd_state before, after;
	unsigned int i;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * Ask for more than one instance: what is under test is what happens
	 * to the ones no request ever lands on, and with a single DRNG there
	 * are none of those. The ESDM caps this to the nodes it sees.
	 */
	esdm_config_max_nodes_set(ESDM_RSD_NODES);

	CKINT(esdm_init());

	before = rsd_state_get();
	if (!before.nodes || !before.pr_found) {
		printf("the statistics report %u DRNGs and %s prediction resistance instance\n",
		       before.nodes, before.pr_found ? "a" : "no");
		goto err;
	}

	printf("%u DRNG instance(s), %u of them not seeded yet\n", before.nodes,
	       before.nodes_unseeded);

	/* The worker is taken from the thread pool, so there has to be one */
	if (thread_init(1)) {
		printf("cannot initialize threading support\n");
		goto err;
	}

	/*
	 * Short enough that the test does not have to sit out the default
	 * interval of ten minutes.
	 */
	esdm_set_reseed_max_time(ESDM_RSD_INTERVAL);

	if (!esdm_drng_mgr_reseed_worker_start() ||
	    !esdm_drng_mgr_reseed_worker_running()) {
		printf("the reseed worker is not on duty\n");
		goto err;
	}

	/*
	 * Nothing is requested from here on. What the worker does now, it went
	 * looking for on its own.
	 */
	for (i = 0; i < ESDM_RSD_SLICES; i++) {
		after = rsd_state_get();
		if (!after.nodes_unseeded &&
		    after.pr_seed_generation > before.pr_seed_generation)
			break;
		rsd_sleep_slice();
	}

	after = rsd_state_get();

	/* Every instance is seeded. */
	if (after.nodes_unseeded) {
		printf("%u of %u DRNG instances are still not seeded\n",
		       after.nodes_unseeded, after.nodes);
		goto err;
	}

	if (before.nodes_unseeded) {
		printf("the worker brought %u DRNG instance(s) up to the fully seeded level\n",
		       before.nodes_unseeded);
	} else {
		printf("every DRNG instance was already seeded at start up\n");
	}

	/* And the prediction resistance instance is kept fresh */
	if (after.pr_seed_generation <= before.pr_seed_generation) {
		printf("the prediction resistance DRNG was not reseeded: seed generation %lld\n",
		       after.pr_seed_generation);
		goto err;
	}

	printf("the prediction resistance DRNG was reseeded without a request: seed generation %lld -> %lld\n",
	       before.pr_seed_generation, after.pr_seed_generation);

	/* With every instance seeded, what does the worker do next? */
	if (rsd_idle_check())
		goto err;

	/* And what does it do when that changes under it? */
	if (rsd_shorten_check())
		goto err;

	/* Down to the interval that has no work for it at all */
	if (rsd_zero_interval_check())
		goto err;

out:
	esdm_drng_mgr_reseed_worker_stop();
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
	return esdm_reseed_worker_test();
#else
	return 77;
#endif
}
