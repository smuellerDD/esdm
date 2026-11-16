/*
 * Reseeding of the node DRNGs without a reseed worker
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

/*
 * A node DRNG hands its reseed to the reseed worker. libesdm used without its
 * monitor has none, and neither has a process whose worker could not start:
 * the DRNG has to reseed inline then, or it serves on its first seed for good.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"

#ifdef ESDM_TESTMODE

/* Instances asked for - the ESDM caps this to its node count */
#define NW_NODES 4

/* Requests after which a DRNG reseeds, and the requests issued */
#define NW_THRESH 8
#define NW_REQUESTS (8 * NW_THRESH)

struct nw_state {
	long long seed_generation;
	bool found;
};

/* The DRNG serving node 1, which esdm_config_thread_node_set(0) selects */
static void nw_state_cb(const struct esdm_drng_stats *stats, void *priv)
{
	struct nw_state *state = priv;

	if (stats->node_valid && stats->node == 1) {
		state->seed_generation = stats->seed_generation;
		state->found = true;
	}
}

static int nw_test(void)
{
	struct nw_state before = { 0 }, after = { 0 };
	uint8_t buf[32];
	unsigned int i;
	int ret = 0;

	esdm_config_max_nodes_set(NW_NODES);
	esdm_config_drng_reseed_thresh_set(NW_THRESH);

	if (esdm_init()) {
		printf("FAIL: esdm_init failed\n");
		return 1;
	}

	if (esdm_drng_mgr_reseed_worker_running()) {
		printf("FAIL: a reseed worker runs without esdm_init_monitor()\n");
		ret = 1;
		goto out;
	}

	esdm_force_fully_seeded_all_drbgs();
	esdm_config_thread_node_set(0);

	esdm_drng_stats_foreach(nw_state_cb, &before);
	if (!before.found) {
		printf("SKIP: no node DRNG besides the initial one\n");
		ret = 77;
		goto out;
	}

	for (i = 0; i < NW_REQUESTS; i++) {
		if (esdm_get_random_bytes_full(buf, sizeof(buf)) !=
		    (ssize_t)sizeof(buf)) {
			printf("FAIL: request %u produced no data\n", i);
			ret = 1;
			goto out;
		}
	}

	esdm_drng_stats_foreach(nw_state_cb, &after);
	printf("seed generation of node 1: %lld before, %lld after %u requests\n",
	       before.seed_generation, after.seed_generation, NW_REQUESTS);
	if (after.seed_generation <= before.seed_generation) {
		printf("FAIL: the node DRNG was not reseeded without a worker\n");
		ret = 1;
	}

out:
	esdm_fini();
	return ret;
}

#endif /* ESDM_TESTMODE */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	esdm_logger_set_verbosity(LOGGER_NONE);
	return nw_test();
#else
	return 77;
#endif
}
