/*
 * Test that several Jitter RNG instances refill the block cache
 *
 * With es_jent_instances above 1 the cache of the Jitter RNG is refilled by
 * that many collectors side by side, each in a thread of its own per round of
 * the ES monitor (thread_fork_join(), inline on a single CPU). The test sets
 * three instances before esdm_init(), runs the monitor callback of the source
 * itself - the first round only arms it - and takes the blocks out through
 * get_cached: every one carries the entropy of the configured rate, and the
 * cache delivers blocks until it is drained.
 *
 * It also checks that esdm_config_es_jent_instances_set() keeps the number
 * within 1 to 64.
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "memset_secure.h"

#define ES_JI_INSTANCES 3

#if (ESDM_JENT_ENTROPY_BLOCKS != 0)

static int es_ji_config(void)
{
	int ret = 0;

	esdm_config_es_jent_instances_set(0);
	if (esdm_config_es_jent_instances() != 1) {
		printf("ES Jitter RNG instances - fail: 0 instances kept as %u\n",
		       esdm_config_es_jent_instances());
		ret++;
	}

	esdm_config_es_jent_instances_set(1000);
	if (esdm_config_es_jent_instances() != 64) {
		printf("ES Jitter RNG instances - fail: 1000 instances kept as %u\n",
		       esdm_config_es_jent_instances());
		ret++;
	}

	esdm_config_es_jent_instances_set(ES_JI_INSTANCES);
	if (esdm_config_es_jent_instances() != ES_JI_INSTANCES) {
		printf("ES Jitter RNG instances - fail: %u instances kept as %u\n",
		       ES_JI_INSTANCES, esdm_config_es_jent_instances());
		ret++;
	}

	if (!ret)
		printf("ES Jitter RNG instances - pass: the number is kept within 1 to 64\n");

	return ret;
}

static int es_ji_refill(void)
{
	struct esdm_es_cb *es = esdm_es[esdm_ext_es_jitter];
	uint32_t bits = esdm_get_seed_entropy_osr(false, true);
	uint32_t expected =
		esdm_fast_noise_entropylevel(esdm_config_es_jent_entropy_rate(),
					     bits);
	struct entropy_es eb_es;
	unsigned int i, hits = 0;
	int ret = 0;

	if (!es->monitor_es || !es->get_cached) {
		printf("ES Jitter RNG instances - fail: no cache callbacks\n");
		return 1;
	}
	if (!es->active()) {
		printf("ES Jitter RNG instances - Jitter RNG not available, skipping\n");
		return 77;
	}

	/* The first round arms the cache, the second fills it */
	es->monitor_es();
	es->monitor_es();

	for (i = 0; i <= ESDM_JENT_ENTROPY_BLOCKS; i++) {
		memset(&eb_es, 0, sizeof(eb_es));
		if (!es->get_cached(&eb_es, bits))
			break;
		hits++;
		if (eb_es.e_bits != expected) {
			printf("ES Jitter RNG instances - fail: block %u carries %u bits instead of %u\n",
			       i, eb_es.e_bits, expected);
			ret++;
		}
	}
	memset_secure(&eb_es, 0, sizeof(eb_es));

	printf("ES Jitter RNG instances - %u instances filled %u of %u blocks\n",
	       esdm_config_es_jent_instances(), hits, ESDM_JENT_ENTROPY_BLOCKS);

	/*
	 * Nothing else takes from the cache here but a seeding the monitor
	 * might start, which takes a block or two at most.
	 */
	if (hits < ESDM_JENT_ENTROPY_BLOCKS / 2) {
		printf("ES Jitter RNG instances - fail: the instances did not refill the cache\n");
		ret++;
	}
	if (hits > ESDM_JENT_ENTROPY_BLOCKS) {
		printf("ES Jitter RNG instances - fail: more blocks than slots\n");
		ret++;
	}

	if (!ret)
		printf("ES Jitter RNG instances - pass: the instances refilled the cache\n");

	return ret;
}

static int es_ji_test(void)
{
	int ret = es_ji_config(), rc;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* All DRNGs fully seeded by the Jitter RNG alone, so none asks again */
	esdm_config_max_nodes_set(1);
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	rc = esdm_init();
	if (rc) {
		printf("ES Jitter RNG instances - fail: esdm_init: %d\n", rc);
		return 1;
	}

	rc = es_ji_refill();
	if (rc == 77 && !ret)
		ret = 77;
	else if (rc != 77)
		ret += rc;

	esdm_fini();

	return ret;
}

#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if (ESDM_JENT_ENTROPY_BLOCKS != 0)
	return es_ji_test();
#else
	printf("no Jitter RNG cache in this build\n");
	return 77;
#endif
}
