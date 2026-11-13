/*
 * Test that several Jitter RNG collectors serve
 *
 * The test sets three collectors before esdm_init() and reads through the
 * source as often: every read carries the entropy of the configured rate.
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

static int es_ji_read(void)
{
	struct esdm_es_cb *es = esdm_es[esdm_ext_es_jitter];
	uint32_t bits = esdm_get_seed_entropy_osr(false, true);
	uint32_t expected =
		esdm_fast_noise_entropylevel(esdm_config_es_jent_entropy_rate(),
					     bits);
	struct entropy_es eb_es;
	unsigned int i;
	int ret = 0;

	if (!es->active()) {
		printf("ES Jitter RNG instances - Jitter RNG not available, skipping\n");
		return 77;
	}

	for (i = 0; i < ES_JI_INSTANCES; i++) {
		memset(&eb_es, 0, sizeof(eb_es));
		es->get_ent(&eb_es, bits);
		if (eb_es.e_bits != expected) {
			printf("ES Jitter RNG instances - fail: read %u carries %u bits instead of %u\n",
			       i, eb_es.e_bits, expected);
			ret++;
		}
	}
	memset_secure(&eb_es, 0, sizeof(eb_es));

	if (!ret)
		printf("ES Jitter RNG instances - pass: the collectors serve\n");

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

	rc = es_ji_read();
	if (rc == 77 && !ret)
		ret = 77;
	else if (rc != 77)
		ret += rc;

	esdm_fini();

	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return es_ji_test();
}
