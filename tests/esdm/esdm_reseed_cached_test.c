/*
 * Test that a reseed leaves out a source whose cache is empty
 *
 * A reseed takes the block a source with a cache has ready, see struct
 * esdm_es_cb.get_cached. With its cache empty, the source is asked to collect
 * only if the other sources fall short of the seed: under load, a slow source
 * would otherwise hold up every reseed once its cache is drained.
 *
 * The Jitter RNG is that source here, its cache left empty - without the ES
 * monitor nothing fills it - and the aux pool is the other credited source:
 *
 *   - with a seed's worth in the aux pool, the reseed collects from it alone,
 *   - with the aux pool empty, the Jitter RNG is asked after all.
 *
 * Which sources delivered is told by the entropy the reseed collected, as the
 * test mode records it.
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
#include "esdm_drng_mgr.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "es_rates.h"
#include "test_pertubation.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT) &&                         \
	(ESDM_JENT_ENTROPY_BLOCKS != 0)

/* Seeding passes the DRNGs get to be seeded initially */
#define ESDM_RC_SEED_PASSES 10

/*
 * A forced reseed of the initial DRNG in a request, and the entropy it
 * collected - one pass, recorded by esdm_entropy_rate_eb().
 */
static int esdm_rc_reseed(uint32_t *collected)
{
	uint8_t buf[32];

	atomic_store(&seed_entropy_ptr, -1);
	esdm_drng_force_reseed();
	if (esdm_get_random_bytes(buf, sizeof(buf)) != sizeof(buf)) {
		printf("the request was not served\n");
		return 1;
	}
	if (atomic_load(&seed_entropy_ptr) != 0) {
		printf("%d seeding passes recorded instead of one\n",
		       atomic_load(&seed_entropy_ptr) + 1);
		return 1;
	}

	*collected = seed_entropy[0];
	return 0;
}

static int esdm_rc_test(void)
{
	uint8_t data[ESDM_MAX_DIGESTSIZE];
	uint32_t requested, collected, aux;
	unsigned int i;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* Every request lands on the initial DRNG */
	esdm_config_max_nodes_set(1);

	/* The Jitter RNG and the aux pool are the credited sources */
	esdm_test_es_rates_zero();
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	/* No esdm_init_monitor(): nothing fills the cache of the Jitter RNG */
	ret = esdm_init();
	if (ret)
		return ret;

	memset(data, 0x5a, sizeof(data));
	for (i = 0; i < ESDM_RC_SEED_PASSES && !esdm_pool_all_nodes_seeded_get();
	     i++) {
		esdm_pool_insert_aux(data, sizeof(data), sizeof(data) << 3);
		esdm_force_fully_seeded_all_drbgs();
	}
	if (!esdm_pool_all_nodes_seeded_get() || !esdm_state_operational()) {
		printf("DRNGs cannot be seeded, skipping test\n");
		ret = 77;
		goto out;
	}

	requested = esdm_get_seed_entropy_osr(false, false);

	/* A seed's worth in the aux pool: the empty cache is left out */
	esdm_pool_set_entropy(0);
	esdm_pool_insert_aux(data, sizeof(data), requested);
	aux = esdm_avail_entropy_aux();
	if (aux < requested) {
		printf("the aux pool holds %u bits, not %u\n", aux, requested);
		ret = 77;
		goto out;
	}
	if (esdm_rc_reseed(&collected))
		goto err;
	printf("with %u bits in the aux pool, the reseed collected %u of %u bits\n",
	       aux, collected, requested);
	if (collected < requested || collected > aux) {
		printf("FAIL: the Jitter RNG with an empty cache was asked although the aux pool delivered the seed\n");
		goto err;
	}

	/* Nothing in the aux pool: the Jitter RNG has to collect after all */
	esdm_pool_set_entropy(0);
	if (esdm_rc_reseed(&collected))
		goto err;
	printf("with the aux pool empty, the reseed collected %u of %u bits\n",
	       collected, requested);
	if (collected < requested) {
		printf("FAIL: the Jitter RNG was left out although the other sources fell short\n");
		goto err;
	}

	printf("the reseed left out the empty cache only while the aux pool covered the seed\n");
	ret = 0;

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}

#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT) &&                         \
	(ESDM_JENT_ENTROPY_BLOCKS != 0)
	return esdm_rc_test();
#else
	printf("no Jitter RNG with a cache in this build\n");
	return 77;
#endif
}
