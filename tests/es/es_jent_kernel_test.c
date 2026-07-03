/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * Structural / graceful-absence test for the in-kernel jitterentropy source.
 *
 * Unlike the CPU and Jitter RNG tests, this source may simply not be present
 * on the test machine (jitterentropy_rng kernel module not loaded). The test
 * therefore does
 * NOT require entropy to be delivered; it verifies that the ES callback vector
 * is well-formed and that every callback is safe to invoke and internally
 * consistent whether the device is present or absent. That still catches NULL
 * derefs, crashes, malformed state strings and max/curr_entropy divergence.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"

#define ES_IDX esdm_ext_es_jent_kernel
#define ES_NAME "jent_kernel"

static int es_jent_kernel_name(void)
{
	const char *name = esdm_es[ES_IDX]->name;

	if (!name) {
		printf("ES %s - fail: name not set!\n", ES_NAME);
		return 1;
	}
	printf("ES %s - pass: name: %s\n", ES_NAME, name);
	return 0;
}

static int es_jent_kernel_state(void)
{
	char buf[512];

	/* state is optional; nothing to check if absent */
	if (!esdm_es[ES_IDX]->state)
		return 0;

	memset(buf, 0, sizeof(buf));
	esdm_es[ES_IDX]->state(buf, sizeof(buf));
	if (!strstr(buf, "Available entropy")) {
		printf("ES %s - fail: state string malformed: %s\n", ES_NAME,
		       buf);
		return 1;
	}
	printf("ES %s - pass: state:\n%s\n", ES_NAME, buf);
	return 0;
}

static int es_jent_kernel_poolsize(void)
{
	uint32_t maxe, curr;

	if (!esdm_es[ES_IDX]->max_entropy || !esdm_es[ES_IDX]->curr_entropy)
		return 0;

	/*
	 * Both may legitimately be 0 when the device is absent. The invariant
	 * that must hold either way is that max_entropy() agrees with
	 * curr_entropy() evaluated at the security strength.
	 */
	maxe = esdm_es[ES_IDX]->max_entropy();
	curr = esdm_es[ES_IDX]->curr_entropy(esdm_security_strength());
	if (maxe != curr) {
		printf("ES %s - fail: max_entropy (%u) inconsistent with curr_entropy (%u)\n",
		       ES_NAME, maxe, curr);
		return 1;
	}
	printf("ES %s - pass: entropy accounting consistent (%u bits)\n",
	       ES_NAME, maxe);
	return 0;
}

static int es_jent_kernel_getdata(void)
{
	struct entropy_es eb_es;

	if (!esdm_es[ES_IDX]->get_ent)
		return 0;

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	/*
	 * With no device present, get_ent must gracefully return 0 credited
	 * bits rather than crash or over-credit. When a device IS present it
	 * may return up to the requested amount.
	 */
	if (eb_es.e_bits > ESDM_DRNG_INIT_SEED_SIZE_BITS) {
		printf("ES %s - fail: get_ent over-credited entropy: %u bits\n",
		       ES_NAME, eb_es.e_bits);
		return 1;
	}
	printf("ES %s - pass: get_ent returned %u bits (device %s)\n", ES_NAME,
	       eb_es.e_bits, eb_es.e_bits ? "present" : "absent");
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (esdm_es[ES_IDX]->init)
		/* init may fail when the device is absent - tolerate it */
		(void)esdm_es[ES_IDX]->init();

	ret += es_jent_kernel_name();
	ret += es_jent_kernel_state();
	ret += es_jent_kernel_poolsize();
	ret += es_jent_kernel_getdata();

	if (esdm_es[ES_IDX]->fini)
		esdm_es[ES_IDX]->fini();

	return ret;
}
