/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched.h"

static int es_krng_getstate(void)
{
	char buf[500];

	if (!esdm_es[esdm_ext_es_krng]->state) {
		printf("ES Kernel RNG - fail: state callback missing\n");
		return 1;
	}

	memset(buf, 0, sizeof(buf));

	esdm_es[esdm_ext_es_krng]->state(buf, sizeof(buf));
	if (!strstr(buf, "Entropy Rate per 256 data bits") ||
	    !strstr(buf, "Available entropy")) {
		printf("ES Kernel RNG - fail: state information contains unexpected content: %s\n",
		       buf);
		return 1;
	}

	printf("ES KRNG - pass: get state test passed:\n%s\n", buf);

	return 0;
}

static int es_krng_getdata(uint32_t expected_ent_level)
{
	struct entropy_es eb_es;
	uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES];

	if (!esdm_es[esdm_ext_es_krng]->get_ent) {
		printf("ES Kernel RNG - fail: get_ent callback missing\n");
		return 1;
	}

	esdm_config_es_krng_entropy_rate_set(expected_ent_level);

	memset(&eb_es, 0, sizeof(eb_es));
	memset(&zero, 0, sizeof(zero));

	esdm_es[esdm_ext_es_krng]->get_ent(&eb_es,
					   ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	if (eb_es.e_bits !=
	    esdm_fast_noise_entropylevel(esdm_config_es_krng_entropy_rate(),
					 ESDM_DRNG_INIT_SEED_SIZE_BITS)) {
		printf("ES Kernel RNG - fail: get_ent failed to deliver requested data (expected %u, received %u bits)\n",
		       esdm_fast_noise_entropylevel(
			       esdm_config_es_krng_entropy_rate(),
			       ESDM_DRNG_INIT_SEED_SIZE_BITS),
		       eb_es.e_bits);
		return 1;
	}

	if (!memcmp(eb_es.e, zero, ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
		printf("ES Kernel RNG - fail: get_ent failed to deliver data\n");
		return 1;
	}

	printf("ES KRNG - pass: get data test for entropy level %u passed\n",
	       expected_ent_level);

	return 0;
}

static int es_krng_poolsize(uint32_t expected_ent_level)
{
	uint32_t ret, ret2;

	if (!esdm_es[esdm_ext_es_krng]->max_entropy) {
		printf("ES Kernel RNG - fail: max_entropy callback missing\n");
		return 1;
	}

	if (!esdm_es[esdm_ext_es_krng]->curr_entropy) {
		printf("ES Kernel RNG - fail: curr_entropy callback missing\n");
		return 1;
	}

	if (esdm_config_fips_enabled() || esdm_sched_enabled()) {
		if (esdm_config_es_krng_entropy_rate()) {
			printf("KRNG ES - fail entropy rate in FIPS mode > 0\n");
			return 1;
		}
	}

	esdm_config_es_krng_entropy_rate_set(expected_ent_level);

	ret = esdm_es[esdm_ext_es_krng]->max_entropy();
	if (ret !=
	    esdm_fast_noise_entropylevel(esdm_config_es_krng_entropy_rate(),
					 esdm_security_strength())) {
		printf("ES Kernel RNG - fail: max_entropy failed: %d\n", ret);
		return 1;
	}

	if (esdm_config_es_krng_entropy_rate() !=
	    esdm_fast_noise_entropylevel(esdm_config_es_krng_entropy_rate(),
					 esdm_security_strength())) {
		printf("ES Kernel RNG - fail: esdm_fast_noise_entropylevel returned unexpected value: %u\n",
		       esdm_fast_noise_entropylevel(
			       esdm_config_es_krng_entropy_rate(),
			       esdm_security_strength()));
		return 1;
	}

	ret2 = esdm_es[esdm_ext_es_krng]->curr_entropy(
		esdm_security_strength());
	if (ret != ret2) {
		printf("ES Kernel RNG - fail: max_entropy inconsisten with curr_entropy: max_entropy %u, curr_entropy %u\n",
		       ret, ret2);
		return 1;
	}

	printf("ES KRNG - pass: poolsize test for entropy level %u passed\n",
	       expected_ent_level);

	return 0;
}

static int es_krng_name(void)
{
	const char *name = esdm_es[esdm_ext_es_krng]->name;

	if (!name) {
		printf("ES Kernel RNG - fail: name not set!");
		return 1;
	}

	printf("ES KRNG - pass: name test passed: %s\n", name);

	return 0;
}

static int es_krng_init(void)
{
	int ret;

	if (!esdm_es[esdm_ext_es_krng]->init) {
		printf("ES Kernel RNG - fail: init callback missing\n");
		return 1;
	}

	ret = esdm_es[esdm_ext_es_krng]->init();
	if (ret) {
		printf("ES Kernel RNG - fail: init failed: %d\n", ret);
		return 1;
	}

	printf("ES KRNG - pass: init test passed\n");

	return 0;
}

static int es_krng_fini(void)
{
	if (!esdm_es[esdm_ext_es_krng]->fini) {
		printf("ES Kernel RNG - fail: fini callback missing\n");
		return 1;
	}
	esdm_es[esdm_ext_es_krng]->fini();

	printf("ES KRNG - pass: fini test passed\n");

	return 0;
}

int main(int argc, char *argv[])
{
	unsigned int i;
	int ret;

	(void)argc;
	(void)argv;

	logger_set_verbosity(LOGGER_DEBUG);

	ret = es_krng_init();
	if (ret)
		return ret;

	ret += es_krng_name();

	for (i = 1; i <= ESDM_DRNG_SECURITY_STRENGTH_BITS; i++) {
		ret += es_krng_poolsize(i);
		ret += es_krng_getdata(i);
	}

	ret += es_krng_getstate();
	ret += es_krng_fini();

	return ret;
}
