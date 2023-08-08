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

static int es_jent_getstate(void)
{
	char buf[500];

	if (!esdm_es[esdm_ext_es_jitter]->state) {
		printf("ES Jitter RNG - fail: state callback missing\n");
		return 1;
	}

	memset(buf, 0, sizeof(buf));

	esdm_es[esdm_ext_es_jitter]->state(buf, sizeof(buf));
	if (!strstr(buf, "Library version") ||
	    !strstr(buf, "Available entropy")) {
		printf("ES Jitter RNG - fail: state information contains unexpected content: %s\n",
		       buf);
		return 1;
	}

	printf("ES Jitter RNG - pass: state information found:\n%s\n", buf);

	return 0;
}

static int es_jent_getdata(uint32_t expected_ent_level)
{
	struct entropy_es eb_es;
	uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES];

	if (!esdm_es[esdm_ext_es_jitter]->get_ent) {
		printf("ES Jitter RNG - fail: get_ent callback missing\n");
		return 1;
	}

	esdm_config_es_jent_entropy_rate_set(expected_ent_level);

	memset(&eb_es, 0, sizeof(eb_es));
	memset(&zero, 0, sizeof(zero));
	esdm_es[esdm_ext_es_jitter]->get_ent(
		&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	if (eb_es.e_bits !=
	    esdm_fast_noise_entropylevel(esdm_config_es_jent_entropy_rate(),
					 ESDM_DRNG_INIT_SEED_SIZE_BITS)) {
		printf("ES Jitter RNG - fail: get_ent failed to deliver requested data (expected %u, received %u bits)\n",
		       esdm_fast_noise_entropylevel(
			       esdm_config_es_jent_entropy_rate(),
			       ESDM_DRNG_INIT_SEED_SIZE_BITS),
		       eb_es.e_bits);
		return 1;
	}
	printf("ES Jitter RNG - pass: get_ent delivered requested entropy\n");

	if (!memcmp(eb_es.e, zero, ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
		printf("ES Jitter RNG - fail: get_ent failed to deliver data\n");
		return 1;
	}

	printf("ES Jitter RNG - pass: get data test for entropy level %u passed\n",
	       expected_ent_level);

	return 0;
}

static int es_jent_poolsize(uint32_t expected_ent_level)
{
	uint32_t ret, ret2;

	if (!esdm_es[esdm_ext_es_jitter]->max_entropy) {
		printf("ES Jitter RNG - fail: max_entropy callback missing\n");
		return 1;
	}

	if (!esdm_es[esdm_ext_es_jitter]->curr_entropy) {
		printf("ES Jitter RNG - fail: curr_entropy callback missing\n");
		return 1;
	}

	esdm_config_es_jent_entropy_rate_set(expected_ent_level);

	ret = esdm_es[esdm_ext_es_jitter]->max_entropy();
	if (ret !=
	    esdm_fast_noise_entropylevel(esdm_config_es_jent_entropy_rate(),
					 esdm_security_strength())) {
		printf("ES Jitter RNG - fail: max_entropy failed: %d\n", ret);
		return 1;
	}
	printf("ES Jitter RNG - pass: max_entropy: %d\n", ret);

	if (esdm_config_es_jent_entropy_rate() !=
	    esdm_fast_noise_entropylevel(esdm_config_es_jent_entropy_rate(),
					 esdm_security_strength())) {
		printf("ES Jitter RNG - fail: esdm_fast_noise_entropylevel returned unexpected value: %u\n",
		       esdm_fast_noise_entropylevel(
			       esdm_config_es_jent_entropy_rate(),
			       esdm_security_strength()));
		return 1;
	}
	printf("ES Jitter RNG - pass: max_entropy shows expected value: %d\n",
	       ret);

	ret2 = esdm_es[esdm_ext_es_jitter]->curr_entropy(
		esdm_security_strength());
	if (ret != ret2) {
		printf("ES Jitter RNG - fail: max_entropy inconsistent with curr_entropy: max_entropy %u, curr_entropy %u\n",
		       ret, ret2);
		return 1;
	}

	printf("ES Jitter RNG - pass: poolsize for entropy level %u test passed\n",
	       expected_ent_level);

	return 0;
}

static int es_jent_poolsize_pre_init(void)
{
	uint32_t ret;

	if (!esdm_es[esdm_ext_es_jitter]->max_entropy) {
		printf("ES Jitter RNG - fail: max_entropy callback missing\n");
		return 1;
	}

	ret = esdm_es[esdm_ext_es_jitter]->max_entropy();
	if (ret != 0) {
		printf("ES Jitter RNG - fail: max_entropy before initalization is not zero: %d\n",
		       ret);
		return 1;
	}

	printf("ES Jitter RNG - pass: pre init test passed\n");

	return 0;
}

static int es_jent_name(void)
{
	const char *name = esdm_es[esdm_ext_es_jitter]->name;

	if (!name) {
		printf("ES Jitter RNG - fail: name not set!");
		return 1;
	}

	printf("ES Jitter RNG - pass: name test passed: %s\n", name);

	return 0;
}

static int es_jent_init(void)
{
	int ret;

	if (!esdm_es[esdm_ext_es_jitter]->init) {
		printf("ES Jitter RNG - fail: init callback missing\n");
		return 1;
	}

	ret = esdm_es[esdm_ext_es_jitter]->init();
	if (ret) {
		printf("ES Jitter RNG - fail: init failed: %d\n", ret);
		return 1;
	}

	printf("ES Jitter RNG - pass: init test passed\n");

	return 0;
}

static int es_jent_fini(void)
{
	if (!esdm_es[esdm_ext_es_jitter]->fini) {
		printf("ES Jitter RNG - fail: fini callback missing\n");
		return 1;
	}
	esdm_es[esdm_ext_es_jitter]->fini();

	printf("ES Jitter RNG - pass: fini test passed\n");

	return 0;
}

int main(int argc, char *argv[])
{
	uint32_t i;
	int ret;

	(void)argc;
	(void)argv;

	logger_set_verbosity(LOGGER_DEBUG);

	/* Poolsize before initialization */
	ret = es_jent_poolsize_pre_init();
	ret += es_jent_init();
	if (ret)
		return ret;

	ret += es_jent_name();

	for (i = 1; i <= ESDM_DRNG_SECURITY_STRENGTH_BITS; i++) {
		ret += es_jent_poolsize(i);
		ret += es_jent_getdata(i);
	}

	ret += es_jent_getstate();
	ret += es_jent_fini();

	return ret;
}
