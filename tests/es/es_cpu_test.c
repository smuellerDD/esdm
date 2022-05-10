/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"

static int es_cpu_getstate(void)
{
	char buf[500];

	if (!esdm_es[esdm_ext_es_cpu]->state) {
		printf("ES CPU - fail: state callback missing\n");
		return 1;
	}

	memset(buf, 0, sizeof(buf));

	esdm_es[esdm_ext_es_cpu]->state(buf, sizeof(buf));
	if (!strstr(buf, "Hash for compressing data") ||
	    !strstr(buf, "Available entropy") ||
	    !strstr(buf, "Data multiplier")) {
		printf("ES CPU: state information contains unexpected content: %s\n",
		       buf);
		return 1;
	}
	printf("ES CPU - pass: state information found:\n%s\n", buf);

	return 0;
}

static int es_cpu_getdata(uint32_t expected_ent_level)
{
	struct entropy_es eb_es;
	uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES];

	if (!esdm_es[esdm_ext_es_cpu]->get_ent) {
		printf("ES CPU - fail: get_ent callback missing\n");
		return 1;
	}

	esdm_config_es_cpu_entropy_rate_set(expected_ent_level);

	memset(&eb_es, 0, sizeof(eb_es));
	memset(&zero, 0, sizeof(zero));
	esdm_es[esdm_ext_es_cpu]->get_ent(&eb_es,
					  ESDM_DRNG_INIT_SEED_SIZE_BITS,
					  true);
	if (eb_es.e_bits != esdm_fast_noise_entropylevel(
				expected_ent_level,
				ESDM_DRNG_INIT_SEED_SIZE_BITS)) {
		printf("ES CPU - fail: get_ent failed to deliver requested data (expected %u, received %u bits)\n",
		        esdm_fast_noise_entropylevel(
				expected_ent_level,
				ESDM_DRNG_INIT_SEED_SIZE_BITS), eb_es.e_bits);
		return 1;
	}
	printf("ES CPU - pass: get_ent delivered requested entropy\n");

	if (!memcmp(eb_es.e, zero, ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
		printf("ES CPU - fail: get_ent failed to deliver data\n");
		return 1;
	}
	printf("ES CPU - pass: get_ent delivered data\n");

	return 0;
}

static int es_cpu_poolsize(uint32_t expected_ent_level)
{
	uint32_t ret, ret2;

	if (!esdm_es[esdm_ext_es_cpu]->max_entropy) {
		printf("ES CPU - fail: max_entropy callback missing\n");
		return 1;
	}

	if (!esdm_es[esdm_ext_es_cpu]->curr_entropy) {
		printf("ES CPU - fail: curr_entropy callback missing\n");
		return 1;
	}

	esdm_config_es_cpu_entropy_rate_set(expected_ent_level);

	ret = esdm_es[esdm_ext_es_cpu]->max_entropy();
	if (ret != esdm_fast_noise_entropylevel(
		expected_ent_level,
		esdm_security_strength())) {
		printf("ES CPU - fail: max_entropy failed: %d\n", ret);
		return 1;
	}
	printf("ES CPU - pass: max_entropy: %d\n", ret);

	if (expected_ent_level != esdm_fast_noise_entropylevel(
		expected_ent_level,
		esdm_security_strength())) {
		printf("ES CPU - fail: esdm_fast_noise_entropylevel returned unexpected value: %u\n",
		       esdm_fast_noise_entropylevel(
				expected_ent_level,
				esdm_security_strength()));
		return 1;
	}
	printf("ES CPU - pass: max_entropy shows expected value: %d\n", ret);

	ret2 = esdm_es[esdm_ext_es_cpu]->curr_entropy(esdm_security_strength());
	if (ret != ret2) {
		printf("ES CPU - fail: max_entropy inconsistent with curr_entropy: max_entropy %u, curr_entropy %u\n",
		       ret, ret2);
		return 1;
	}
	printf("ES CPU - pass: curr_entropy: %d\n", ret2);

	return 0;
}

static int es_cpu_name(void)
{
	const char *name = esdm_es[esdm_ext_es_cpu]->name;

	if (!name) {
		printf("ES CPU - fail: name not set!");
		return 1;
	}

	printf("ES CPU - pass: name: %s\n", name);

	return 0;
}

static int es_cpu_init(void)
{
	int ret;

	if (!esdm_es[esdm_ext_es_cpu]->init) {
		printf("ES CPU - fail: init callback missing\n");
		return 1;
	}

	ret = esdm_es[esdm_ext_es_cpu]->init();
	if (ret) {
		printf("ES CPU - fail: init failed: %d\n", ret);
		return 1;
	}

	printf("ES CPU - pass: init\n");

	return 0;
}

int main(int argc, char *argv[])
{
	uint32_t i;
	int ret;

	(void)argc;
	(void)argv;

	logger_set_verbosity(LOGGER_DEBUG);

	ret = es_cpu_init();
	if (ret)
		return ret;

	ret += es_cpu_name();

	for (i = 1; i <= ESDM_DRNG_SECURITY_STRENGTH_BITS; i++) {
		ret += es_cpu_poolsize(i);
		ret += es_cpu_getdata(i);
	}

	ret += es_cpu_getstate();

	return ret;
}
