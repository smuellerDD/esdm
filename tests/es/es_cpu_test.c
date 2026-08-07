/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <stdbool.h>
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
	esdm_es[esdm_ext_es_cpu]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS,
					  true);
	if (eb_es.e_bits !=
	    esdm_fast_noise_entropylevel(expected_ent_level,
					 ESDM_DRNG_INIT_SEED_SIZE_BITS)) {
		printf("ES CPU - fail: get_ent failed to deliver requested data (expected %u, received %u bits)\n",
		       esdm_fast_noise_entropylevel(
			       expected_ent_level,
			       ESDM_DRNG_INIT_SEED_SIZE_BITS),
		       eb_es.e_bits);
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
	if (ret != esdm_fast_noise_entropylevel(expected_ent_level,
						esdm_security_strength())) {
		printf("ES CPU - fail: max_entropy failed: %d\n", ret);
		return 1;
	}
	printf("ES CPU - pass: max_entropy: %d\n", ret);

	if (expected_ent_level !=
	    esdm_fast_noise_entropylevel(expected_ent_level,
					 esdm_security_strength())) {
		printf("ES CPU - fail: esdm_fast_noise_entropylevel returned unexpected value: %u\n",
		       esdm_fast_noise_entropylevel(expected_ent_level,
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

/*
 * The state string is written with snprintf into whatever the caller offers,
 * and the JSON status document hands it a share of a fixed buffer. Check that a
 * buffer too small for the full text is truncated rather than run over, and
 * that what is written stays a NUL terminated string.
 */
static int es_cpu_getstate_truncated(void)
{
	char buf[sizeof(" Hash for compressing data: ") + 8];
	char canary[16];

	memset(buf, 0x5a, sizeof(buf));
	memset(canary, 0x5a, sizeof(canary));

	esdm_es[esdm_ext_es_cpu]->state(buf, sizeof(buf) - sizeof(canary));

	if (memcmp(buf + sizeof(buf) - sizeof(canary), canary,
		   sizeof(canary))) {
		printf("ES CPU - fail: state wrote past the end of the buffer\n");
		return 1;
	}

	if (buf[sizeof(buf) - sizeof(canary) - 1] != '\0') {
		printf("ES CPU - fail: state did not terminate the truncated string\n");
		return 1;
	}

	printf("ES CPU - pass: state truncates into a short buffer: %s\n", buf);

	return 0;
}

/*
 * Two pulls in a row must not deliver the same bytes. The entropy source hands
 * its buffer to the ES manager without looking at it, so a CPU instruction that
 * stopped producing new values - or a gather loop that stopped writing - would
 * otherwise be credited at the full rate for a repeat of the previous seed.
 */
static int es_cpu_getdata_differs(void)
{
	struct entropy_es first, second;

	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));

	esdm_es[esdm_ext_es_cpu]->get_ent(&first, ESDM_DRNG_INIT_SEED_SIZE_BITS,
					  true);
	esdm_es[esdm_ext_es_cpu]->get_ent(&second,
					  ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	if (!memcmp(first.e, second.e, ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
		printf("ES CPU - fail: two successive pulls delivered identical data\n");
		return 1;
	}
	printf("ES CPU - pass: successive pulls deliver different data\n");

	return 0;
}

/*
 * A partial request: the gather loop runs over full machine words, so the
 * smaller of the two sizes the ES manager asks for must come back with exactly
 * the entropy that was requested and no bytes written beyond it.
 */
static int es_cpu_getdata_partial(void)
{
	struct entropy_es eb_es;
	uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES];
	const uint32_t requested = ESDM_DRNG_SECURITY_STRENGTH_BITS;

	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	memset(&eb_es, 0, sizeof(eb_es));
	memset(zero, 0, sizeof(zero));

	esdm_es[esdm_ext_es_cpu]->get_ent(&eb_es, requested, true);

	if (eb_es.e_bits !=
	    esdm_fast_noise_entropylevel(ESDM_DRNG_SECURITY_STRENGTH_BITS,
					 requested)) {
		printf("ES CPU - fail: partial request credited %u bits\n",
		       eb_es.e_bits);
		return 1;
	}

	if (!memcmp(eb_es.e, zero, requested >> 3)) {
		printf("ES CPU - fail: partial request delivered no data\n");
		return 1;
	}

	if (ESDM_DRNG_INIT_SEED_SIZE_BYTES > (requested >> 3) &&
	    memcmp(eb_es.e + (requested >> 3), zero,
		   ESDM_DRNG_INIT_SEED_SIZE_BYTES - (requested >> 3))) {
		printf("ES CPU - fail: partial request wrote beyond the requested %u bits\n",
		       requested);
		return 1;
	}
	printf("ES CPU - pass: partial request of %u bits honoured\n",
	       requested);

	return 0;
}

/*
 * The source is compiled in for this architecture - the test would have been
 * skipped otherwise - so it must say so. The ES manager skips every callback of
 * a source that reports itself inactive.
 */
static int es_cpu_active(void)
{
	if (!esdm_es[esdm_ext_es_cpu]->active) {
		printf("ES CPU - fail: active callback missing\n");
		return 1;
	}

	if (!esdm_es[esdm_ext_es_cpu]->active()) {
		printf("ES CPU - fail: source delivers data but reports itself inactive\n");
		return 1;
	}
	printf("ES CPU - pass: active\n");

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

/*
 * The CPU entropy source is compiled in for this architecture, but the CPU
 * running the test may not implement the instruction behind it - an arm64 part
 * without FEAT_RNG, or an x86 hypervisor withholding RDSEED. esdm_es_cpu.c then
 * credits 0 bits and wipes the buffer, which is correct behaviour of an absent
 * source rather than a failure, so the test is skipped. ->active() cannot
 * answer this: it only reports whether the source was compiled in.
 */
static bool es_cpu_data_available(void)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));

	/*
	 * Probe with a non-zero entropy rate: the delivered bits are credited
	 * according to the configured rate, so with a rate of 0 - which is a
	 * legitimate configuration - even a working source would report 0 bits
	 * and look absent. The checks below set the rate per iteration anyway.
	 */
	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	esdm_es[esdm_ext_es_cpu]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS,
					  true);

	return eb_es.e_bits > 0;
}

int main(int argc, char *argv[])
{
	uint32_t i;
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ret = es_cpu_init();
	if (ret)
		return ret;

	if (!es_cpu_data_available()) {
		printf("ES CPU: CPU delivers no random numbers on this platform, skipping test\n");
		return 77;
	}

	ret += es_cpu_name();
	ret += es_cpu_active();

	/*
	 * From 0 on: a rate of 0 is what the default build configures for this
	 * source, and it must still deliver data - the rate says what the output
	 * is credited with, not whether there is any.
	 */
	for (i = 0; i <= ESDM_DRNG_SECURITY_STRENGTH_BITS; i++) {
		ret += es_cpu_poolsize(i);
		ret += es_cpu_getdata(i);
	}

	ret += es_cpu_getdata_differs();
	ret += es_cpu_getdata_partial();
	ret += es_cpu_getstate();
	ret += es_cpu_getstate_truncated();

	return ret;
}
