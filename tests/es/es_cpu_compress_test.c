/*
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
 * Test of the compressing data path of the CPU entropy source.
 *
 * When one word of CPU output is not one word of entropy the source pulls a
 * multiple of the requested amount and conditions it with a hash. Which of the
 * two paths esdm_cpu_get() takes is decided once at init from
 * cpu_es_multiplier() and the es_cpu_multiplier build option, and on the
 * machines this suite runs on both come out as 1: x86 has RDSEED, arm64 has
 * RNDRRS, and the option defaults to 1. The whole compression path - the
 * oversampling arithmetic, the chunking, the truncation of the digest and the
 * error handling around it - is then never executed, which is what
 * esdm_get_cpu_data_compress() showing up unreached in the coverage report
 * says.
 *
 * There is no run time control over the multiplier, so the entropy source is
 * compiled into the test with the build option raised. That also puts its
 * internal functions in reach, which is what lets the digest sized request
 * below be made at all: it exceeds the buffer of struct entropy_es and cannot
 * be asked for through the ES callback.
 *
 * The value is deliberately small. What is under test is the code path, and
 * every unit of it costs another full pull from a rate limited instruction.
 */

#include "config.h"

#undef ESDM_CPU_FULL_ENT_MULTIPLIER
#define ESDM_CPU_FULL_ENT_MULTIPLIER 4

/* The unit under test */
#include "esdm_es_cpu.c"

#include <stdlib.h>

#include "common_test.h"

#define TEST_MULTIPLIER 4

/*
 * Backing store for the requests made directly below, which are larger than
 * struct entropy_es. Declared as unsigned long, since the gather loop of
 * esdm_get_cpu_data() writes it a machine word at a time.
 */
static unsigned long big_buf[(ESDM_MAX_DIGESTSIZE + sizeof(unsigned long) - 1) /
			     sizeof(unsigned long)];

static bool buf_is_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return false;
	}

	return true;
}

/*
 * The multiplier is what selects the path under test, so establish it before
 * anything is read from it.
 */
static void check_multiplier(void)
{
	uint32_t multiplier = esdm_cpu_multiplier();

	CHECK(multiplier >= TEST_MULTIPLIER,
	      "multiplier %u below the configured %u - init did not apply the build option",
	      multiplier, TEST_MULTIPLIER);
	CHECK(multiplier > 1,
	      "multiplier is %u, so esdm_cpu_get() takes the uncompressed path and this test covers nothing",
	      multiplier);
}

/*
 * The ES callback with the multiplier in place: same contract as in
 * es_cpu_test.c, but served by esdm_get_cpu_data_compress().
 */
static void check_get_ent(uint32_t rate)
{
	struct entropy_es first, second;
	uint32_t expected;

	esdm_config_es_cpu_entropy_rate_set(rate);
	expected = esdm_fast_noise_entropylevel(rate,
						ESDM_DRNG_INIT_SEED_SIZE_BITS);

	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));

	esdm_es_cpu.get_ent(&first, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	esdm_es_cpu.get_ent(&second, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	CHECK_EQ(first.e_bits, expected);
	CHECK_EQ(second.e_bits, expected);

	/*
	 * Data is delivered irrespective of how it is credited - a rate of 0 is
	 * a statement about the entropy of the source, not about its output.
	 */
	CHECK(!buf_is_zero(first.e, ESDM_DRNG_INIT_SEED_SIZE_BYTES),
	      "rate %u: compressed output is all zero", rate);
	CHECK(memcmp(first.e, second.e, ESDM_DRNG_INIT_SEED_SIZE_BYTES),
	      "rate %u: two pulls returned the same digest", rate);
}

/*
 * The two ways the digest leaves the function. A request below the digest size
 * is served from a truncated copy, one that meets it is written in place - the
 * branch a request through struct entropy_es can never reach, its buffer being
 * smaller than any digest ESDM uses.
 */
static void check_digest_sized_request(void)
{
	uint8_t *buf = (uint8_t *)big_buf;
	uint32_t ent_bits;

	memset(big_buf, 0, sizeof(big_buf));

	ent_bits = esdm_get_cpu_data_compress(buf, ESDM_MAX_DIGESTSIZE << 3,
					      esdm_cpu_multiplier());

	CHECK_EQ(ent_bits, ESDM_MAX_DIGESTSIZE << 3);
	CHECK(!buf_is_zero(buf, ESDM_MAX_DIGESTSIZE),
	      "digest sized request delivered no data");
}

/*
 * With the oversampling on the pull is larger, which is the only thing that
 * makes the partial trailing block happen at all. Both settings are exercised,
 * since the arithmetic differs and only one of them is what a given build runs
 * with.
 *
 * The mechanism rather than the compliance claim is what is checked for:
 * esdm_sp80090c_compliant() answers no in a build to one of the DRG classes
 * even where the oversampling is applied. It cannot be switched on at all in a
 * build that left it out at compile time - the FIPS, SP800-90C and DRG.3 builds
 * are the ones that cover this half.
 */
static void check_oversampling(void)
{
#ifdef ESDM_OVERSAMPLE_ENTROPY_SOURCES
	esdm_config_force_fips_set(esdm_config_force_sp80090c_enabled);
	CHECK(esdm_es_oversampling(),
	      "oversampling did not take effect, its path not covered");

	check_get_ent(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	check_digest_sized_request();

	esdm_config_force_fips_set(esdm_config_force_fips_disabled);
#else
	printf("ES CPU compress: built without entropy source oversampling, SP800-90C path not tested\n");
#endif
}

/* The multiplier is part of what the source reports about itself. */
static void check_state(void)
{
	char buf[512], expected[64];

	memset(buf, 0, sizeof(buf));
	esdm_es_cpu.state(buf, sizeof(buf));

	snprintf(expected, sizeof(expected), " Data multiplier: %u\n",
		 esdm_cpu_multiplier());
	CHECK(strstr(buf, expected) != NULL,
	      "state does not report the multiplier as \"%s\":\n%s", expected,
	      buf);

	/* With a multiplier there is a conditioning hash, and it has a name. */
	CHECK(strstr(buf, "Hash for compressing data: N/A") == NULL,
	      "state reports no conditioning hash despite a multiplier of %u:\n%s",
	      esdm_cpu_multiplier(), buf);
}

int main(int argc, char *argv[])
{
	struct entropy_es probe;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	CHECK_EQ(esdm_es_cpu.init(), 0);
	check_multiplier();

	/*
	 * The instruction may be absent even though the source is compiled in -
	 * see the same probe in es_cpu_test.c for why ->active() cannot answer
	 * this.
	 */
	memset(&probe, 0, sizeof(probe));
	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_es_cpu.get_ent(&probe, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	if (!probe.e_bits) {
		printf("ES CPU compress: CPU delivers no random numbers on this platform, skipping test\n");
		return 77;
	}

	check_get_ent(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	check_get_ent(1);
	check_get_ent(0);
	check_digest_sized_request();
	check_oversampling();
	check_state();

	return common_test_result("ES CPU compressing path");
}
