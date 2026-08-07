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
 * Test of the two x86 CPU entropy source primitives, RDSEED and RDRAND.
 *
 * es_cpu_test.c drives the entropy source through its ES callbacks, and that
 * reaches only one of the two instructions: cpu_es_get() deliberately performs
 * no fallback, so on every CPU that has RDSEED - which is every one since
 * Broadwell and Zen - RDRAND is never executed. Its feature detection, its
 * retry loop and the intrinsic behind it are dead code in that run, and a
 * regression in the half that only old or virtualized machines use would be
 * found by nobody.
 *
 * The header is therefore compiled into the test and both instructions are
 * called directly, since cpu_es_x86_rdrand() has no caller that can be made to
 * select it at runtime.
 *
 * What may be asserted about a hardware RNG is limited - by construction its
 * output is a different value every time. The checks below are of the kind
 * that catches an instruction which is not executed at all, a buffer that is
 * never written, a stuck bit or a wrong-width intrinsic; they are not, and
 * cannot be, an assessment of the generator, which is the CPU vendor's to make.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_test.h"
#include "es_cpu/cpu_random_x86.h"

/*
 * Words drawn per instruction. Large enough for the distribution checks below
 * to have no realistic chance of a false alarm, small enough that RDSEED - the
 * slow one, and rate limited in hardware - stays well inside the test timeout.
 */
#define SAMPLES 512

#define WORD_BITS (sizeof(unsigned long) * 8)

/*
 * A draw is a bounded retry loop, so it can legitimately come back empty when
 * the hardware queue stays drained for the whole loop. That is a transient
 * condition the entropy source handles, not a defect, but it must be the rare
 * exception: below this share of failed draws the sample is still accepted.
 */
#define MAX_FAILED_DRAWS (SAMPLES / 10)

typedef bool (*draw_fn)(unsigned long *buf);

static int cmp_ulong(const void *a, const void *b)
{
	const unsigned long x = *(const unsigned long *)a;
	const unsigned long y = *(const unsigned long *)b;

	return (x > y) - (x < y);
}

/*
 * Draw SAMPLES words with @draw and check that they look like the output of a
 * working random number generator rather than like an instruction that never
 * ran.
 */
static void check_instruction(const char *name, draw_fn draw)
{
	unsigned long *sample = calloc(SAMPLES, sizeof(unsigned long));
	unsigned int failed = 0, drawn = 0, i;
	unsigned int bit_set[WORD_BITS];
	unsigned long total_set = 0;
	size_t b;

	CHECK(sample != NULL, "%s: out of memory", name);
	if (!sample)
		return;

	memset(bit_set, 0, sizeof(bit_set));

	for (i = 0; i < SAMPLES; i++) {
		/*
		 * Prefilled with a value the instruction cannot plausibly
		 * produce twice in a row, so a draw that reports success
		 * without writing anything is caught rather than counted.
		 */
		unsigned long word = ~0UL;

		if (!draw(&word)) {
			failed++;
			continue;
		}

		CHECK(word != ~0UL,
		      "%s: draw %u reported success but left the buffer untouched",
		      name, i);

		sample[drawn++] = word;

		for (b = 0; b < WORD_BITS; b++) {
			if (word & (1UL << b)) {
				bit_set[b]++;
				total_set++;
			}
		}
	}

	printf("%s: %u of %u draws delivered a word\n", name, drawn, SAMPLES);

	CHECK(drawn > 0, "%s: not a single draw succeeded", name);
	CHECK(failed <= MAX_FAILED_DRAWS,
	      "%s: %u of %u draws failed, more than the tolerated %u", name,
	      failed, SAMPLES, MAX_FAILED_DRAWS);
	if (!drawn)
		goto out;

	/*
	 * Every word distinct. With 512 draws of a 32 or 64 bit value a genuine
	 * collision is far below any probability that matters, so a repeat means
	 * a latched output register rather than bad luck.
	 */
	qsort(sample, drawn, sizeof(*sample), cmp_ulong);
	for (i = 1; i < drawn; i++) {
		CHECK(sample[i] != sample[i - 1],
		      "%s: value 0x%lx delivered twice - output appears stuck",
		      name, sample[i]);
	}

	/*
	 * Roughly half of all bits set. The expected deviation over 512 words is
	 * a fraction of a percent, so the ten percent window below is wide
	 * enough to never fire by chance while still catching an all-zero, an
	 * all-ones or a half-written buffer.
	 */
	CHECK(total_set > (unsigned long)drawn * WORD_BITS * 40 / 100 &&
		      total_set < (unsigned long)drawn * WORD_BITS * 60 / 100,
	      "%s: %lu of %lu bits set - implausible bit balance", name,
	      total_set, (unsigned long)drawn * WORD_BITS);

	/*
	 * The same per bit position: an output where one bit never changes is
	 * invisible in the total above but is exactly what a wrong-width
	 * intrinsic or a sign-extended value looks like.
	 */
	for (b = 0; b < WORD_BITS; b++) {
		CHECK(bit_set[b] > drawn * 15 / 100 &&
			      bit_set[b] < drawn * 85 / 100,
		      "%s: bit %zu set in %u of %u words - appears stuck", name,
		      b, bit_set[b], drawn);
	}

out:
	free(sample);
}

/* The detection functions memoize their answer - it must not drift. */
static void check_detection_stable(void)
{
	int seed = rdseed_available();
	int rand = rdrand_available();
	unsigned int i;

	for (i = 0; i < 3; i++) {
		CHECK_EQ(rdseed_available(), seed);
		CHECK_EQ(rdrand_available(), rand);
	}
}

static bool cpuinfo_has_flag(const char *flag)
{
	char line[4096];
	FILE *f = fopen("/proc/cpuinfo", "r");
	bool found = false;

	if (!f)
		return false;

	while (fgets(line, sizeof(line), f)) {
		char *pos;

		if (strncmp(line, "flags", 5))
			continue;

		/* Match a whole token, not a substring of a longer flag. */
		for (pos = strstr(line, flag); pos;
		     pos = strstr(pos + 1, flag)) {
			char before = pos[-1];
			char after = pos[strlen(flag)];

			if ((before == ' ' || before == '\t') &&
			    (after == ' ' || after == '\n' || after == '\0')) {
				found = true;
				break;
			}
		}
		break;
	}

	fclose(f);
	return found;
}

/*
 * Cross-check the CPUID based detection against what the kernel reports.
 *
 * Only one direction can be asserted: the kernel clears feature bits it
 * distrusts - the RDRAND erratum on several AMD families is masked out of
 * /proc/cpuinfo while CPUID keeps advertising it - so CPUID may legitimately
 * say more than the flags line does. It may never say less.
 */
static void check_detection_matches_cpuinfo(void)
{
	if (cpuinfo_has_flag("rdseed"))
		CHECK(rdseed_available(),
		      "kernel reports rdseed, CPUID detection does not");
	if (cpuinfo_has_flag("rdrand"))
		CHECK(rdrand_available(),
		      "kernel reports rdrand, CPUID detection does not");
}

/* An instruction the CPU does not have must be declined, not attempted. */
static void check_absent_declined(void)
{
	unsigned long buf = 0x5a5a5a5aUL;

	if (!rdseed_available()) {
		CHECK(!cpu_es_x86_rdseed(&buf),
		      "rdseed reported data on a CPU without the instruction");
		CHECK_EQ(buf, 0x5a5a5a5aUL);
	}

	if (!rdrand_available()) {
		CHECK(!cpu_es_x86_rdrand(&buf),
		      "rdrand reported data on a CPU without the instruction");
		CHECK_EQ(buf, 0x5a5a5a5aUL);
	}
}

/*
 * cpu_es_get() is what the entropy source calls. It must deliver whenever
 * either instruction is there, and pick RDSEED over RDRAND - the multiplier
 * below is derived from that choice, so a fallback would silently credit
 * RDRAND output at the full RDSEED rate.
 */
static void check_cpu_es_get(void)
{
	unsigned long buf = ~0UL;
	bool expected = rdseed_available() || rdrand_available();

	CHECK_EQ(cpu_es_get(&buf), expected);
	if (expected)
		CHECK(buf != ~0UL, "cpu_es_get did not write the buffer");
}

/*
 * With RDSEED the source is a seeded entropy source and one word of output is
 * one word of entropy. Without it the data comes from the RDRAND DRBG, and the
 * multiplier is what makes a pull logically equivalent to a reseed.
 */
static void check_multiplier(void)
{
	unsigned long buf;
	bool rdseed_works = cpu_es_x86_rdseed(&buf) || cpu_es_x86_rdseed(&buf);
	unsigned int expected = rdseed_works ? 1 : 2 * 1024;

	CHECK_EQ(cpu_es_multiplier(), expected);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	check_detection_stable();
	check_detection_matches_cpuinfo();
	check_absent_declined();

	if (!rdseed_available() && !rdrand_available()) {
		printf("ES CPU x86: neither RDSEED nor RDRAND on this CPU, skipping test\n");
		return 77;
	}

	if (rdseed_available())
		check_instruction("rdseed", cpu_es_x86_rdseed);
	else
		printf("ES CPU x86: no RDSEED on this CPU, instruction not tested\n");

	if (rdrand_available())
		check_instruction("rdrand", cpu_es_x86_rdrand);
	else
		printf("ES CPU x86: no RDRAND on this CPU, instruction not tested\n");

	check_cpu_es_get();
	check_multiplier();

	return common_test_result("ES CPU x86 RDSEED/RDRAND");
}
