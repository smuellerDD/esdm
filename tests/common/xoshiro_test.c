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

/* Tests of the xoshiro256++ generator in common/xoshiro_prng.c. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common_test.h"
#include "xoshiro_prng.h"

/* The first outputs for the state { 1, 2, 3, 4 } */
static const uint64_t xoshiro_kat[] = {
	0x0000000002800001ULL, 0x0000000003800067ULL, 0x000cc00003800067ULL,
	0x000cc201994400b2ULL, 0x8012a2019ac433cdULL, 0x8a69978acdee33baULL,
	0xc271134733154abdULL, 0xac2ba09179169e97ULL,
};

/* The state the generator is left in after those outputs */
static const uint64_t xoshiro_kat_state[4] = {
	0xd058d4081b070347ULL,
	0x60785010040e8140ULL,
	0xe03808160b0380c3ULL,
	0x30204e0f198301a1ULL,
};

/* Draws per interval in the equidistribution check */
#define XOSHIRO_TEST_DRAWS 100000

static struct xoshiro_state xoshiro_test_fixed(void)
{
	struct xoshiro_state state = { .s = { 1, 2, 3, 4 } };

	return state;
}

static void test_known_answers(void)
{
	struct xoshiro_state state = xoshiro_test_fixed();
	unsigned int i;

	for (i = 0; i < sizeof(xoshiro_kat) / sizeof(xoshiro_kat[0]); i++) {
		uint64_t val = xoshiro_generate(&state);

		CHECK(val == xoshiro_kat[i],
		      "draw %u: got 0x%016llx, expected 0x%016llx", i,
		      (unsigned long long)val,
		      (unsigned long long)xoshiro_kat[i]);
	}

	CHECK_MEM_EQ(state.s, xoshiro_kat_state, sizeof(xoshiro_kat_state));
}

/*
 * Two states that differ produce different sequences, and one state produces a
 * sequence rather than a repetition - the coarsest statement that the state
 * update is wired up at all.
 */
static void test_sequence(void)
{
	struct xoshiro_state a = xoshiro_test_fixed();
	struct xoshiro_state b = { .s = { 4, 3, 2, 1 } };
	uint64_t prev = xoshiro_generate(&a);
	unsigned int i, repeats = 0, equal = 0;

	xoshiro_generate(&b);

	for (i = 0; i < 1000; i++) {
		uint64_t val_a = xoshiro_generate(&a);
		uint64_t val_b = xoshiro_generate(&b);

		if (val_a == prev)
			repeats++;
		if (val_a == val_b)
			equal++;
		prev = val_a;
	}

	CHECK_EQ(repeats, 0);
	CHECK_EQ(equal, 0);
}

/* The seeding from the operating system leaves a usable, unpredictable state */
static void test_init(void)
{
	static const uint64_t zero[4] = { 0, 0, 0, 0 };
	struct xoshiro_state a, b;
	unsigned int i, equal = 0;

	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));

	if (xoshiro_init(&a) || xoshiro_init(&b)) {
		CHECK(0, "the generator cannot be seeded from the system");
		return;
	}

	/* The all-zero state is the one the generator cannot leave */
	CHECK(memcmp(a.s, zero, sizeof(zero)) != 0,
	      "a seeded state is all zero");
	CHECK(memcmp(a.s, b.s, sizeof(zero)) != 0,
	      "two seeded states are identical");

	for (i = 0; i < 100; i++) {
		if (xoshiro_generate(&a) == xoshiro_generate(&b))
			equal++;
	}

	CHECK_EQ(equal, 0);
}

/* Every draw lands inside the interval, whatever shape the interval has */
static void test_interval_range(void)
{
	struct xoshiro_state state = xoshiro_test_fixed();
	static const struct {
		uint64_t lower;
		uint64_t upper;
	} intervals[] = {
		{ 0, 2 },
		{ 0, 60 },
		{ 7, 8 },
		{ 100, 137 },
		{ UINT64_MAX - 5, UINT64_MAX },
		/* A span that is not a power of two, so the bias is real */
		{ 0, 3 },
	};
	unsigned int i, j;

	for (i = 0; i < sizeof(intervals) / sizeof(intervals[0]); i++) {
		uint64_t lower = intervals[i].lower;
		uint64_t upper = intervals[i].upper;
		unsigned int outside = 0;

		for (j = 0; j < 10000; j++) {
			uint64_t val =
				xoshiro_generate_interval(&state, lower, upper);

			if (val < lower || val >= upper)
				outside++;
		}

		CHECK(!outside, "interval [%llu, %llu): %u of %u draws outside",
		      (unsigned long long)lower, (unsigned long long)upper,
		      outside, j);
	}
}

/* An interval that holds one value or none at all is answered without a draw */
static void test_interval_empty(void)
{
	struct xoshiro_state state = xoshiro_test_fixed();
	struct xoshiro_state untouched = xoshiro_test_fixed();

	CHECK_EQ(xoshiro_generate_interval(&state, 42, 43), 42);
	CHECK_EQ(xoshiro_generate_interval(&state, 42, 42), 42);
	CHECK_EQ(xoshiro_generate_interval(&state, 42, 7), 42);

	CHECK_MEM_EQ(state.s, untouched.s, sizeof(state.s));
}

/* The values of an interval come up equally often. */
static void test_interval_equidistribution(void)
{
	struct xoshiro_state state = xoshiro_test_fixed();
	static const unsigned int spans[] = { 2, 3, 10, 60 };
	unsigned int i;

	for (i = 0; i < sizeof(spans) / sizeof(spans[0]); i++) {
		unsigned int span = spans[i], hist[60] = { 0 }, j;
		unsigned int expect = XOSHIRO_TEST_DRAWS / span;
		unsigned int lowest = XOSHIRO_TEST_DRAWS, highest = 0;

		for (j = 0; j < XOSHIRO_TEST_DRAWS; j++)
			hist[xoshiro_generate_interval(&state, 0, span)]++;

		for (j = 0; j < span; j++) {
			if (hist[j] < lowest)
				lowest = hist[j];
			if (hist[j] > highest)
				highest = hist[j];
		}

		/* Within a tenth of the even share, in both directions */
		CHECK(lowest > expect - expect / 10 &&
			      highest < expect + expect / 10,
		      "span %u: %u draws spread between %u and %u, evenly it is %u",
		      span, XOSHIRO_TEST_DRAWS, lowest, highest, expect);
	}
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_known_answers();
	test_sequence();
	test_init();
	test_interval_range();
	test_interval_empty();
	test_interval_equidistribution();

	return common_test_result("xoshiro256++");
}
