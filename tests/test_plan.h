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

#ifndef TEST_PLAN_H
#define TEST_PLAN_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Test plan markers on stdout, one line each, so the plan and its assertions
 * can be read back from the JUnit output of the test run:
 *
 *	DESCRIPTION: what the test is about, see test_plan_describe()
 *	STEP:     an action the test performs
 *	REQUIRE:  a condition that has to hold, printed before it is checked -
 *		  on a failure the last REQUIRE is the one that did not hold
 *	CHECK:    the check of a REQUIRE as written in the code in [], its
 *		  verdict, "is ok" or "has failed", and the actual value it
 *		  was made on
 *	RUNUNTIL: a repeated action and the condition that ends it
 *
 * The text of a STEP, REQUIRE and RUNUNTIL is a string literal, known at
 * compile time: the plan reads the same from the source as from the output of
 * any run. Only a CHECK reports what a run found.
 *
 * Flushed right away, so the markers stay in order with the log output and
 * survive a test that crashes.
 */
static inline void test_plan(const char *prefix, const char *text)
{
	printf("%s: %s\n", prefix, text);
	fflush(stdout);
}

static inline bool __attribute__((format(printf, 3, 4)))
test_check(bool ok, const char *cond, const char *fmt, ...)
{
	va_list args;

	printf("CHECK: [%s] %s (actual: ", cond, ok ? "is ok" : "has failed");
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf(")\n");
	fflush(stdout);

	return ok;
}

/*
 * The description meson.build gives the test in ESDM_TEST_DESCRIPTION, printed
 * before the test runs: meson's JUnit output has no field for one, but carries
 * the output of the test. Unset once printed, so it is printed once even by a
 * test that executes itself again or includes this in two of its files.
 */
__attribute__((constructor)) static void test_plan_describe(void)
{
	const char *desc = getenv("ESDM_TEST_DESCRIPTION");

	if (!desc || !*desc)
		return;

	test_plan("DESCRIPTION", desc);
	unsetenv("ESDM_TEST_DESCRIPTION");
}

/* The empty literals around @text let nothing but a string literal compile */
#define TEST_STEP(text) test_plan("STEP", "" text "")
#define TEST_REQUIRE(text) test_plan("REQUIRE", "" text "")
#define TEST_RUNUNTIL(text) test_plan("RUNUNTIL", "" text "")

/*
 * Check @cond, print it as written together with the actual value - the
 * remaining arguments, a format and what it formats - and return whether it
 * holds. The condition and the actual value are evaluated separately, so
 * neither may have side effects.
 */
#define TEST_CHECK(cond, ...) test_check(!!(cond), #cond, __VA_ARGS__)

#endif /* TEST_PLAN_H */
