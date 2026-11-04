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
 * Test plan markers on stdout, one line each, read back from the JUnit output:
 *
 *	HEADLINE:    the title of the test, see test_plan_describe()
 *	DESCRIPTION: what the test is about
 *	FILE:        the source file of the test, relative to the repository
 *	FUNCTION:    the function in it that runs the test
 *	STEP:        an action the test performs
 *	REQUIRE:     a condition that has to hold, printed before its check
 *	CHECK:       a REQUIRE's check as written, "is ok" or "has failed",
 *		     and the actual value
 *	RUNUNTIL:    a repeated action and the condition that ends it
 *
 * STEP, REQUIRE and RUNUNTIL take string literals, so the plan reads the same
 * from the source as from a run. Flushed at once, to stay in order with the
 * log and survive a crash.
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

/* Print the environment variable @name as the marker @prefix, then unset it */
static inline void test_plan_env(const char *prefix, const char *name)
{
	const char *val = getenv(name);

	if (!val || !*val)
		return;

	test_plan(prefix, val);
	unsetenv(name);
}

/*
 * Print what meson.build passes in ESDM_TEST_HEADLINE, _DESCRIPTION, _FILE and
 * _FUNCTION: meson's JUnit output has no field for them. Unset once printed,
 * so a test that re-executes itself or includes this twice prints them once.
 */
__attribute__((constructor)) static void test_plan_describe(void)
{
	test_plan_env("HEADLINE", "ESDM_TEST_HEADLINE");
	test_plan_env("DESCRIPTION", "ESDM_TEST_DESCRIPTION");
	test_plan_env("FILE", "ESDM_TEST_FILE");
	test_plan_env("FUNCTION", "ESDM_TEST_FUNCTION");
}

/* The empty literals around @text let nothing but a string literal compile */
#define TEST_STEP(text) test_plan("STEP", "" text "")
#define TEST_REQUIRE(text) test_plan("REQUIRE", "" text "")
#define TEST_RUNUNTIL(text) test_plan("RUNUNTIL", "" text "")

/*
 * Check @cond and print it as written with the actual value, a format and its
 * arguments. Both are evaluated separately, so neither may have side effects.
 */
#define TEST_CHECK(cond, ...) test_check(!!(cond), #cond, __VA_ARGS__)

#endif /* TEST_PLAN_H */
