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
 * Minimal check harness shared by the tests of the common/ code.
 *
 * The tests do not abort on the first failure: every check records its verdict
 * and execution continues, so one run reports every broken expectation instead
 * of only the first one. main() returns the failure count, which meson turns
 * into a failed test.
 */

#ifndef COMMON_TEST_H
#define COMMON_TEST_H

#include <stdio.h>
#include <string.h>

static unsigned int common_test_failures;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			common_test_failures++;                                \
			fprintf(stderr, "FAIL %s:%d: ", __func__, __LINE__);   \
			fprintf(stderr, __VA_ARGS__);                          \
			fprintf(stderr, "\n");                                 \
		}                                                              \
	} while (0)

#define CHECK_EQ(got, exp)                                                     \
	do {                                                                   \
		long long __got = (long long)(got);                            \
		long long __exp = (long long)(exp);                            \
                                                                               \
		CHECK(__got == __exp, "%s: got %lld, expected %lld", #got,      \
		      __got, __exp);                                           \
	} while (0)

#define CHECK_STR_EQ(got, exp)                                                 \
	do {                                                                   \
		const char *__got = (got);                                     \
		const char *__exp = (exp);                                     \
                                                                               \
		CHECK(__got && !strcmp(__got, __exp), "%s: got \"%s\", "        \
		      "expected \"%s\"", #got, __got ? __got : "(null)",        \
		      __exp);                                                  \
	} while (0)

#define CHECK_MEM_EQ(got, exp, len)                                            \
	do {                                                                   \
		CHECK(!memcmp((got), (exp), (len)), "%s: unexpected buffer "    \
		      "content", #got);                                        \
	} while (0)

/*
 * Report the result of a test binary. Returns the process exit code: 0 when
 * every check passed, 1 otherwise.
 */
static inline int common_test_result(const char *name)
{
	if (common_test_failures) {
		printf("%s: %u check(s) FAILED\n", name, common_test_failures);
		return 1;
	}

	printf("%s: all checks passed\n", name);
	return 0;
}

#endif /* COMMON_TEST_H */
