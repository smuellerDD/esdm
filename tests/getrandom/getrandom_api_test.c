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
 * Tests of the getrandom/getentropy interposition library that need no server.
 *
 * The two tests next to this one drive the library against a running ESDM,
 * which is what covers the paths that succeed. Two things are left over, and
 * both are what a caller meets when something is wrong:
 *
 * - the flag combinations the library refuses. They are checked before anything
 *   else happens, and each one is a request that cannot be honoured - insecure
 *   randomness that is also blocking, a seed that is also insecure, an unknown
 *   flag. Getting one of these wrong would hand the caller data with properties
 *   it did not ask for, so the refusal is the property, not the data.
 * - the fallback to the kernel. Every call the ESDM cannot answer is retried as
 *   the plain system call, which is what keeps a program working when the
 *   daemon is not running. With no server to answer, that is the path every
 *   request below takes.
 *
 * The library is linked rather than preloaded here, and both the wrapped and
 * the unwrapped entry points are called: the wrapper is what a relinked program
 * reaches, the plain name is what an LD_PRELOAD'ed one does, and the __real_
 * pair is the way back to the kernel that the library offers its callers.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common_test.h"

/* As defined by the library - the kernel knows neither */
#define GRND_SEED 0x0010
#define GRND_FULLY_SEEDED 0x0020

#ifndef GRND_INSECURE
#define GRND_INSECURE 0x0004
#endif

ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags);
ssize_t __real_getrandom(void *buffer, size_t length, unsigned int flags);
int __wrap_getentropy(void *buffer, size_t length);
int __real_getentropy(void *buffer, size_t length);

/* Nothing the library can return should leave the buffer as it found it */
static bool is_untouched(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i] != 0xa5)
			return false;
	}

	return true;
}

static void test_flags_refused(void)
{
	static const struct {
		const char *desc;
		unsigned int flags;
	} cases[] = {
		{ "an unknown flag", 0x8000 },
		{ "insecure and blocking randomness", GRND_INSECURE | GRND_RANDOM },
		{ "an insecure seed", GRND_INSECURE | GRND_SEED },
		{ "a blocking seed", GRND_RANDOM | GRND_SEED },
	};
	uint8_t buf[32];
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		memset(buf, 0xa5, sizeof(buf));

		/*
		 * Refused before any of it reaches the ESDM or the kernel, so
		 * the buffer has to come back as it went in.
		 */
		CHECK(__wrap_getrandom(buf, sizeof(buf), cases[i].flags) ==
			      -EINVAL,
		      "%s was not refused", cases[i].desc);
		CHECK(is_untouched(buf, sizeof(buf)),
		      "%s was refused after writing to the buffer",
		      cases[i].desc);

		/* The interposed entry point answers the same way */
		CHECK(getrandom(buf, sizeof(buf), cases[i].flags) == -EINVAL,
		      "%s was not refused through getrandom()", cases[i].desc);
	}
}

/*
 * Every request that the ESDM cannot answer - which is all of them here - is
 * served by the kernel instead. What each mode means is the ESDM's business;
 * what is checked is that the caller gets the bytes it asked for either way.
 */
static void test_fallback_to_kernel(void)
{
	static const struct {
		const char *desc;
		unsigned int flags;
	} cases[] = {
		{ "a plain request", 0 },
		{ "a non-blocking request", GRND_NONBLOCK },
		{ "insecure randomness", GRND_INSECURE },
		{ "prediction resistant randomness", GRND_RANDOM },
	};
	uint8_t buf[32];
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		memset(buf, 0xa5, sizeof(buf));

		CHECK(__wrap_getrandom(buf, sizeof(buf), cases[i].flags) ==
			      (ssize_t)sizeof(buf),
		      "%s was not served", cases[i].desc);
		CHECK(!is_untouched(buf, sizeof(buf)),
		      "%s delivered nothing", cases[i].desc);
	}

	/* A request for nothing is not an error */
	CHECK_EQ(__wrap_getrandom(buf, 0, 0), 0);
}

/*
 * The seed request has no kernel equivalent, so there is nothing to fall back
 * to: without a server it fails, and it has to fail the way a system call does
 * - with -1 and errno - rather than by handing back the negative error.
 */
static void test_seed_without_server(void)
{
	uint8_t buf[128];
	ssize_t ret;

	memset(buf, 0xa5, sizeof(buf));

	errno = 0;
	ret = __wrap_getrandom(buf, sizeof(buf), GRND_SEED);
	CHECK(ret == -1, "the seed request returned %zd rather than -1", ret);
	CHECK(errno != 0, "the seed request failed without setting errno");

	/* The two flags it takes alongside are accepted, and fail the same way */
	CHECK_EQ(__wrap_getrandom(buf, sizeof(buf),
				  GRND_SEED | GRND_NONBLOCK), -1);
	CHECK_EQ(__wrap_getrandom(buf, sizeof(buf),
				  GRND_SEED | GRND_FULLY_SEEDED), -1);
}

/*
 * getentropy() is the other interface, with the stricter contract: it fills the
 * whole buffer or it fails, and it takes at most 256 bytes.
 */
static void test_getentropy(void)
{
	uint8_t buf[256];

	memset(buf, 0xa5, sizeof(buf));
	CHECK_EQ(__wrap_getentropy(buf, sizeof(buf)), 0);
	CHECK(!is_untouched(buf, sizeof(buf)), "getentropy delivered nothing");

	memset(buf, 0xa5, sizeof(buf));
	CHECK_EQ(getentropy(buf, 32), 0);
	CHECK(!is_untouched(buf, 32), "getentropy() delivered nothing");

	/*
	 * More than the interface promises. The refusal is what a caller
	 * expects from getentropy(3), and it must not partially fill the
	 * buffer on the way out.
	 */
	memset(buf, 0xa5, sizeof(buf));
	errno = 0;
	CHECK_EQ(__wrap_getentropy(buf, sizeof(buf) + 1), -1);
	CHECK_EQ(errno, EIO);
	CHECK(is_untouched(buf, sizeof(buf)),
	      "an oversized getentropy wrote to the buffer anyway");
}

/*
 * The way back to the kernel that the library keeps for its callers. It is what
 * a program uses to reach the system call while the library is interposed, so
 * it must not end up in the ESDM by accident.
 */
static void test_real_entry_points(void)
{
	uint8_t buf[32];

	memset(buf, 0xa5, sizeof(buf));
	CHECK_EQ(__real_getrandom(buf, sizeof(buf), 0), (ssize_t)sizeof(buf));
	CHECK(!is_untouched(buf, sizeof(buf)),
	      "__real_getrandom delivered nothing");

	memset(buf, 0xa5, sizeof(buf));
	CHECK_EQ(__real_getentropy(buf, sizeof(buf)), 0);
	CHECK(!is_untouched(buf, sizeof(buf)),
	      "__real_getentropy delivered nothing");

	/* Same contract as the wrapped one: at most 256 bytes */
	errno = 0;
	CHECK_EQ(__real_getentropy(buf, 257), -1);
	CHECK_EQ(errno, EIO);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_flags_refused();
	test_fallback_to_kernel();
	test_seed_without_server();
	test_getentropy();
	test_real_entry_points();

	return common_test_result("getrandom_api");
}
