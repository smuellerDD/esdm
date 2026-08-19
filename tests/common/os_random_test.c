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
 * Tests of the getrandom(2) readers in common/os_random.c, which the kernel RNG
 * entropy source and the seeding of the xoshiro generator share.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#include "common_test.h"
#include "os_random.h"

/* Buffer sizes the readers are asked for */
#define OS_RANDOM_TEST_LEN 64

/* Byte the buffer is prefilled with, to see what was written */
#define OS_RANDOM_TEST_FILL 0x5a

/* A buffer with a guard byte on each side, prefilled */
struct os_random_test_buf {
	uint8_t front;
	uint8_t data[OS_RANDOM_TEST_LEN];
	uint8_t back;
};

static void os_random_test_buf_init(struct os_random_test_buf *buf)
{
	memset(buf, OS_RANDOM_TEST_FILL, sizeof(*buf));
}

static void os_random_test_buf_check(const struct os_random_test_buf *buf,
				     const char *what)
{
	uint8_t fill[OS_RANDOM_TEST_LEN];

	memset(fill, OS_RANDOM_TEST_FILL, sizeof(fill));

	CHECK(buf->front == OS_RANDOM_TEST_FILL &&
		      buf->back == OS_RANDOM_TEST_FILL,
	      "%s: wrote outside of the buffer", what);

	/*
	 * The whole buffer coming back as the fill byte means nothing was
	 * written.
	 */
	CHECK(memcmp(buf->data, fill, sizeof(fill)) != 0,
	      "%s: buffer was not written", what);
}

/* The system call answer reaches the caller as it is */
static void test_getrandom(void)
{
	struct os_random_test_buf buf;
	ssize_t ret;

	os_random_test_buf_init(&buf);

	ret = esdm_os_getrandom(buf.data, sizeof(buf.data), GRND_NONBLOCK);

	/*
	 * -EAGAIN is the one refusal that is expected rather than a failure:
	 * it is what a kernel RNG that is not initialized yet answers, and the
	 * entropy source using this reader acts on exactly that.
	 */
	if (ret == -EAGAIN) {
		printf("the kernel RNG is not initialized - nothing to read\n");
		return;
	}

	CHECK_EQ(ret, (ssize_t)sizeof(buf.data));
	if (ret == (ssize_t)sizeof(buf.data))
		os_random_test_buf_check(&buf, "esdm_os_getrandom");
}

/* Zero bytes are a request that is served by doing nothing */
static void test_getrandom_empty(void)
{
	struct os_random_test_buf buf;

	os_random_test_buf_init(&buf);

	CHECK_EQ(esdm_os_getrandom(buf.data, 0, GRND_NONBLOCK), 0);
	CHECK_EQ(buf.data[0], OS_RANDOM_TEST_FILL);
}

/* A length the system call cannot express is refused, not truncated */
static void test_getrandom_too_long(void)
{
	struct os_random_test_buf buf;

	os_random_test_buf_init(&buf);

	CHECK_EQ(esdm_os_getrandom(buf.data, (size_t)INT_MAX + 1,
				   GRND_NONBLOCK),
		 -EINVAL);
	CHECK_EQ(buf.data[0], OS_RANDOM_TEST_FILL);
}

/* The filling reader delivers everything that was asked for */
static void test_os_random(void)
{
	struct os_random_test_buf buf;
	unsigned int i;

	for (i = 0; i < 4; i++) {
		os_random_test_buf_init(&buf);

		CHECK_EQ(esdm_os_random(buf.data, sizeof(buf.data)), 0);
		os_random_test_buf_check(&buf, "esdm_os_random");
	}
}

/*
 * Two reads differ. With 64 bytes from a source the whole system depends on,
 * equal answers mean the reader handed back its input buffer rather than
 * anything it read.
 */
static void test_os_random_differs(void)
{
	uint8_t first[OS_RANDOM_TEST_LEN], second[OS_RANDOM_TEST_LEN];

	memset(first, 0, sizeof(first));
	memset(second, 0, sizeof(second));

	CHECK_EQ(esdm_os_random(first, sizeof(first)), 0);
	CHECK_EQ(esdm_os_random(second, sizeof(second)), 0);

	CHECK(memcmp(first, second, sizeof(first)) != 0,
	      "two reads returned the same %zu bytes", sizeof(first));
}

/* Unaligned and odd lengths are filled completely as well */
static void test_os_random_lengths(void)
{
	/* One less than the buffer at most: the reads start at its second byte */
	static const size_t lengths[] = { 1,  3,  7,
					  32, 33, OS_RANDOM_TEST_LEN - 1 };
	unsigned int i;

	for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
		struct os_random_test_buf buf;
		size_t len = lengths[i];
		uint8_t fill[OS_RANDOM_TEST_LEN];

		memset(fill, OS_RANDOM_TEST_FILL, sizeof(fill));
		os_random_test_buf_init(&buf);

		CHECK_EQ(esdm_os_random(buf.data + 1, len), 0);

		/* Neither the guards nor the byte before the buffer moved */
		CHECK(buf.front == OS_RANDOM_TEST_FILL &&
			      buf.back == OS_RANDOM_TEST_FILL &&
			      buf.data[0] == OS_RANDOM_TEST_FILL,
		      "length %zu: wrote outside of the requested range", len);

		/* And what follows the requested range is untouched */
		CHECK(!memcmp(buf.data + 1 + len, fill,
			      sizeof(buf.data) - 1 - len),
		      "length %zu: wrote past the requested range", len);
	}
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_getrandom();
	test_getrandom_empty();
	test_getrandom_too_long();
	test_os_random();
	test_os_random_differs();
	test_os_random_lengths();

	return common_test_result("operating system random numbers");
}
