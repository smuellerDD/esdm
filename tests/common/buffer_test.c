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
 * Tests for common/buffer.c - the buffer allocation helper and the state it
 * leaves behind, including the refusal to allocate over an already allocated
 * buffer (which would leak it) and the requirement that buffer_free() resets
 * the descriptor so it can be reused.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "buffer.h"
#include "common_test.h"
#include "esdm_logger.h"

static void test_buffer_alloc(void)
{
	BUFFER_INIT(buf);

	/* BUFFER_INIT leaves an empty, unallocated descriptor */
	CHECK(buf.buf == NULL, "BUFFER_INIT left a non-NULL buffer");
	CHECK_EQ(buf.len, 0);
	CHECK_EQ(buf.consumed, 0);

	CHECK_EQ(buffer_alloc(64, &buf), 0);
	CHECK(buf.buf != NULL, "buffer_alloc returned success without memory");
	CHECK_EQ(buf.len, 64);
	CHECK_EQ(buf.consumed, 0);

	if (buf.buf) {
		static const uint8_t zero[64] = { 0 };

		/* The allocation is zeroized */
		CHECK_MEM_EQ(buf.buf, zero, sizeof(zero));

		memset(buf.buf, 0xa5, buf.len);
	}

	/* Allocating over a live buffer would leak it and is refused */
	CHECK_EQ(buffer_alloc(32, &buf), -EFAULT);
	CHECK_EQ(buf.len, 64);

	buffer_free(&buf);
	CHECK(buf.buf == NULL, "buffer_free left a dangling pointer");
	CHECK_EQ(buf.len, 0);
	CHECK_EQ(buf.consumed, 0);

	/* After the free the descriptor is usable again */
	CHECK_EQ(buffer_alloc(16, &buf), 0);
	CHECK_EQ(buf.len, 16);
	buffer_free(&buf);
}

static void test_buffer_alloc_zero(void)
{
	BUFFER_INIT(buf);

	/*
	 * A zero-sized allocation succeeds without allocating, so the
	 * descriptor stays empty and a later real allocation still works.
	 */
	CHECK_EQ(buffer_alloc(0, &buf), 0);
	CHECK(buf.buf == NULL, "buffer_alloc(0) allocated memory");
	CHECK_EQ(buf.len, 0);

	CHECK_EQ(buffer_alloc(8, &buf), 0);
	CHECK(buf.buf != NULL, "buffer_alloc after a zero-sized one failed");
	CHECK_EQ(buf.len, 8);

	buffer_free(&buf);
}

static void test_buffer_free_robustness(void)
{
	BUFFER_INIT(buf);

	/* Both a NULL descriptor and an unallocated one are accepted */
	buffer_free(NULL);
	buffer_free(&buf);
	CHECK(buf.buf == NULL, "buffer_free of an empty buffer changed it");

	/* Freeing twice must not double free */
	CHECK_EQ(buffer_alloc(24, &buf), 0);
	buffer_free(&buf);
	buffer_free(&buf);
	CHECK(buf.buf == NULL, "buffer_free left a dangling pointer");
	CHECK_EQ(buf.len, 0);
}

static void test_buffer_consumed_preserved(void)
{
	BUFFER_INIT(buf);

	CHECK_EQ(buffer_alloc(32, &buf), 0);

	/* buffer_alloc does not touch the consumed counter ... */
	buf.consumed = 7;
	CHECK_EQ(buffer_alloc(32, &buf), -EFAULT);
	CHECK_EQ(buf.consumed, 7);

	/* ... while buffer_free resets it along with the rest */
	buffer_free(&buf);
	CHECK_EQ(buf.consumed, 0);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	/* The double allocation below logs a warning - keep the output quiet */
	esdm_logger_set_verbosity(LOGGER_NONE);

	test_buffer_alloc();
	test_buffer_alloc_zero();
	test_buffer_free_robustness();
	test_buffer_consumed_preserved();

	return common_test_result("buffer");
}
