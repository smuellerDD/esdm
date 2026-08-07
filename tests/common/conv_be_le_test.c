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
 * Tests for common/conv_be_le.h.
 *
 * Built twice: once as-is, where the byte swaps resolve to the compiler
 * builtins, and once with CONVERSION_TEST defined, which is the only thing that
 * ever compiles - let alone exercises - the header's own rotation-based
 * _bswap16/32/64 fallback. The endian-dependent macros are checked against the
 * explicit accessors of bitshift_le.h / bitshift_be.h rather than a hard-coded
 * byte order, so the expectations hold on either endianness.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Note: crypto/ carries its own trimmed copies of bitshift_le.h/bitshift_be.h
 * and sits in front of common/ on the include path, so the accessors are
 * pulled in through common/bitshift.h - whose own quoted includes resolve
 * next to itself - rather than by including them directly.
 */
#include "bitshift.h"
#include "common_test.h"
#include "conv_be_le.h"

static void test_swap(void)
{
	CHECK_EQ(_swap16(0x0102), 0x0201);
	CHECK_EQ(_swap16(0x0000), 0x0000);
	CHECK_EQ(_swap16(0xff00), 0x00ff);

	CHECK_EQ(_swap32(0x01020304), 0x04030201);
	CHECK_EQ(_swap32(0x00000000), 0x00000000);
	CHECK_EQ(_swap32(0xffffffff), 0xffffffff);
	CHECK_EQ(_swap32(0x000000ff), 0xff000000);

	CHECK(_swap64(0x0102030405060708ULL) == 0x0807060504030201ULL,
	      "_swap64: got 0x%016llx",
	      (unsigned long long)_swap64(0x0102030405060708ULL));
	CHECK(_swap64(0x00000000000000ffULL) == 0xff00000000000000ULL,
	      "_swap64 of a single low byte");

	/* Swapping twice is the identity */
	CHECK_EQ(_swap16(_swap16(0xbeef)), 0xbeef);
	CHECK_EQ(_swap32(_swap32(0xdeadbeef)), 0xdeadbeef);
	CHECK(_swap64(_swap64(0x0123456789abcdefULL)) == 0x0123456789abcdefULL,
	      "_swap64 applied twice");
}

/*
 * be_bswap*()/le_bswap*() turn a host value into the value whose host-order
 * in-memory representation is the big/little endian byte stream. Compare that
 * representation against what the explicit accessors write.
 */
static void test_endian_macros(void)
{
	const uint16_t v16 = 0x0102;
	const uint32_t v32 = 0x01020304;
	const uint64_t v64 = 0x0102030405060708ULL;
	uint16_t s16;
	uint32_t s32;
	uint64_t s64;
	uint8_t got[8], expect[8];

	s16 = be_bswap16(v16);
	memcpy(got, &s16, sizeof(s16));
	be16_to_ptr(expect, v16);
	CHECK_MEM_EQ(got, expect, sizeof(s16));

	s16 = le_bswap16(v16);
	memcpy(got, &s16, sizeof(s16));
	le16_to_ptr(expect, v16);
	CHECK_MEM_EQ(got, expect, sizeof(s16));

	s32 = be_bswap32(v32);
	memcpy(got, &s32, sizeof(s32));
	be32_to_ptr(expect, v32);
	CHECK_MEM_EQ(got, expect, sizeof(s32));

	s32 = le_bswap32(v32);
	memcpy(got, &s32, sizeof(s32));
	le32_to_ptr(expect, v32);
	CHECK_MEM_EQ(got, expect, sizeof(s32));

	s64 = be_bswap64(v64);
	memcpy(got, &s64, sizeof(s64));
	be64_to_ptr(expect, v64);
	CHECK_MEM_EQ(got, expect, sizeof(s64));

	s64 = le_bswap64(v64);
	memcpy(got, &s64, sizeof(s64));
	le64_to_ptr(expect, v64);
	CHECK_MEM_EQ(got, expect, sizeof(s64));

	/* Applying the conversion twice returns the original value */
	CHECK_EQ(be_bswap16(be_bswap16(v16)), v16);
	CHECK_EQ(le_bswap16(le_bswap16(v16)), v16);
	CHECK_EQ(be_bswap32(be_bswap32(v32)), v32);
	CHECK_EQ(le_bswap32(le_bswap32(v32)), v32);
	CHECK(be_bswap64(be_bswap64(v64)) == v64, "be_bswap64 applied twice");
	CHECK(le_bswap64(le_bswap64(v64)) == v64, "le_bswap64 applied twice");

	/* Exactly one of the two directions is a no-op on a given host */
	CHECK((be_bswap32(v32) == v32) != (le_bswap32(v32) == v32),
	      "neither or both of be_bswap32/le_bswap32 are the identity");
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_swap();
	test_endian_macros();

#ifdef CONVERSION_TEST
	return common_test_result("conv_be_le (software byte swap)");
#else
	return common_test_result("conv_be_le (builtin byte swap)");
#endif
}
