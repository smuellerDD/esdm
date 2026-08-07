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
 * Tests for the header-only helpers of common/: the endian-explicit byte
 * stream accessors (bitshift_le.h / bitshift_be.h / bitshift.h), the bit
 * rotations (rotate.h), the word-wise XOR (xor.h), the min/max helpers
 * (math_helper.h), the alignment macros (buffer.h) and the error pointer
 * encoding (ptr_err.h).
 *
 * These are inline functions, so the coverage they get is whatever their
 * callers happen to produce; the known answers below pin their contract
 * independently of that.
 *
 * Note: xor.h and helper.h both define a static inline aligned(), so only one
 * of the two may be included here.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bitshift.h"
#include "buffer.h"
#include "common_test.h"
#include "math_helper.h"
#include "ptr_err.h"
#include "rotate.h"
#include "xor.h"

static void test_bitshift_le(void)
{
	static const uint8_t stream[8] = { 0x01, 0x02, 0x03, 0x04,
					   0x05, 0x06, 0x07, 0x08 };
	uint8_t out[8];

	CHECK_EQ(ptr_to_le16(stream), 0x0201);
	CHECK_EQ(ptr_to_le32(stream), 0x04030201);
	CHECK(ptr_to_le64(stream) == 0x0807060504030201ULL,
	      "ptr_to_le64: got 0x%016llx",
	      (unsigned long long)ptr_to_le64(stream));

	memset(out, 0, sizeof(out));
	le16_to_ptr(out, 0x0201);
	CHECK_MEM_EQ(out, stream, 2);

	memset(out, 0, sizeof(out));
	le32_to_ptr(out, 0x04030201);
	CHECK_MEM_EQ(out, stream, 4);

	memset(out, 0, sizeof(out));
	le64_to_ptr(out, 0x0807060504030201ULL);
	CHECK_MEM_EQ(out, stream, 8);
}

static void test_bitshift_be(void)
{
	static const uint8_t stream[8] = { 0x01, 0x02, 0x03, 0x04,
					   0x05, 0x06, 0x07, 0x08 };
	uint8_t out[8];

	CHECK_EQ(ptr_to_be16(stream), 0x0102);
	CHECK_EQ(ptr_to_be32(stream), 0x01020304);
	CHECK(ptr_to_be64(stream) == 0x0102030405060708ULL,
	      "ptr_to_be64: got 0x%016llx",
	      (unsigned long long)ptr_to_be64(stream));

	memset(out, 0, sizeof(out));
	be16_to_ptr(out, 0x0102);
	CHECK_MEM_EQ(out, stream, 2);

	memset(out, 0, sizeof(out));
	be32_to_ptr(out, 0x01020304);
	CHECK_MEM_EQ(out, stream, 4);

	memset(out, 0, sizeof(out));
	be64_to_ptr(out, 0x0102030405060708ULL);
	CHECK_MEM_EQ(out, stream, 8);
}

static void test_bitshift_host(void)
{
	static const uint8_t stream[8] = { 0x01, 0x02, 0x03, 0x04,
					   0x05, 0x06, 0x07, 0x08 };

	/*
	 * bitshift.h picks the accessor matching the host byte order, so the
	 * result has to equal exactly one of the two explicit variants.
	 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	CHECK_EQ(ptr_to_16(stream), ptr_to_be16(stream));
	CHECK_EQ(ptr_to_32(stream), ptr_to_be32(stream));
	CHECK(ptr_to_64(stream) == ptr_to_be64(stream), "ptr_to_64 mismatch");
#else
	CHECK_EQ(ptr_to_16(stream), ptr_to_le16(stream));
	CHECK_EQ(ptr_to_32(stream), ptr_to_le32(stream));
	CHECK(ptr_to_64(stream) == ptr_to_le64(stream), "ptr_to_64 mismatch");
#endif
}

static void test_rotate(void)
{
	/* Known answers */
	CHECK_EQ(rol16(0x1234, 4), 0x2341);
	CHECK_EQ(ror16(0x1234, 4), 0x4123);
	CHECK_EQ(rol32(0x12345678, 8), 0x34567812);
	CHECK_EQ(ror32(0x12345678, 8), 0x78123456);
	CHECK(rol64(0x0123456789abcdefULL, 8) == 0x23456789abcdef01ULL,
	      "rol64 known answer");
	CHECK(ror64(0x0123456789abcdefULL, 8) == 0xef0123456789abcdULL,
	      "ror64 known answer");

	/* A rotation by zero and by the full width is the identity */
	CHECK_EQ(rol16(0xbeef, 0), 0xbeef);
	CHECK_EQ(ror16(0xbeef, 0), 0xbeef);
	CHECK_EQ(rol16(0xbeef, 16), 0xbeef);
	CHECK_EQ(ror16(0xbeef, 16), 0xbeef);
	CHECK_EQ(rol32(0xdeadbeef, 0), 0xdeadbeef);
	CHECK_EQ(ror32(0xdeadbeef, 0), 0xdeadbeef);
	CHECK_EQ(rol32(0xdeadbeef, 32), 0xdeadbeef);
	CHECK_EQ(ror32(0xdeadbeef, 32), 0xdeadbeef);
	CHECK(rol64(0x0123456789abcdefULL, 0) == 0x0123456789abcdefULL,
	      "rol64 by 0");
	CHECK(ror64(0x0123456789abcdefULL, 64) == 0x0123456789abcdefULL,
	      "ror64 by 64");

	/* Left and right rotation invert each other over the whole width */
	{
		unsigned int n;

		for (n = 0; n < 16; n++)
			CHECK_EQ(ror16(rol16(0xa5c3, (uint8_t)n), (uint8_t)n),
				 0xa5c3);
		for (n = 0; n < 32; n++)
			CHECK_EQ(ror32(rol32(0xa5c3f00d, (uint8_t)n),
				       (uint8_t)n),
				 0xa5c3f00d);
		for (n = 0; n < 64; n++)
			CHECK(ror64(rol64(0xa5c3f00ddeadbeefULL, (uint8_t)n),
				    (uint8_t)n) == 0xa5c3f00ddeadbeefULL,
			      "rol64/ror64 roundtrip for n=%u", n);
	}
}

/* Reference implementation the word-wise variants have to agree with */
static void xor_reference(uint8_t *dst, const uint8_t *src, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		dst[i] ^= src[i];
}

static void test_xor_one(size_t offset, size_t size,
			 void (*fn)(uint8_t *, const uint8_t *, size_t),
			 const char *name)
{
	_Alignas(8) uint8_t dst[80];
	_Alignas(8) uint8_t src[80];
	uint8_t expect[80];
	size_t i;

	for (i = 0; i < sizeof(dst); i++) {
		dst[i] = (uint8_t)(i * 3 + 1);
		src[i] = (uint8_t)(i * 5 + 7);
	}
	memcpy(expect, dst, sizeof(expect));
	xor_reference(expect + offset, src + offset, size);

	fn(dst + offset, src + offset, size);

	CHECK(!memcmp(dst, expect, sizeof(dst)),
	      "%s(offset %zu, size %zu) produced an unexpected result", name,
	      offset, size);
}

static void test_xor(void)
{
	static const size_t sizes[] = { 0, 1, 3, 4, 5, 7, 8, 9, 15, 16, 20, 23,
					31, 32, 33, 64 };
	unsigned int i;

	CHECK_EQ(aligned((const uint8_t *)(uintptr_t)0x1000, 7), 1);
	CHECK_EQ(aligned((const uint8_t *)(uintptr_t)0x1001, 7), 0);
	CHECK_EQ(aligned((const uint8_t *)(uintptr_t)0x1004, 3), 1);
	CHECK_EQ(aligned((const uint8_t *)(uintptr_t)0x1004, 7), 0);

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		/* Aligned start: the word-wise fast paths are taken */
		test_xor_one(0, sizes[i], xor_8, "xor_8");
		test_xor_one(0, sizes[i], xor_32, "xor_32");
		test_xor_one(0, sizes[i], xor_64, "xor_64");

		/* Unaligned start: the byte-wise fallbacks are taken */
		test_xor_one(1, sizes[i], xor_8, "xor_8");
		test_xor_one(1, sizes[i], xor_32, "xor_32");
		test_xor_one(1, sizes[i], xor_64, "xor_64");

		/* 4 byte aligned only: xor_64 has to fall back to xor_32 */
		test_xor_one(4, sizes[i], xor_32, "xor_32");
		test_xor_one(4, sizes[i], xor_64, "xor_64");
	}
}

static void test_math_helper(void)
{
	CHECK_EQ(min_uint32(3, 7), 3);
	CHECK_EQ(min_uint32(7, 3), 3);
	CHECK_EQ(min_uint32(5, 5), 5);
	CHECK_EQ(max_uint32(3, 7), 7);
	CHECK_EQ(max_uint32(7, 3), 7);

	CHECK(min_uint64(1ULL << 40, 1ULL << 41) == (1ULL << 40),
	      "min_uint64 known answer");
	CHECK(max_uint64(1ULL << 40, 1ULL << 41) == (1ULL << 41),
	      "max_uint64 known answer");

	CHECK_EQ(min_size(0, (size_t)-1), 0);
	CHECK(max_size(0, (size_t)-1) == (size_t)-1, "max_size known answer");

	/* The macros must not evaluate their arguments twice */
	{
		int calls = 0;
		int a = (calls++, 4);
		int b = (calls++, 9);

		CHECK_EQ(min(a, b), 4);
		CHECK_EQ(max(a, b), 9);
		CHECK_EQ(calls, 2);
	}
}

static void test_align(void)
{
	_Alignas(16) uint8_t buf[32];
	unsigned int i;

	/* ALIGN() takes a mask, so ALIGN(x, 7) rounds up to a multiple of 8 */
	CHECK_EQ(ALIGN(0, 7), 0);
	CHECK_EQ(ALIGN(1, 7), 8);
	CHECK_EQ(ALIGN(8, 7), 8);
	CHECK_EQ(ALIGN(9, 7), 16);
	CHECK_EQ(ALIGN(5, 3), 8);
	CHECK_EQ(ALIGN(4, 3), 4);
	CHECK_EQ(ALIGN_APPLY(13, 15), 16);

	/*
	 * The pointer variants take the alignment itself and must never move
	 * a pointer backwards or by more than the alignment.
	 */
	for (i = 0; i < 16; i++) {
		uint8_t *p = buf + i;
		uint64_t *p64 = ALIGN_PTR_64(p, 8);
		uint32_t *p32 = ALIGN_PTR_32(p, 4);
		uint16_t *p16 = ALIGN_PTR_16(p, 2);
		uint8_t *p8 = ALIGN_PTR_8(p, 1);

		CHECK((uint8_t *)p64 >= p && (uint8_t *)p64 < p + 8,
		      "ALIGN_PTR_64 out of range for offset %u", i);
		CHECK(((uintptr_t)p64 & 7) == 0,
		      "ALIGN_PTR_64 unaligned for offset %u", i);
		CHECK((uint8_t *)p32 >= p && (uint8_t *)p32 < p + 4,
		      "ALIGN_PTR_32 out of range for offset %u", i);
		CHECK(((uintptr_t)p32 & 3) == 0,
		      "ALIGN_PTR_32 unaligned for offset %u", i);
		CHECK((uint8_t *)p16 >= p && (uint8_t *)p16 < p + 2,
		      "ALIGN_PTR_16 out of range for offset %u", i);
		CHECK(((uintptr_t)p16 & 1) == 0,
		      "ALIGN_PTR_16 unaligned for offset %u", i);
		CHECK(p8 == p, "ALIGN_PTR_8 moved the pointer for offset %u", i);
	}
}

static void test_ptr_err(void)
{
	void *err = ERR_PTR(-EINVAL);
	int value = 5;

	CHECK(IS_ERR(err), "ERR_PTR(-EINVAL) is not recognized as an error");
	CHECK_EQ(PTR_ERR(err), -EINVAL);

	CHECK(!IS_ERR(NULL), "NULL must not be an error pointer");
	CHECK(!IS_ERR(&value), "a valid pointer must not be an error pointer");

	/* The encodable range ends at PTR_MAX_ERRNO */
	CHECK(IS_ERR(ERR_PTR(-1)), "-1 must be an error pointer");
	CHECK(IS_ERR(ERR_PTR(-PTR_MAX_ERRNO)),
	      "-PTR_MAX_ERRNO must be an error pointer");
	CHECK(!IS_ERR(ERR_PTR(-(PTR_MAX_ERRNO + 1))),
	      "beyond -PTR_MAX_ERRNO must not be an error pointer");
	CHECK(!IS_ERR(ERR_PTR(0)), "0 must not be an error pointer");
	CHECK(!IS_ERR(ERR_PTR(1)), "a positive value must not be an error");
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_bitshift_le();
	test_bitshift_be();
	test_bitshift_host();
	test_rotate();
	test_xor();
	test_math_helper();
	test_align();
	test_ptr_err();

	return common_test_result("bitops");
}
