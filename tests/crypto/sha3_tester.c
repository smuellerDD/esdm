/*
 * Known-answer tests of the built-in SHA-3 implementation (crypto/sha3.c)
 *
 * Keccak absorbs its input as little-endian 64-bit lanes. sha3.c has two
 * paths for that: one decoding the input byte by byte, and a fast one loading
 * whole lanes from an input that is aligned to them - which is also the path
 * that absorbs the padded final block. Every message is therefore hashed from
 * an aligned buffer, from a misaligned one and in pieces that leave a partial
 * block behind, and each has to give the known answer. A path that loads the
 * lanes in host byte order rather than little-endian gives a different digest
 * on big-endian machines, which is what commit 82777b8 fixed.
 *
 * The NIST example vectors for SHA-3 are used: the 1600-bit message of the
 * byte 0xa3 is longer than the block of every SHA-3 variant, so it takes the
 * full-block paths as well.
 *
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm_sha3.h"
#include "selftest_kat.h"

/* The 1600-bit message of the NIST examples: 200 times the byte 0xa3 */
#define SHA3_TEST_MSG_LEN 200
#define SHA3_TEST_MSG_BYTE 0xa3

/* Longest digest below - SHA3-512 and the SHAKE256 output */
#define SHA3_TEST_MAX_DIGEST 64

static const uint8_t exp_224[] = {
	0x93, 0x76, 0x81, 0x6a, 0xba, 0x50, 0x3f, 0x72, 0xf9, 0x6c,
	0xe7, 0xeb, 0x65, 0xac, 0x09, 0x5d, 0xee, 0xe3, 0xbe, 0x4b,
	0xf9, 0xbb, 0xc2, 0xa1, 0xcb, 0x7e, 0x11, 0xe0,
};

static const uint8_t exp_256[] = {
	0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07, 0xa9, 0x8e,
	0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf, 0xd4, 0x6c, 0xfd, 0x81,
	0xb2, 0x2e, 0x39, 0x73, 0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3,
	0x17, 0x87,
};

static const uint8_t exp_384[] = {
	0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9, 0x5d, 0xc4,
	0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b, 0x18, 0x9c, 0xc1, 0xe4,
	0x2b, 0x74, 0x16, 0x8e, 0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d,
	0xbc, 0xdd, 0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98,
	0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f,
};

static const uint8_t exp_512[] = {
	0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1, 0x46, 0x7f,
	0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b, 0xec, 0x76, 0x28, 0xed,
	0xf5, 0xf3, 0xfd, 0xc0, 0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae,
	0xec, 0xa8, 0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3,
	0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b, 0xe5, 0x89,
	0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41, 0x6d, 0xf6, 0x54, 0x5a,
	0x1c, 0xe8, 0xba, 0x00,
};

/* 512 bits of SHAKE256 output */
static const uint8_t exp_shake256[] = {
	0xcd, 0x8a, 0x92, 0x0e, 0xd1, 0x41, 0xaa, 0x04, 0x07, 0xa2,
	0x2d, 0x59, 0x28, 0x86, 0x52, 0xe9, 0xd9, 0xf1, 0xa7, 0xee,
	0x0c, 0x1e, 0x7c, 0x1c, 0xa6, 0x99, 0x42, 0x4d, 0xa8, 0x4a,
	0x90, 0x4d, 0x2d, 0x70, 0x0c, 0xaa, 0xe7, 0x39, 0x6e, 0xce,
	0x96, 0x60, 0x44, 0x40, 0x57, 0x7d, 0xa4, 0xf3, 0xaa, 0x22,
	0xae, 0xb8, 0x85, 0x7f, 0x96, 0x1c, 0x4c, 0xd8, 0xe0, 0x6f,
	0x0a, 0xe6, 0x61, 0x0b,
};

/* SHA3-512("abc"): a message that only ever reaches the final block */
static const uint8_t exp_512_abc[] = {
	0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93,
	0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e, 0x08, 0xf6, 0x21, 0x82,
	0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2,
	0x71, 0x2e, 0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
	0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, 0x57, 0x34,
	0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27,
	0x4e, 0xec, 0x53, 0xf0,
};

/*
 * Hash @msg of @msglen bytes in updates of the sizes in @chunks (0 ends the
 * list, the rest of the message goes in one last update) and compare against
 * @exp of @explen bytes.
 */
static int sha3_check(const char *name, const struct esdm_hash *hash,
		      const char *how, const uint8_t *msg, size_t msglen,
		      const size_t *chunks, const uint8_t *exp, size_t explen)
{
	struct esdm_hash_ctx *ctx = NULL;
	uint8_t act[SHA3_TEST_MAX_DIGEST];
	size_t done = 0;
	int ret;

	if (esdm_hash_alloc(hash, &ctx)) {
		printf("%s: cannot allocate the hash context\n", name);
		return 1;
	}

	esdm_hash_init(ctx);
	for (; chunks && *chunks && done + *chunks <= msglen; chunks++) {
		esdm_hash_update(ctx, msg + done, *chunks);
		done += *chunks;
	}
	esdm_hash_update(ctx, msg + done, msglen - done);
	/* A no-op for the fixed size digests, the output length for SHAKE */
	esdm_hash_set_digestsize(ctx, explen);
	esdm_hash_final(ctx, act);

	/* Checks the digest and that a digest off by a byte is rejected */
	ret = esdm_kat_check(act, exp, explen);
	if (ret)
		printf("%s: wrong digest for the message %s\n", name, how);

	esdm_hash_zero_free(ctx);
	return ret ? 1 : 0;
}

static int sha3_tester(const char *name, const struct esdm_hash *hash,
		       const uint8_t *exp, size_t explen)
{
	/*
	 * Lane aligned so that &buf[0] takes the aligned path and &buf[1] the
	 * byte-wise one. The pieces leave partial blocks behind, which the
	 * following updates complete from varying offsets.
	 */
	static const size_t pieces[] = { 1, 7, 64, 3, 0 };
	uint64_t buf[(SHA3_TEST_MSG_LEN + 1 + 7) / 8];
	uint8_t *aligned = (uint8_t *)buf;
	uint8_t mod[SHA3_TEST_MSG_LEN];
	uint8_t act[SHA3_TEST_MAX_DIGEST];
	struct esdm_hash_ctx *ctx = NULL;
	int ret = 0;

	memset(aligned, SHA3_TEST_MSG_BYTE, SHA3_TEST_MSG_LEN);
	ret += sha3_check(name, hash, "from an aligned buffer", aligned,
			  SHA3_TEST_MSG_LEN, NULL, exp, explen);

	memset(aligned + 1, SHA3_TEST_MSG_BYTE, SHA3_TEST_MSG_LEN);
	ret += sha3_check(name, hash, "from a misaligned buffer", aligned + 1,
			  SHA3_TEST_MSG_LEN, NULL, exp, explen);

	memset(aligned, SHA3_TEST_MSG_BYTE, SHA3_TEST_MSG_LEN);
	ret += sha3_check(name, hash, "in pieces", aligned, SHA3_TEST_MSG_LEN,
			  pieces, exp, explen);

	/* A message off by its first byte must not produce that digest */
	if (esdm_kat_modify(mod, aligned, sizeof(mod)) ||
	    esdm_hash_alloc(hash, &ctx)) {
		printf("%s: cannot set up the negative test\n", name);
		return 1;
	}
	esdm_hash_init(ctx);
	esdm_hash_update(ctx, mod, sizeof(mod));
	esdm_hash_set_digestsize(ctx, explen);
	esdm_hash_final(ctx, act);
	if (esdm_kat_check_differs(act, exp, explen)) {
		printf("%s: a different message gives the same digest\n", name);
		ret++;
	}
	esdm_hash_zero_free(ctx);

	if (!ret)
		printf("%s: passed\n", name);

	return ret ? 1 : 0;
}

int main(int argc, char *argv[])
{
	static const uint8_t abc[] = { 'a', 'b', 'c' };
	int ret = 0;

	(void)argc;
	(void)argv;

	ret += sha3_tester("SHA3-224", esdm_sha3_224, exp_224,
			   sizeof(exp_224));
	ret += sha3_tester("SHA3-256", esdm_sha3_256, exp_256,
			   sizeof(exp_256));
	ret += sha3_tester("SHA3-384", esdm_sha3_384, exp_384,
			   sizeof(exp_384));
	ret += sha3_tester("SHA3-512", esdm_sha3_512, exp_512,
			   sizeof(exp_512));
	ret += sha3_tester("SHAKE256", esdm_shake256, exp_shake256,
			   sizeof(exp_shake256));
	ret += sha3_check("SHA3-512", esdm_sha3_512, "\"abc\"", abc,
			  sizeof(abc), NULL, exp_512_abc, sizeof(exp_512_abc));

	return ret ? 1 : 0;
}
