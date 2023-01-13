/*
 * Backend for the ESDM providing the SHA-512 implementation.
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>

#include "config.h"
#include "esdm_crypto.h"
#include "esdm_builtin_sha512.h"
#include "lc_sha512.h"
#include "lc_sha3.h"
#include "ret_checkers.h"

static uint32_t esdm_sha512_hash_digestsize(void *hash)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	return (uint32_t)lc_hash_digestsize(hash_ctx);
}

static int esdm_sha512_hash_init(void *hash)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

#if defined(ESDM_HASH_SHA512)
	LC_HASH_SET_CTX(hash_ctx, lc_sha512);
#elif defined(ESDM_HASH_SHA3_512)
	LC_HASH_SET_CTX(hash_ctx, lc_sha3_512);
#else
#error "Unknown default hash selected"
#endif

	lc_hash_init(hash_ctx);
	return 0;
}

static int
esdm_sha512_hash_update(void *hash, const uint8_t *inbuf, size_t inbuflen)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	lc_hash_update(hash_ctx, inbuf, inbuflen);
	return 0;
}

static int esdm_sha512_hash_final(void *hash, uint8_t *digest)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	lc_hash_final(hash_ctx, digest);
	return 0;
}

static const char *esdm_sha512_hash_name(void)
{
#if defined(ESDM_HASH_SHA512)
	return "builtin SHA-512";
#elif defined(ESDM_HASH_SHA3_512)
	return "builtin SHA3-512";
#else
#error "Unknown default hash selected"
#endif
}

static void esdm_sha512_hash_desc_zero(void *hash)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	lc_hash_zero(hash_ctx);
}

static int esdm_sha512_hash_alloc_common(const struct lc_hash *hash, void **ctx)
{
	struct lc_hash_ctx *ctx512;
	int ret;

	CKINT(lc_hash_alloc(hash, &ctx512));

	*ctx = ctx512;

out:
	return ret;
}

static void esdm_sha512_hash_dealloc(void *ctx)
{
	lc_hash_zero_free(ctx);
}

#if defined(ESDM_HASH_SHA512)

static int esdm_sha512_hash_selftest(void)
{
	LC_HASH_CTX_ON_STACK(ctx, lc_sha512);
	static const uint8_t msg_512[] = { 0x7F, 0xAD, 0x12 };
	static const uint8_t exp_512[] = { 0x53, 0x35, 0x98, 0xe5, 0x29, 0x49,
					   0x18, 0xa0, 0xaf, 0x4b, 0x3a, 0x62,
					   0x31, 0xcb, 0xd7, 0x19, 0x21, 0xdb,
					   0x80, 0xe1, 0x00, 0xa0, 0x74, 0x95,
					   0xb4, 0x44, 0xc4, 0x7a, 0xdb, 0xbc,
					   0x9a, 0x64, 0x76, 0xbb, 0xc8, 0xdb,
					   0x8e, 0xe3, 0x0c, 0x87, 0x2f, 0x11,
					   0x35, 0xf1, 0x64, 0x65, 0x9c, 0x52,
					   0xce, 0xc7, 0x7c, 0xcf, 0xb8, 0xc7,
					   0xd8, 0x57, 0x63, 0xda, 0xee, 0x07,
					   0x9f, 0x60, 0x0c, 0x79 };
	uint8_t act[LC_SHA512_SIZE_DIGEST];
	int ret = 0;

	lc_hash_init(ctx);
	lc_hash_update(ctx, msg_512, 3);
	lc_hash_final(ctx, act);
	if (memcmp(act, exp_512, LC_SHA512_SIZE_DIGEST))
		ret = -EFAULT;

	lc_hash_zero(ctx);
	return ret;
}

static int esdm_sha512_hash_alloc(void **ctx)
{
	return (esdm_sha512_hash_alloc_common(lc_sha512, ctx));
}

#elif defined(ESDM_HASH_SHA3_512)

static int esdm_sha512_hash_selftest(void)
{
	LC_HASH_CTX_ON_STACK(ctx, lc_sha3_512);
	static const uint8_t msg_512[] = { 0x82, 0xD9, 0x19 };
	static const uint8_t exp_512[] = { 0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5,
					   0x0A, 0x67, 0xFE, 0x69, 0xBD, 0x3F,
					   0xCE, 0xFE, 0x12, 0xE7, 0x1D, 0xE0,
					   0x4F, 0xA2, 0x51, 0xC6, 0x7E, 0x9C,
					   0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC,
					   0x89, 0xCA, 0x9B, 0x28, 0x88, 0x3B,
					   0x2A, 0xDB, 0x22, 0x84, 0x69, 0x5D,
					   0xD0, 0x43, 0x77, 0x55, 0x32, 0x19,
					   0xC8, 0xFD, 0x07, 0xA9, 0x4C, 0x29,
					   0xD7, 0x46, 0xCC, 0xEF, 0xB1, 0x09,
					   0x6E, 0xDE, 0x42, 0x91 };
	uint8_t act[LC_SHA3_512_SIZE_DIGEST];
	int ret = 0;

	lc_hash_init(ctx);
	lc_hash_update(ctx, msg_512, 3);
	lc_hash_final(ctx, act);
	if (memcmp(act, exp_512, LC_SHA3_512_SIZE_DIGEST))
		ret = -EFAULT;

	lc_hash_zero(ctx);
	return ret;
}

static int esdm_sha512_hash_alloc(void **ctx)
{
	return (esdm_sha512_hash_alloc_common(lc_sha3_512, ctx));
}

#endif

const struct esdm_hash_cb esdm_builtin_sha512_cb = {
	.hash_name		= esdm_sha512_hash_name,
	.hash_selftest		= esdm_sha512_hash_selftest,
	.hash_digestsize	= esdm_sha512_hash_digestsize,
	.hash_init		= esdm_sha512_hash_init,
	.hash_update		= esdm_sha512_hash_update,
	.hash_final		= esdm_sha512_hash_final,
	.hash_desc_zero		= esdm_sha512_hash_desc_zero,
	.hash_alloc		= esdm_sha512_hash_alloc,
	.hash_dealloc		= esdm_sha512_hash_dealloc
};
