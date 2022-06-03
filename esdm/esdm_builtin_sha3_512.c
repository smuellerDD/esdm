/*
 * Backend for the ESDM providing the SHA-3_512 implementation.
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

#include "esdm_crypto.h"
#include "esdm_builtin_sha3_512.h"
#include "lc_sha3.h"

static uint32_t esdm_sha3_512_hash_digestsize(void *hash)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	return (uint32_t)lc_hash_digestsize(hash_ctx);
}

static int esdm_sha3_512_hash_init(void *hash)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	LC_HASH_SET_CTX(hash_ctx, lc_sha3_512);
	lc_hash_init(hash_ctx);
	return 0;
}

static int
esdm_sha3_512_hash_update(void *hash, const uint8_t *inbuf, size_t inbuflen)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	lc_hash_update(hash_ctx, inbuf, inbuflen);
	return 0;
}

static int esdm_sha3_512_hash_final(void *hash, uint8_t *digest)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	lc_hash_final(hash_ctx, digest);
	return 0;
}

static const char *esdm_sha3_512_hash_name(void)
{
	return "builtin SHA3-512";
}

static void esdm_sha3_512_hash_desc_zero(void *hash)
{
	struct lc_hash_ctx *hash_ctx = (struct lc_hash_ctx *)hash;

	lc_hash_zero(hash_ctx);
}

static int esdm_sha3_512_hash_selftest(void)
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

const struct esdm_hash_cb esdm_builtin_sha3_512_cb = {
	.hash_name		= esdm_sha3_512_hash_name,
	.hash_selftest		= esdm_sha3_512_hash_selftest,
	.hash_digestsize	= esdm_sha3_512_hash_digestsize,
	.hash_init		= esdm_sha3_512_hash_init,
	.hash_update		= esdm_sha3_512_hash_update,
	.hash_final		= esdm_sha3_512_hash_final,
	.hash_desc_zero		= esdm_sha3_512_hash_desc_zero,
};
