/*
 * Backend for the ESDM providing the SHA-256 implementation.
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
#include "esdm_builtin_sha256.h"
#include "builtin/sha256.h"
#include "logger.h"

static uint32_t esdm_sha256_hash_digestsize(void *hash)
{
	(void)hash;
	return sha256->digestsize;
}

static int esdm_sha256_hash_init(void *hash)
{
	struct hash_ctx *hash_ctx = (struct hash_ctx *)hash;

	sha256->init(hash_ctx);
	return 0;
}

static int
esdm_sha256_hash_update(void *hash, const uint8_t *inbuf, size_t inbuflen)
{
	struct hash_ctx *hash_ctx = (struct hash_ctx *)hash;

	sha256->update(hash_ctx, inbuf, inbuflen);
	return 0;
}

static int esdm_sha256_hash_final(void *hash, uint8_t *digest)
{
	struct hash_ctx *hash_ctx = (struct hash_ctx *)hash;

	sha256->final(hash_ctx, digest);
	return 0;
}

static const char *esdm_sha256_hash_name(void)
{
	return "builtin SHA-256";
}

static void esdm_sha256_hash_desc_zero(void *hash)
{
	struct hash_ctx *hash_ctx = (struct hash_ctx *)hash;

	hash_zero(hash_ctx);
}


static int esdm_sha256_hash_selftest(void)
{
	HASH_CTX_ON_STACK(ctx);
	static const uint8_t msg_256[] = { 0x06, 0x3A, 0x53 };
	static const uint8_t exp_256[] = { 0x8b, 0x05, 0x65, 0x59, 0x60, 0x71,
					   0xc7, 0x6e, 0x35, 0xe1, 0xea, 0x54,
					   0x48, 0x39, 0xe6, 0x47, 0x27, 0xdf,
					   0x89, 0xb4, 0xde, 0x27, 0x74, 0x44,
					   0xa7, 0x7f, 0x77, 0xcb, 0x97, 0x89,
					   0x6f, 0xf4 };
	uint8_t act[SHA256_SIZE_DIGEST];
	int ret = 0;

	sha256->init(ctx);
	sha256->update(ctx, msg_256, 3);
	sha256->final(ctx, act);
	if (memcmp(act, exp_256, SHA256_SIZE_DIGEST))
		ret = -EFAULT;

	hash_zero(ctx);
	return ret;
}


const struct esdm_hash_cb esdm_builtin_sha256_cb = {
	.hash_name		= esdm_sha256_hash_name,
	.hash_selftest		= esdm_sha256_hash_selftest,
	.hash_digestsize	= esdm_sha256_hash_digestsize,
	.hash_init		= esdm_sha256_hash_init,
	.hash_update		= esdm_sha256_hash_update,
	.hash_final		= esdm_sha256_hash_final,
	.hash_desc_zero		= esdm_sha256_hash_desc_zero,
};
