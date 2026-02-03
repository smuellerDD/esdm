/* Generic HMAC implementation
 *
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_hmac.h"
#include "visibility.h"

#define IPAD 0x36
#define OPAD 0x5c

DSO_PUBLIC
void esdm_hmac_reinit(struct esdm_hmac_ctx *hmac_ctx)
{
	struct esdm_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;

	esdm_hash_init(hash_ctx);
	esdm_hash_update(hash_ctx, hmac_ctx->k_ipad, esdm_hash_blocksize(hash_ctx));
}

DSO_PUBLIC
void esdm_hmac_init(struct esdm_hmac_ctx *hmac_ctx, const uint8_t *key,
		  size_t keylen)
{
	struct esdm_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	const struct esdm_hash *hash = hash_ctx->hash;
	uint8_t *k_opad, *k_ipad;
	unsigned int i;

	if (esdm_hash_ctxsize(hash_ctx) > ESDM_HASH_STATE_SIZE(hash) ||
	    esdm_hash_blocksize(hash_ctx) > ESDM_SHA_MAX_SIZE_BLOCK ||
	    esdm_hash_digestsize(hash_ctx) > ESDM_SHA_MAX_SIZE_DIGEST)
		return;

	k_opad = hmac_ctx->k_opad;
	k_ipad = hmac_ctx->k_ipad;

	if (keylen > esdm_hash_blocksize(hash_ctx)) {
		esdm_hash_init(hash_ctx);
		esdm_hash_update(hash_ctx, key, keylen);
		esdm_hash_final(hash_ctx, k_opad);
		memset(k_opad + esdm_hash_digestsize(hash_ctx), 0,
		       esdm_hash_blocksize(hash_ctx) -
			       esdm_hash_digestsize(hash_ctx));
	} else {
		memcpy(k_opad, key, keylen);
		memset(k_opad + keylen, 0,
		       esdm_hash_blocksize(hash_ctx) - keylen);
	}

	for (i = 0; i < esdm_hash_blocksize(hash_ctx); i++)
		k_ipad[i] = k_opad[i] ^ IPAD;

	for (i = 0; i < esdm_hash_blocksize(hash_ctx); i++)
		k_opad[i] ^= OPAD;

	esdm_hmac_reinit(hmac_ctx);
}

DSO_PUBLIC
void esdm_hmac_update(struct esdm_hmac_ctx *hmac_ctx, const uint8_t *in,
		    size_t inlen)
{
	struct esdm_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;

	esdm_hash_update(hash_ctx, in, inlen);
}

DSO_PUBLIC
void esdm_hmac_final(struct esdm_hmac_ctx *hmac_ctx, uint8_t *mac)
{
	struct esdm_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	uint8_t *k_opad = hmac_ctx->k_opad;

	esdm_hash_final(hash_ctx, mac);

	esdm_hash_init(hash_ctx);
	esdm_hash_update(hash_ctx, k_opad, esdm_hash_blocksize(hash_ctx));
	esdm_hash_update(hash_ctx, mac, esdm_hash_digestsize(hash_ctx));
	esdm_hash_final(hash_ctx, mac);
}

DSO_PUBLIC
int esdm_hmac_alloc(const struct esdm_hash *hash, struct esdm_hmac_ctx **hmac_ctx)
{
	struct esdm_hmac_ctx *out_ctx;
	int ret = posix_memalign((void *)&out_ctx, sizeof(uint64_t),
				 ESDM_HMAC_CTX_SIZE(hash));

	if (ret)
		return -ret;

	ESDM_HMAC_SET_CTX(out_ctx, hash);

	*hmac_ctx = out_ctx;

	return 0;
}

DSO_PUBLIC
void esdm_hmac_zero_free(struct esdm_hmac_ctx *hmac_ctx)
{
	if (!hmac_ctx)
		return;

	esdm_hmac_zero(hmac_ctx);
	free(hmac_ctx);
}
