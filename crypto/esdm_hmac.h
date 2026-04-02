/*
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

#ifndef ESDM_HMAC_H
#define ESDM_HMAC_H

#include "esdm_hash.h"
#include "esdm_sha3.h"
#include "memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ESDM_SHA3_MAX_SIZE_BLOCK
#define ESDM_SHA_MAX_SIZE_BLOCK ESDM_SHA3_MAX_SIZE_BLOCK
#elif ESDM_SHA512_SIZE_BLOCK
#define ESDM_SHA_MAX_SIZE_BLOCK ESDM_SHA512_SIZE_BLOCK
#elif ESDM_SHA256_SIZE_BLOCK
#define ESDM_SHA_MAX_SIZE_BLOCK ESDM_SHA256_SIZE_BLOCK
#else
#error "No known maximum block size defined - include sha3.h, sha512.h or sha256.h before hmac.h"
#endif

struct esdm_hmac_ctx {
	uint8_t *k_opad;
	uint8_t *k_ipad;
	struct esdm_hash_ctx hash_ctx;
};

#define ESDM_HMAC_STATE_SIZE(x)                                                  \
	(ESDM_HASH_STATE_SIZE(x) + 2 * ESDM_SHA_MAX_SIZE_BLOCK)
#define ESDM_HMAC_CTX_SIZE(x) (ESDM_HMAC_STATE_SIZE(x) + sizeof(struct esdm_hmac_ctx))

#define _ESDM_HMAC_SET_CTX(name, hashname, ctx, offset)                          \
	_ESDM_HASH_SET_CTX((&name->hash_ctx), hashname, ctx, offset);            \
	name->k_opad = (uint8_t *)((uint8_t *)ctx + offset +                   \
				   ESDM_HASH_STATE_SIZE(hashname));              \
	name->k_ipad = (uint8_t *)((uint8_t *)ctx + offset +                   \
				   ESDM_HASH_STATE_SIZE(hashname) +              \
				   ESDM_SHA_MAX_SIZE_BLOCK)

#define ESDM_HMAC_SET_CTX(name, hashname)                                        \
	_ESDM_HMAC_SET_CTX(name, hashname, name, sizeof(struct esdm_hmac_ctx))

/**
 * @brief Initialize HMAC context
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param [in] key MAC key of arbitrary size
 * @param [in] keylen Size of the MAC key
 *
 * The caller must provide an allocated hmac_ctx. This can be achieved by
 * using HMAC_CTX_ON_STACK or by using hmac_alloc.
 */
void esdm_hmac_init(struct esdm_hmac_ctx *hmac_ctx, const uint8_t *key,
		  size_t keylen);

/**
 * @brief Re-initialize HMAC context after a hmac_final operation
 *
 * This operation allows the HMAC context to be used again with the same key
 * set during hmac_init.
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 */
void esdm_hmac_reinit(struct esdm_hmac_ctx *hmac_ctx);

/**
 * @brief Update HMAC
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 */
void esdm_hmac_update(struct esdm_hmac_ctx *hmac_ctx, const uint8_t *in,
		    size_t inlen);

/**
 * @brief Calculate HMAC mac
 *
 * If the cipher handle shall be used for a new HMAC operation with the same
 * key after this call, you MUST re-initialize the handle with hmac_reinit.
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param [out] mac Buffer with at least the size of the message digest that
 *		    is returned by hmac_macsize.
 */
void esdm_hmac_final(struct esdm_hmac_ctx *hmac_ctx, uint8_t *mac);

/**
 * @brief Allocate HMAC context on heap
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    HMAC calculation with.
 * @param [out] hmac_ctx Allocated HMAC context
 *
 * @return 0 on success, < 0 on error
 */
int esdm_hmac_alloc(const struct esdm_hash *hash, struct esdm_hmac_ctx **hmac_ctx);

/**
 * @brief Zeroize and free HMAC context
 *
 * @param [in] hmac_ctx HMAC context to be zeroized and freed
 */
void esdm_hmac_zero_free(struct esdm_hmac_ctx *hmac_ctx);

/**
 * @brief Zeroize HMAC context allocated with either HMAC_CTX_ON_STACK or
 *	  hmac_alloc
 *
 * @param [in] hmac_ctx HMAC context to be zeroized
 */
static inline void esdm_hmac_zero(struct esdm_hmac_ctx *hmac_ctx)
{
	struct esdm_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	const struct esdm_hash *hash = hash_ctx->hash;

	memset_secure((uint8_t *)hmac_ctx + sizeof(struct esdm_hmac_ctx), 0,
		      ESDM_HMAC_STATE_SIZE(hash));
}

/**
 * @brief Allocate stack memory for the HMAC context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hashname Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define ESDM_HMAC_CTX_ON_STACK(name, hashname)                                   \
	ESDM_ALIGNED_BUFFER(name##_ctx_buf, ESDM_HMAC_CTX_SIZE(hashname),          \
			  uint64_t);                                           \
	struct esdm_hmac_ctx *name = (struct esdm_hmac_ctx *)name##_ctx_buf;       \
	ESDM_HMAC_SET_CTX(name, hashname);                                       \
	esdm_hmac_zero(name)

/**
 * @brief Return the MAC size
 *
 * @param [in] hmac_ctx HMAC context to be zeroized
 *
 * @return MAC size
 */
static inline size_t esdm_hmac_macsize(struct esdm_hmac_ctx *hmac_ctx)
{
	struct esdm_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;

	return esdm_hash_digestsize(hash_ctx);
}

/**
 * @brief Calculate HMAC - one-shot
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    HMAC calculation with.
 * @param [in] key MAC key of arbitrary size
 * @param [in] keylen Size of the MAC key
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 * @param [out] mac Buffer with at least the size of the message digest.
 *
 * The HMAC calculation operates entirely on the stack.
 */
static inline void esdm_hmac(const struct esdm_hash *hash, const uint8_t *key,
			   size_t keylen, const uint8_t *in, size_t inlen,
			   uint8_t *mac)
{
	ESDM_HMAC_CTX_ON_STACK(hmac_ctx, hash);

	esdm_hmac_init(hmac_ctx, key, keylen);
	esdm_hmac_update(hmac_ctx, in, inlen);
	esdm_hmac_final(hmac_ctx, mac);

	esdm_hmac_zero(hmac_ctx);
}

#ifdef __cplusplus
}
#endif

#endif /* ESDM_HMAC_H */
