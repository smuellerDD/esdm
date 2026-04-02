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

#ifndef ESDM_HASH_H
#define ESDM_HASH_H

#include <stdint.h>

#include "memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

struct esdm_hash_state;
struct esdm_hash {
	void (*init)(struct esdm_hash_state *ctx);
	void (*update)(struct esdm_hash_state *ctx, const uint8_t *in,
		       size_t inlen);
	void (*final)(struct esdm_hash_state *ctx, uint8_t *digest);
	void (*set_digestsize)(struct esdm_hash_state *ctx, size_t digestsize);
	size_t (*get_digestsize)(struct esdm_hash_state *ctx);
	unsigned int blocksize;
	unsigned int statesize;
};

struct esdm_hash_ctx {
	const struct esdm_hash *hash;
	struct esdm_hash_state *hash_state;
};

#define ESDM_ALIGNED_BUFFER(name, size, type)                                  \
	type name[(size + sizeof(type) - 1) / sizeof(type)]                    \
		__attribute__((aligned(sizeof(type))))

#define ESDM_SHA_MAX_SIZE_DIGEST 64
#define ESDM_HASH_STATE_SIZE(x) (x->statesize)
#define ESDM_HASH_CTX_SIZE(x)                                                  \
	(sizeof(struct esdm_hash_ctx) + ESDM_HASH_STATE_SIZE(x))

#define _ESDM_HASH_SET_CTX(name, hashname, ctx, offset)                        \
	name->hash_state =                                                     \
		(struct esdm_hash_state *)((uint8_t *)ctx + offset);           \
	name->hash = hashname

#define ESDM_HASH_SET_CTX(name, hashname)                                      \
	_ESDM_HASH_SET_CTX(name, hashname, name, sizeof(struct esdm_hash_ctx))

/**
 * @brief Initialize hash context
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 *
 * The caller must provide an allocated hash_ctx. This can be achieved by
 * using ESDM_HASH_CTX_ON_STACK or by using hash_alloc.
 */
static inline void esdm_hash_init(struct esdm_hash_ctx *hash_ctx)
{
	const struct esdm_hash *hash = hash_ctx->hash;

	hash->init(hash_ctx->hash_state);
}

/**
 * @brief Update hash
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 */
static inline void esdm_hash_update(struct esdm_hash_ctx *hash_ctx,
				    const uint8_t *in, size_t inlen)
{
	const struct esdm_hash *hash = hash_ctx->hash;

	hash->update(hash_ctx->hash_state, in, inlen);
}

/**
 * @brief Calculate message digest
 *
 * For SHAKE, it is permissible to calculate the final digest in chunks by
 * invoking the message digest calculation multiple times. Note, as the
 * digest calculation operates block-wise, you MUST operate the message digest
 * calculation also block-wise (or multiples of blocks). The following code
 * example illustrates it:
 *
 * ```
 * size_t outlen = full_size;
 *
 * esdm_hash_init(ctx);
 * esdm_hash_update(ctx, msg, msg_len);
 * esdm_hash_set_digestsize(ctx, ESDM_SHA3_256_SIZE_BLOCK);
 * for (len = outlen; len > 0;
 *      len -= esdm_hash_digestsize(ctx),
 *      out += esdm_hash_digestsize(ctx)) {
 *          if (len < esdm_hash_digestsize(ctx))
 *                  esdm_hash_set_digestsize(ctx, len);
 *          esdm_hash_final(ctx, out);
 * }
 * ```
 *
 * See the test `shake_squeeze_more_tester.c` for an example.
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 * @param [out] digest Buffer with at least the size of the message digest.
 */
static inline void esdm_hash_final(struct esdm_hash_ctx *hash_ctx,
				   uint8_t *digest)
{
	const struct esdm_hash *hash = hash_ctx->hash;

	hash->final(hash_ctx->hash_state, digest);
}

/**
 * @brief Set the size of the message digest - this call is intended for SHAKE
 *
 * @param [in] hash_ctx Reference to hash context implementation to be used to
 *			perform hash calculation with.
 * @param [in] digestsize Size of the requested digest.
 */
static inline void esdm_hash_set_digestsize(struct esdm_hash_ctx *hash_ctx,
					    size_t digestsize)
{
	const struct esdm_hash *hash = hash_ctx->hash;

	if (hash->set_digestsize)
		hash->set_digestsize(hash_ctx->hash_state, digestsize);
}

static inline size_t esdm_hash_digestsize(struct esdm_hash_ctx *hash_ctx)
{
	const struct esdm_hash *hash = hash_ctx->hash;

	return hash->get_digestsize(hash_ctx->hash_state);
}

static inline unsigned int esdm_hash_blocksize(struct esdm_hash_ctx *hash_ctx)
{
	const struct esdm_hash *hash = hash_ctx->hash;

	return hash->blocksize;
}

static inline unsigned int esdm_hash_ctxsize(struct esdm_hash_ctx *hash_ctx)
{
	const struct esdm_hash *hash = hash_ctx->hash;

	return hash->statesize;
}

/**
 * @brief Zeroize Hash context allocated with either ESDM_HASH_CTX_ON_STACK or
 *	  esdm_hmac_alloc
 *
 * @param [in] hash_state Hash context to be zeroized
 */
static inline void esdm_hash_zero(struct esdm_hash_ctx *hash_ctx)
{
	const struct esdm_hash *hash = hash_ctx->hash;

	memset_secure((uint8_t *)hash_ctx + sizeof(struct esdm_hash_ctx), 0,
		      hash->statesize);
}

/**
 * @brief Allocate stack memory for the hash context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hashname Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define ESDM_HASH_CTX_ON_STACK(name, hashname)                                 \
	ESDM_ALIGNED_BUFFER(name##_ctx_buf, ESDM_HASH_CTX_SIZE(hashname),      \
			    uint64_t);                                         \
	struct esdm_hash_ctx *name = (struct esdm_hash_ctx *)name##_ctx_buf;   \
	ESDM_HASH_SET_CTX(name, hashname);                                     \
	esdm_hash_zero(name)

/**
 * @brief Allocate Hash context on heap
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    hash calculation with.
 * @param [out] hash_ctx Allocated hash context
 *
 * @return: 0 on success, < 0 on error
 */
int esdm_hash_alloc(const struct esdm_hash *hash,
		    struct esdm_hash_ctx **hash_ctx);

/**
 * @brief Zeroize and free hash context
 *
 * @param [in] hash_ctx hash context to be zeroized and freed
 */
void esdm_hash_zero_free(struct esdm_hash_ctx *hash_ctx);

/**
 * @brief Calculate message digest - one-shot
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    hash calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 * @param [out] digest Buffer with at least the size of the message digest.
 *
 * The hash calculation operates entirely on the stack.
 */
static inline void esdm_hash(const struct esdm_hash *hash, const uint8_t *in,
			     size_t inlen, uint8_t *digest)
{
	ESDM_HASH_CTX_ON_STACK(hash_ctx, hash);

	esdm_hash_init(hash_ctx);
	esdm_hash_update(hash_ctx, in, inlen);
	esdm_hash_final(hash_ctx, digest);

	esdm_hash_zero(hash_ctx);
}

#ifdef __cplusplus
}
#endif

#endif /* ESDM_HASH_H */
