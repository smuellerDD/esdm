/*
 * Copyright (C) 2016 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#ifndef _ESDM_SYM_H
#define _ESDM_SYM_H

#include <stdint.h>

#include "memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

struct esdm_sym_state;
struct esdm_sym {
	void (*init)(struct esdm_sym_state *ctx);
	int (*setkey)(struct esdm_sym_state *ctx, uint8_t *key, size_t keylen);
	int (*setiv)(struct esdm_sym_state *ctx, uint8_t *iv, size_t ivlen);
	void (*encrypt)(struct esdm_sym_state *ctx, const uint8_t *in,
			uint8_t *out, size_t len);
	void (*decrypt)(struct esdm_sym_state *ctx, const uint8_t *in,
			uint8_t *out, size_t len);
	unsigned int statesize;
	unsigned int blocksize;
};

struct esdm_sym_ctx {
	const struct esdm_sym *sym;
	struct esdm_sym_state *sym_state;
};

#define ESDM_SYM_STATE_SIZE(x) (x->statesize)
#define ESDM_SYM_CTX_SIZE(x)                                                   \
	(sizeof(struct esdm_sym_ctx) + ESDM_SYM_STATE_SIZE(x))

/*
 * Align the esdm_sym_state structure to 8 bytes boundary irrespective where
 * it is embedded into. This is achieved by adding 7 more bytes than necessary
 * to ESDM_ALIGNED_SYM_BUFFER and then adjusting the pointer offset in that range
 * accordingly.
 *
 * TODO: make this adjustable with a esdm_sym->alignment setting - but the
 * question is which pre-processor macro to use to select the proper
 * ESDM_ALIGN_PTR_XX macro depending on esdm_sym->alignment during compile time.
 */
#define ESDM_SYM_ALIGNMENT(symname) (8)
#define ESDM_SYM_ALIGNMASK(symname) (ESDM_SYM_ALIGNMENT(symname) - 1)

#define ESDM_ALIGN_APPLY(x, mask) (((x) + (mask)) & ~(mask))
#define ESDM_ALIGN(x, a) ESDM_ALIGN_APPLY((x), (unsigned long)(a))
#define ESDM_ALIGN_PTR_64(p, a)                                                \
	((uint64_t *)ESDM_ALIGN((unsigned long)(p), (a)))
#define ESDM_ALIGN_PTR_32(p, a)                                                \
	((uint32_t *)ESDM_ALIGN((unsigned long)(p), (a)))
#define ESDM_ALIGN_PTR_16(p, a)                                                \
	((uint16_t *)ESDM_ALIGN((unsigned long)(p), (a)))
#define ESDM_ALIGN_PTR_8(p, a) ((uint8_t *)ESDM_ALIGN((unsigned long)(p), (a)))
#define ESDM_ALIGN_SYM_MASK(p, symname)                                        \
	ESDM_ALIGN_PTR_64(p, ESDM_SYM_ALIGNMASK(symname))

/**
 * Get aligned buffer with additional spare size of ESDM_SYM_ALIGNMASK to
 * ensure that the underlying symmetric algorithm implementation buffer is
 * aligned to proper size.
 */
#define ESDM_ALIGNED_SYM_BUFFER(name, symname, size, type)                     \
	type name[(size + ESDM_SYM_ALIGNMASK(symname) + sizeof(type) - 1) /    \
		  sizeof(type)] __attribute__((aligned(sizeof(type))))

#define _ESDM_SYM_SET_CTX(name, symname, ctx, offset)                          \
	name->sym_state = (struct esdm_sym_state *)ESDM_ALIGN_SYM_MASK(        \
		((uint8_t *)(ctx)) + (offset), symname);                       \
	name->sym = symname

#define ESDM_SYM_SET_CTX(name, symname)                                        \
	_ESDM_SYM_SET_CTX(name, symname, name, sizeof(struct esdm_sym_ctx))

/**
 * @brief Initialize symmetric context
 *
 * @param [in] sym_ctx Reference to sym context implementation to be used to
 *		       perform sym calculation with.
 *
 * The caller must provide an allocated sym_ctx. This can be achieved by
 * using LCSYM_CTX_ON_STACK or by using sym_alloc.
 */
static inline void esdm_sym_init(struct esdm_sym_ctx *ctx)
{
	const struct esdm_sym *sym = ctx->sym;

	sym->init(ctx->sym_state);
}

static inline int esdm_sym_setkey(struct esdm_sym_ctx *ctx, uint8_t *key,
				  size_t keylen)
{
	const struct esdm_sym *sym = ctx->sym;

	return sym->setkey(ctx->sym_state, key, keylen);
}

static inline int esdm_sym_setiv(struct esdm_sym_ctx *ctx, uint8_t *iv,
				 size_t ivlen)
{
	const struct esdm_sym *sym = ctx->sym;

	return sym->setiv(ctx->sym_state, iv, ivlen);
}

static inline void esdm_sym_encrypt(struct esdm_sym_ctx *ctx, uint8_t *in,
				    uint8_t *out, size_t len)
{
	const struct esdm_sym *sym = ctx->sym;

	sym->encrypt(ctx->sym_state, in, out, len);
}

static inline void esdm_sym_decrypt(struct esdm_sym_ctx *ctx, uint8_t *in,
				    uint8_t *out, size_t len)
{
	const struct esdm_sym *sym = ctx->sym;

	sym->decrypt(ctx->sym_state, in, out, len);
}

/**
 * @brief Zeroize Hash context allocated with either ESDM_HASH_CTX_ON_STACK or
 *	  esdm_hmac_alloc
 *
 * @param [in] ctx Hash context to be zeroized
 */
static inline void esdm_sym_zero(struct esdm_sym_ctx *ctx)
{
	const struct esdm_sym *sym = ctx->sym;

	memset_secure((uint8_t *)ctx + sizeof(struct esdm_sym_ctx), 0,
		      ESDM_SYM_STATE_SIZE(sym));
}

/**
 * @brief Allocate stack memory for the sym context
 *
 * @param [in] name Name of the stack variable
 * @param [in] symname Pointer of type struct sym referencing the sym
 *			 implementation to be used
 */
#define ESDM_SYM_CTX_ON_STACK(name, symname)                                   \
	ESDM_ALIGNED_SYM_BUFFER(name##_ctx_buf, symname,                       \
				ESDM_SYM_CTX_SIZE(symname), uint64_t);         \
	struct esdm_sym_ctx *name = (struct esdm_sym_ctx *)name##_ctx_buf;     \
	ESDM_SYM_SET_CTX(name, symname);                                       \
	esdm_sym_zero(name)

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_SYM_H */
