/*
 * Backend for the ESDM providing the SHAKE256 implementation.
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

#include "esdm_builtin_shake256.h"
#include "esdm_crypto.h"
#include "esdm_sha3.h"
#include "ret_checkers.h"

static int esdm_shake256_xof_init(void *xof)
{
	struct esdm_hash_ctx *hash_ctx = (struct esdm_hash_ctx *)xof;

	esdm_hash_init(hash_ctx);
	return 0;
}

static int esdm_shake256_xof_update(void *xof, const uint8_t *inbuf,
				    size_t inbuflen)
{
	struct esdm_hash_ctx *hash_ctx = (struct esdm_hash_ctx *)xof;

	esdm_hash_update(hash_ctx, inbuf, inbuflen);
	return 0;
}

static int esdm_shake256_xof_final(void *xof, uint8_t *out, size_t outlen)
{
	struct esdm_hash_ctx *hash_ctx = (struct esdm_hash_ctx *)xof;

	esdm_hash_set_digestsize(hash_ctx, outlen);
	esdm_hash_final(hash_ctx, out);
	return 0;
}

static int esdm_shake256_xof_alloc(void **ctx)
{
	struct esdm_hash_ctx *hash_ctx;
	int ret;

	CKINT(esdm_hash_alloc(esdm_shake256, &hash_ctx));
	esdm_hash_zero(hash_ctx);
	*ctx = hash_ctx;

out:
	return ret;
}

static void esdm_shake256_xof_dealloc(void *ctx)
{
	esdm_hash_zero_free(ctx);
}

static const char *esdm_shake256_xof_name(void)
{
	return "builtin SHAKE256";
}

const struct esdm_xof_cb esdm_builtin_shake256_cb = {
	.xof_name = esdm_shake256_xof_name,
	.xof_init = esdm_shake256_xof_init,
	.xof_update = esdm_shake256_xof_update,
	.xof_final = esdm_shake256_xof_final,
	.xof_alloc = esdm_shake256_xof_alloc,
	.xof_dealloc = esdm_shake256_xof_dealloc,
};
