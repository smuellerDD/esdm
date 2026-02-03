// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Hash heap memory management
 *
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "esdm_hash.h"
#include "visibility.h"

DSO_PUBLIC
int esdm_hash_alloc(const struct esdm_hash *hash,
		    struct esdm_hash_ctx **hash_ctx)
{
	struct esdm_hash_ctx *out_ctx;
	int ret = posix_memalign((void *)&out_ctx, sizeof(uint64_t),
				 ESDM_HASH_CTX_SIZE(hash));

	if (ret)
		return -ret;

	ESDM_HASH_SET_CTX(out_ctx, hash);

	*hash_ctx = out_ctx;

	return 0;
}

DSO_PUBLIC
void esdm_hash_zero_free(struct esdm_hash_ctx *hash_ctx)
{
	if (!hash_ctx)
		return;

	esdm_hash_zero(hash_ctx);
	free(hash_ctx);
}
