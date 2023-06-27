// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Backend for providing the hash primitive using the kernel crypto API.
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <linux/module.h>

#include "esdm_hash_kcapi.h"

static char *esdm_hash_name = "sha512";

/* The parameter must be r/o in sysfs as otherwise races appear. */
module_param(esdm_hash_name, charp, 0444);
MODULE_PARM_DESC(esdm_hash_name, "Kernel crypto API hash name");

struct esdm_hash_info {
	struct crypto_shash *tfm;
};

static const char *esdm_kcapi_hash_name(void)
{
	return esdm_hash_name;
}

static void _esdm_kcapi_hash_free(struct esdm_hash_info *esdm_hash)
{
	struct crypto_shash *tfm = esdm_hash->tfm;

	crypto_free_shash(tfm);
	kfree(esdm_hash);
}

static void *esdm_kcapi_hash_alloc(const char *name)
{
	struct esdm_hash_info *esdm_hash;
	struct crypto_shash *tfm;
	int ret;

	if (!name) {
		pr_err("Hash name missing\n");
		return ERR_PTR(-EINVAL);
	}

	tfm = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("could not allocate hash %s\n", name);
		return ERR_CAST(tfm);
	}

	ret = sizeof(struct esdm_hash_info);
	esdm_hash = kmalloc(ret, GFP_KERNEL);
	if (!esdm_hash) {
		crypto_free_shash(tfm);
		return ERR_PTR(-ENOMEM);
	}

	esdm_hash->tfm = tfm;

	pr_info("Hash %s allocated\n", name);

	return esdm_hash;
}

static void *esdm_kcapi_hash_name_alloc(void)
{
	return esdm_kcapi_hash_alloc(esdm_kcapi_hash_name());
}

static u32 esdm_kcapi_hash_digestsize(void *hash)
{
	struct esdm_hash_info *esdm_hash = (struct esdm_hash_info *)hash;
	struct crypto_shash *tfm = esdm_hash->tfm;

	return crypto_shash_digestsize(tfm);
}

static void esdm_kcapi_hash_dealloc(void *hash)
{
	struct esdm_hash_info *esdm_hash = (struct esdm_hash_info *)hash;

	_esdm_kcapi_hash_free(esdm_hash);
	pr_info("Hash deallocated\n");
}

static int esdm_kcapi_hash_init(struct shash_desc *shash, void *hash)
{
	struct esdm_hash_info *esdm_hash = (struct esdm_hash_info *)hash;
	struct crypto_shash *tfm = esdm_hash->tfm;

	shash->tfm = tfm;
	return crypto_shash_init(shash);
}

static int esdm_kcapi_hash_update(struct shash_desc *shash, const u8 *inbuf,
			   u32 inbuflen)
{
	return crypto_shash_update(shash, inbuf, inbuflen);
}

static int esdm_kcapi_hash_final(struct shash_desc *shash, u8 *digest)
{
	return crypto_shash_final(shash, digest);
}

static void esdm_kcapi_hash_zero(struct shash_desc *shash)
{
	shash_desc_zero(shash);
}

static const struct esdm_hash_cb _esdm_kcapi_hash_cb = {
	.hash_name		= esdm_kcapi_hash_name,
	.hash_alloc		= esdm_kcapi_hash_name_alloc,
	.hash_dealloc		= esdm_kcapi_hash_dealloc,
	.hash_digestsize	= esdm_kcapi_hash_digestsize,
	.hash_init		= esdm_kcapi_hash_init,
	.hash_update		= esdm_kcapi_hash_update,
	.hash_final		= esdm_kcapi_hash_final,
	.hash_desc_zero		= esdm_kcapi_hash_zero,
};
const struct esdm_hash_cb *esdm_kcapi_hash_cb = &_esdm_kcapi_hash_cb;
