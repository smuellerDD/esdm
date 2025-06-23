// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Backend for the ESDM providing the cryptographic primitives using the
 * kernel crypto API and its DRBG.
 *
 * Taken and adapted from LRNG.
 *
 * Copyright (C) 2022-2025, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/drbg.h>
#include <linux/init.h>
#include <linux/module.h>

#include "esdm_drbg_kcapi.h"

/*
 * Define a DRBG used to extract data from the entropy pool.
 *
 * The security strengths of the DRBGs are all 256 bits according to
 * SP800-57 section 5.6.1.
 *
 * This definition is allowed to be changed.
 */
#ifdef CONFIG_CRYPTO_DRBG_HMAC
static unsigned int esdm_drbg_type = 0;
#elif defined CONFIG_CRYPTO_DRBG_HASH
static unsigned int esdm_drbg_type = 1;
#elif defined CONFIG_CRYPTO_DRBG_CTR
static unsigned int esdm_drbg_type = 2;
#else
#error "Unknown DRBG in use"
#endif

/* The parameter must be r/o in sysfs as otherwise races appear. */
module_param(esdm_drbg_type, uint, 0444);
MODULE_PARM_DESC(esdm_drbg_type, "DRBG type used for ESDM (0->HMAC_DRBG, 1->Hash_DRBG, 2->CTR_DRBG)");

struct esdm_drbg {
	const char* hash_name;
	const char* drbg_core;
};

static const struct esdm_drbg esdm_drbg_types[] = {
	{
		/* HMAC_DRBG with SHA-512 */
		.drbg_core = "drbg_nopr_hmac_sha512",
	},
	{
		/* Hash_DRBG with SHA-512 using derivation function */
		.drbg_core = "drbg_nopr_sha512"
	},
	{
		/* CTR_DRBG with AES-256 using derivation function */
		.drbg_core = "drbg_nopr_ctr_aes256",
	}
};

static int esdm_drbg_seed_helper(void* drbg, const u8* inbuf, u32 inbuflen)
{
	struct drbg_state* drbg_s = (struct drbg_state*)drbg;
	LIST_HEAD(seedlist);
	struct drbg_string data;
	int ret;

	drbg_string_fill(&data, inbuf, inbuflen);
	list_add_tail(&data.list, &seedlist);
	ret = drbg_s->d_ops->update(drbg, &seedlist, drbg_s->seeded);

	if (ret >= 0)
		drbg_s->seeded = DRBG_SEED_STATE_FULL;

	return ret;
}

static int esdm_drbg_generate_helper(void* drbg, u8* outbuf, u32 outbuflen)
{
	struct drbg_state* drbg_s = (struct drbg_state*)drbg;

	return drbg_s->d_ops->generate(drbg, outbuf, outbuflen, NULL);
}

static void* esdm_drbg_alloc(void)
{
	const u32 sec_strength = 32;
	struct drbg_state* drbg_s;
	int coreref = -1;
	bool pr = false;
	int ret;

	drbg_convert_tfm_core(esdm_drbg_types[esdm_drbg_type].drbg_core,
			      &coreref, &pr);
	if (coreref < 0)
		return ERR_PTR(-EFAULT);

	drbg_s = kzalloc(sizeof(struct drbg_state), GFP_KERNEL);
	if (!drbg_s)
		return ERR_PTR(-ENOMEM);

	drbg_s->core = &drbg_cores[coreref];
	drbg_s->seeded = DRBG_SEED_STATE_UNSEEDED;
	ret = drbg_alloc_state(drbg_s);
	if (ret)
		goto err;

	if (sec_strength > drbg_sec_strength(drbg_s->core->flags)) {
		pr_err("Security strength of DRBG (%u bits) lower than requested by ESDM (%u bits)\n",
		       drbg_sec_strength(drbg_s->core->flags) * 8,
		       sec_strength * 8);
		goto dealloc;
	}

	if (sec_strength < drbg_sec_strength(drbg_s->core->flags))
		pr_warn("Security strength of DRBG (%u bits) higher than requested by ESDM (%u bits)\n",
			drbg_sec_strength(drbg_s->core->flags) * 8,
			sec_strength * 8);

	pr_info("DRBG with %s core allocated\n", drbg_s->core->backend_cra_name);

	return drbg_s;

dealloc:
	if (drbg_s->d_ops)
		drbg_s->d_ops->crypto_fini(drbg_s);
	drbg_dealloc_state(drbg_s);
err:
	kfree(drbg_s);
	return ERR_PTR(-EINVAL);
}

static void esdm_drbg_dealloc(void* drbg)
{
	struct drbg_state* drbg_s = (struct drbg_state*)drbg;

	if (drbg && drbg_s->d_ops)
		drbg_s->d_ops->crypto_fini(drbg_s);
	drbg_dealloc_state(drbg);
	kfree_sensitive(drbg);
	pr_info("DRBG deallocated\n");
}

static const char* esdm_drbg_name(void)
{
	return esdm_drbg_types[esdm_drbg_type].drbg_core;
}

static int esdm_drbg_is_fully_seeded(void* drbg)
{
	struct drbg_state* drbg_s = (struct drbg_state*)drbg;

	if (drbg && drbg_s->d_ops)
		return drbg_s->seeded == DRBG_SEED_STATE_FULL;

	return -EINVAL;
}

static const struct esdm_drbg_cb esdm_drbg_cb_int = {
	.drbg_name = esdm_drbg_name,
	.drbg_alloc = esdm_drbg_alloc,
	.drbg_dealloc = esdm_drbg_dealloc,
	.drbg_seed = esdm_drbg_seed_helper,
	.drbg_generate = esdm_drbg_generate_helper,
	.drbg_is_fully_seeded = esdm_drbg_is_fully_seeded,
};
const struct esdm_drbg_cb *esdm_drbg_cb = &esdm_drbg_cb_int;

int esdm_drbg_selftest(void)
{
	struct crypto_rng *drbg;

	/* Allocate the DRBG once to trigger the kernel crypto API self test */
	drbg = crypto_alloc_rng(esdm_drbg_types[esdm_drbg_type].drbg_core, 0,
				0);
	if (IS_ERR(drbg)) {
		pr_err("could not allocate DRBG and trigger self-test: %ld\n",
		       PTR_ERR(drbg));
		return PTR_ERR(drbg);
	}
	crypto_free_rng(drbg);

	return 0;
}
