// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Backend for the ESDM providing the cryptographic primitives using the
 * kernel crypto API and its DRBG.
 *
 * Taken and adapted from LRNG.
 *
 * Copyright (C) 2022-2025, Stephan Mueller <smueller@chronox.de>
 */

#include "esdm_definitions.h"
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

static int esdm_drbg_seed_helper(void* drbg, struct list_head *seedlist)
{
	struct drbg_state* drbg_s = (struct drbg_state*)drbg;
	int ret;

	ret = drbg_s->d_ops->update(drbg_s, seedlist, drbg_s->seeded != DRBG_SEED_STATE_UNSEEDED);

	if (ret >= 0)
		drbg_s->seeded = DRBG_SEED_STATE_FULL;

	return ret;
}

static int esdm_drbg_generate_helper(void* drbg, u8* outbuf, u32 outbuflen, u8* additional_data, u32 additional_data_len)
{
	struct drbg_state* drbg_s = (struct drbg_state*)drbg;
	struct drbg_string addtl;
	LIST_HEAD(addtllist);

	if (additional_data != NULL && additional_data_len > 0) {
		drbg_string_fill(&addtl, additional_data, additional_data_len);
		list_add_tail(&addtl.list, &addtllist);
		return drbg_s->d_ops->generate(drbg, outbuf, outbuflen, &addtllist);
	} else {
		return drbg_s->d_ops->generate(drbg, outbuf, outbuflen, NULL);
	}
}

static void* esdm_drbg_alloc(u8* personalization, u32 perslen)
{
	const u32 sec_strength = 32;
	struct drbg_state* drbg_s;
	struct drbg_string data;
	LIST_HEAD(seedlist);
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

	drbg_string_fill(&data, personalization, perslen);
	list_add_tail(&data.list, &seedlist);
	ret = drbg_s->d_ops->update(drbg_s, &seedlist, 0);
	if (ret) {
		pr_warn("unable to add personalization string to DRBG instance\n");
		goto dealloc;
	}

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

static u32 esdm_drbg_sec_strength(void *drbg)
{
	struct drbg_state* drbg_s = (struct drbg_state*)drbg;

	if (!drbg_s)
		return 0;

	return drbg_sec_strength(drbg_s->core->flags) * 8;
}

static const struct esdm_drbg_cb esdm_drbg_cb_int = {
	.drbg_name = esdm_drbg_name,
	.drbg_alloc = esdm_drbg_alloc,
	.drbg_dealloc = esdm_drbg_dealloc,
	.drbg_seed = esdm_drbg_seed_helper,
	.drbg_generate = esdm_drbg_generate_helper,
	.drbg_sec_strength = esdm_drbg_sec_strength,
};
const struct esdm_drbg_cb *esdm_drbg_cb = &esdm_drbg_cb_int;

int esdm_drbg_selftest(void)
{
	struct crypto_rng *drbg;
	struct drbg_state *drbg_s;
	int ret = 0;

	/* Allocate the DRBG once to trigger the kernel crypto API self test */
	drbg = crypto_alloc_rng(esdm_drbg_types[esdm_drbg_type].drbg_core, 0,
				0);
	if (IS_ERR(drbg)) {
		pr_err("could not allocate DRBG and trigger self-test: %ld\n",
		       PTR_ERR(drbg));
		ret = PTR_ERR(drbg);
		goto out;
	}

	if (crypto_rng_reset(drbg, (u8*)"ABC", 3)) {
		ret = -EINVAL;
		pr_warn("DRBG reset failed\n");
		goto out;
	}

	drbg_s = crypto_rng_ctx(drbg);
	if (!drbg_s) {
		ret = -EINVAL;
		pr_warn("DRBG not accesible in self-test\n");
		goto out;
	}

	/* check minimal security strength */
	if (esdm_drbg_cb->drbg_sec_strength(drbg_s) < esdm_security_strength()) {
		ret = -EINVAL;
		pr_warn("DRBG security strength insufficient for post-processing\n");
		goto out;
	}

out:
	if (drbg) {
		crypto_free_rng(drbg);
		drbg = NULL;
	}

	return ret;
}
