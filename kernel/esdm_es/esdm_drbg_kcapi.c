// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Backend for the ESDM providing the DRBG of the cryptographic post-processing
 * with memory (DRG.3) of the entropy sources: the XDRBG-256 of the ESDM over
 * the kernel's SHAKE256 where the kernel has its SHA-3 library, else the
 * HMAC_DRBG of the kernel crypto API.
 *
 * Taken and adapted from LRNG.
 *
 * Copyright (C) 2022-2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "esdm_definitions.h"

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/version.h>

#include "esdm_drbg_kcapi.h"
#include "esdm_drbg_string.h"

#if IS_ENABLED(CONFIG_CRYPTO_LIB_SHA3)

/*
 * The XDRBG-256 of the ESDM (esdm/crypto/esdm_xdrbg.c, compiled into the
 * module by esdm_xdrbg_shared.c) over the SHAKE256 of the kernel's SHA-3
 * library, with a security strength of 256 bits. The personalization string
 * and then the time stamps are inserted as the seed of the next extraction,
 * which reseeds - instantiates, the first time - and generates, with the
 * additional input as alpha of both.
 */

#include <crypto/sha3.h>
#include <linux/slab.h>

#include "esdm_portable.h"
#include "esdm_xdrbg.h"

/* Security strength of XDRBG-256 in bits */
#define ESDM_XDRBG_SEC_STRENGTH_BITS 256

static const char *esdm_shake256_name(void)
{
	return "shake256";
}

static int esdm_shake256_init(void *xof)
{
	shake256_init(xof);
	return 0;
}

static int esdm_shake256_update(void *xof, const u8 *inbuf, size_t inbuflen)
{
	shake_update(xof, inbuf, inbuflen);
	return 0;
}

static int esdm_shake256_final(void *xof, u8 *out, size_t outlen)
{
	shake_squeeze(xof, out, outlen);
	shake_zeroize_ctx(xof);
	return 0;
}

static int esdm_shake256_alloc(void **ctx)
{
	*ctx = kzalloc(sizeof(struct shake_ctx), GFP_KERNEL);
	return *ctx ? 0 : -ENOMEM;
}

static void esdm_shake256_dealloc(void *ctx)
{
	kfree_sensitive(ctx);
}

static const struct esdm_xof_cb esdm_kernel_shake256 = {
	.xof_name = esdm_shake256_name,
	.xof_init = esdm_shake256_init,
	.xof_update = esdm_shake256_update,
	.xof_final = esdm_shake256_final,
	.xof_alloc = esdm_shake256_alloc,
	.xof_dealloc = esdm_shake256_dealloc,
};
const struct esdm_xof_cb *esdm_default_xof_cb = &esdm_kernel_shake256;

struct esdm_kernel_xdrbg {
	struct esdm_xdrbg xdrbg;
	u8 *pers;
	u32 perslen;
};

static int esdm_drbg_seed_helper(void *drbg, struct list_head *seedlist)
{
	struct esdm_kernel_xdrbg *drbg_s = drbg;
	const struct drbg_string *s;
	int ret = 0;

	/* A new instantiation: its seed starts with the personalization */
	if (!esdm_xdrbg_started(&drbg_s->xdrbg) && drbg_s->perslen)
		CKINT(esdm_xdrbg_insert(&drbg_s->xdrbg, drbg_s->pers,
					drbg_s->perslen));

	list_for_each_entry(s, seedlist, list)
		CKINT(esdm_xdrbg_insert(&drbg_s->xdrbg, s->buf, s->len));

out:
	return ret;
}

static int esdm_drbg_generate_helper(void *drbg, u8 *outbuf, u32 outbuflen,
				     u8 *additional_data,
				     u32 additional_data_len)
{
	struct esdm_kernel_xdrbg *drbg_s = drbg;
	int ret;

	ret = esdm_xdrbg_extract(&drbg_s->xdrbg, additional_data,
				 additional_data_len, outbuf, outbuflen);

	return ret ? ret : outbuflen;
}

static void esdm_drbg_dealloc(void *drbg)
{
	struct esdm_kernel_xdrbg *drbg_s = drbg;

	esdm_xdrbg_free(&drbg_s->xdrbg);
	kfree_sensitive(drbg_s->pers);
	kfree_sensitive(drbg_s);
	pr_info("DRBG deallocated\n");
}

static void *esdm_drbg_alloc(u8 *personalization, u32 perslen)
{
	struct esdm_kernel_xdrbg *drbg_s;
	int ret;

	drbg_s = kzalloc(sizeof(*drbg_s), GFP_KERNEL);
	if (!drbg_s)
		return ERR_PTR(-ENOMEM);

	ret = esdm_xdrbg_alloc(&drbg_s->xdrbg);
	if (ret)
		goto err;

	if (perslen) {
		drbg_s->pers = kmemdup(personalization, perslen, GFP_KERNEL);
		if (!drbg_s->pers) {
			ret = -ENOMEM;
			goto err;
		}
		drbg_s->perslen = perslen;
	}

	pr_info("DRBG with xdrbg256 core allocated\n");

	return drbg_s;

err:
	esdm_drbg_dealloc(drbg_s);
	return ERR_PTR(ret);
}

static const char *esdm_drbg_name(void)
{
	return "xdrbg256";
}

static u32 esdm_drbg_sec_strength(void *drbg)
{
	if (!drbg)
		return 0;

	return ESDM_XDRBG_SEC_STRENGTH_BITS;
}

static int esdm_drbg_is_initialized(void *drbg)
{
	struct esdm_kernel_xdrbg *drbg_s = drbg;

	if (!drbg_s)
		return 0;

	return drbg_s->xdrbg.instantiated;
}

static const struct esdm_drbg_cb esdm_drbg_cb_int = {
	.drbg_name = esdm_drbg_name,
	.drbg_alloc = esdm_drbg_alloc,
	.drbg_dealloc = esdm_drbg_dealloc,
	.drbg_seed = esdm_drbg_seed_helper,
	.drbg_generate = esdm_drbg_generate_helper,
	.drbg_sec_strength = esdm_drbg_sec_strength,
	.drbg_is_initialized = esdm_drbg_is_initialized,
};
const struct esdm_drbg_cb *esdm_drbg_cb = &esdm_drbg_cb_int;

int esdm_drbg_selftest(void)
{
	int ret;

	/* check minimal security strength */
	if (ESDM_XDRBG_SEC_STRENGTH_BITS < esdm_security_strength()) {
		pr_warn("DRBG sec. strength insufficient for post-processing\n");
		return -EINVAL;
	}

	/* The known-answer test of the ESDM's XDRBG-256, on the kernel's XOF */
	ret = esdm_xdrbg_selftest();
	if (ret)
		pr_err("XDRBG-256 known-answer test failed: %d\n", ret);

	return ret;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(7, 2, 0)

/*
 * Without the kernel's SHA-3 library, up to Linux 7.1: the HMAC_DRBG with
 * SHA-512 of the kernel crypto API, whose security strength is 256 bits
 * according to SP800-57 section 5.6.1.
 */
#ifndef CONFIG_CRYPTO_DRBG_HMAC
#error "ESDM requires the HMAC_DRBG of the kernel (CONFIG_CRYPTO_DRBG_HMAC)"
#endif

#define ESDM_DRBG_CORE "drbg_nopr_hmac_sha512"

static int esdm_drbg_seed_helper(void *drbg, struct list_head *seedlist)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;
	int ret;

	ret = drbg_s->d_ops->update(drbg_s, seedlist,
				    drbg_s->seeded != DRBG_SEED_STATE_UNSEEDED);

	if (ret == 0)
		drbg_s->seeded = DRBG_SEED_STATE_FULL;

	return ret;
}

static int esdm_drbg_generate_helper(void *drbg, u8 *outbuf, u32 outbuflen,
				     u8 *additional_data,
				     u32 additional_data_len)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;
	struct drbg_string addtl;
	LIST_HEAD(addtllist);

	if (additional_data != NULL && additional_data_len > 0) {
		drbg_string_fill(&addtl, additional_data, additional_data_len);
		list_add_tail(&addtl.list, &addtllist);
		return drbg_s->d_ops->generate(drbg, outbuf, outbuflen,
					       &addtllist);
	} else {
		return drbg_s->d_ops->generate(drbg, outbuf, outbuflen, NULL);
	}
}

static void *esdm_drbg_alloc(u8 *personalization, u32 perslen)
{
	const u32 sec_strength = 32;
	struct drbg_state *drbg_s;
	struct drbg_string data;
	LIST_HEAD(seedlist);
	int coreref = -1;
	bool pr = false;
	int ret;

	drbg_convert_tfm_core(ESDM_DRBG_CORE, &coreref, &pr);
	if (coreref < 0)
		return ERR_PTR(-EFAULT);

	drbg_s = kvzalloc(sizeof(struct drbg_state), GFP_KERNEL);
	if (!drbg_s)
		return ERR_PTR(-ENOMEM);

	drbg_s->core = &drbg_cores[coreref];
	drbg_s->seeded = DRBG_SEED_STATE_UNSEEDED;
	ret = drbg_alloc_state(drbg_s);
	if (ret)
		goto err;

	/*
	 * The instantiation below is the update without reseed, which takes
	 * C as zero (SP800-90A 10.1.2.3 step 2). drbg_alloc_state() kmallocs
	 * V and C, which the kernel's own instantiation zeroes in drbg_seed()
	 * - bypassed here.
	 */
	memset(drbg_s->V, 0, drbg_statelen(drbg_s));
	memset(drbg_s->C, 0, drbg_statelen(drbg_s));

	if (sec_strength > drbg_sec_strength(drbg_s->core->flags)) {
		pr_err("Security strength of DRBG (%u bits) lower "
		       "than requested by ESDM (%u bits)\n",
		       drbg_sec_strength(drbg_s->core->flags) * 8,
		       sec_strength * 8);
		goto dealloc;
	}

	if (sec_strength < drbg_sec_strength(drbg_s->core->flags))
		pr_warn("Security strength of DRBG (%u bits) higher "
			"than requested by ESDM (%u bits)\n",
			drbg_sec_strength(drbg_s->core->flags) * 8,
			sec_strength * 8);

	drbg_string_fill(&data, personalization, perslen);
	list_add_tail(&data.list, &seedlist);
	ret = drbg_s->d_ops->update(drbg_s, &seedlist, 0);
	if (ret) {
		pr_warn("unable to add personalization string to DRBG instance\n");
		goto dealloc;
	}

	pr_info("DRBG with %s core allocated\n",
		drbg_s->core->backend_cra_name);

	return drbg_s;

dealloc:
	if (drbg_s->d_ops)
		drbg_s->d_ops->crypto_fini(drbg_s);
	drbg_dealloc_state(drbg_s);
err:
	kvfree(drbg_s);
	return ERR_PTR(-EINVAL);
}

static void esdm_drbg_dealloc(void *drbg)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;

	if (drbg && drbg_s->d_ops)
		drbg_s->d_ops->crypto_fini(drbg_s);
	drbg_dealloc_state(drbg);
	kvfree_sensitive(drbg, sizeof(struct drbg_state));
	pr_info("DRBG deallocated\n");
}

static const char *esdm_drbg_name(void)
{
	return ESDM_DRBG_CORE;
}

static u32 esdm_drbg_sec_strength(void *drbg)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;

	if (!drbg_s)
		return 0;

	return drbg_sec_strength(drbg_s->core->flags) * 8;
}

static int esdm_drbg_is_initialized(void *drbg)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;

	if (!drbg_s)
		return 0;

	return drbg_s->seeded == DRBG_SEED_STATE_FULL;
}

static const struct esdm_drbg_cb esdm_drbg_cb_int = {
	.drbg_name = esdm_drbg_name,
	.drbg_alloc = esdm_drbg_alloc,
	.drbg_dealloc = esdm_drbg_dealloc,
	.drbg_seed = esdm_drbg_seed_helper,
	.drbg_generate = esdm_drbg_generate_helper,
	.drbg_sec_strength = esdm_drbg_sec_strength,
	.drbg_is_initialized = esdm_drbg_is_initialized,
};
const struct esdm_drbg_cb *esdm_drbg_cb = &esdm_drbg_cb_int;

int esdm_drbg_selftest(void)
{
	struct crypto_rng *drbg = NULL;
	struct drbg_state *drbg_s;
	int ret = 0;

	/* Allocate the DRBG once to trigger the kernel crypto API self test */
	drbg = crypto_alloc_rng(ESDM_DRBG_CORE, 0, 0);
	if (IS_ERR(drbg)) {
		pr_err("could not allocate DRBG and trigger self-test: %ld\n",
		       PTR_ERR(drbg));
		ret = PTR_ERR(drbg);
		/*
		 * Clear the error pointer so the "if (drbg)" cleanup below does
		 * not pass an ERR_PTR to crypto_free_rng().
		 */
		drbg = NULL;
		goto out;
	}

	/* trigger initialization */
	if (crypto_rng_reset(drbg, (u8 *)"ABC", 3)) {
		ret = -EINVAL;
		pr_warn("DRBG reset failed\n");
		goto out;
	}

	/* convert to underlying drbg struct */
	drbg_s = crypto_rng_ctx(drbg);
	if (!drbg_s) {
		ret = -EINVAL;
		pr_warn("DRBG not accessible in self-test\n");
		goto out;
	}

	/* check minimal security strength */
	if (esdm_drbg_cb->drbg_sec_strength(drbg_s) <
	    esdm_security_strength()) {
		ret = -EINVAL;
		pr_warn("DRBG sec. strength insufficient for post-processing\n");
		goto out;
	}

out:
	if (drbg) {
		crypto_free_rng(drbg);
		drbg = NULL;
	}

	return ret;
}


#else

/*
 * Linux 7.2 reduced the kernel DRBG to a private HMAC_DRBG that cannot be
 * driven with ESDM's seed lists, so from then on the module needs the XDRBG
 * and with it the kernel's SHA-3 library.
 */
#error "ESDM requires the SHA-3 library of the kernel (CONFIG_CRYPTO_LIB_SHA3, selected by CONFIG_CRYPTO_SHA3)"

#endif
