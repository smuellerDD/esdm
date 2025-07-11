/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM SP800-90A definitions
 *
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_DRBG_KCAPI_H
#define _ESDM_DRBG_KCAPI_H

/*
 * struct esdm_drbg_cb - cryptographic callback functions defining a drbg
 * @drbg_name		Name of drbg
 * @drbg_alloc:		Allocate drbg -- the provided integer should be used for
 *			sanity checks.
 *			return: allocated data structure or PTR_ERR on error
 * @drbg_dealloc:	Deallocate drbg
 * @drbg_seed:		Seed the drbg with data of arbitrary length drbg: is
 *			pointer to data structure allocated with drbg_alloc
 *			return: >= 0 on success, < 0 on error
 * @drbg_generate:	Generate random numbers from the drbg with arbitrary
 *			length
 * @drbg_sec_strength:	Return DRBG security strength in bits
 */
struct esdm_drbg_cb {
	const char *(*drbg_name)(void);
	void *(*drbg_alloc)(u8 *personalization, u32 perslen);
	void (*drbg_dealloc)(void *drbg);
	int (*drbg_seed)(void *drbg, struct list_head *seedlist);
	int (*drbg_generate)(void *drbg, u8 *outbuf, u32 outbuflen,
			     u8 *additional_data, u32 additional_data_len);
	u32 (*drbg_sec_strength)(void *drbg);
};

/* can be called from module entry point */
int esdm_drbg_selftest(void);

extern const struct esdm_drbg_cb *esdm_drbg_cb;

#endif /* _ESDM_DRBG_KCAPI_H */
