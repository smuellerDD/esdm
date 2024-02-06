/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_HASH_KCAPI_H
#define _ESDM_HASH_KCAPI_H

#include <crypto/hash.h>
#include <linux/types.h>

/*
 * struct esdm_hash_cb - cryptographic callback functions defining a hash
 * @hash_name		Name of Hash used for reading entropy pool arbitrary
 *			length
 * @hash_alloc:		Allocate the hash for reading the entropy pool
 *			return: allocated data structure (NULL is success too)
 *				or ERR_PTR on error
 * @hash_dealloc:	Deallocate Hash
 * @hash_digestsize:	Return the digestsize for the used hash to read out
 *			entropy pool
 *			hash: is pointer to data structure allocated with
 *			      hash_alloc
 *			return: size of digest of hash in bytes
 * @hash_init:		Initialize hash
 *			hash: is pointer to data structure allocated with
 *			      hash_alloc
 *			return: 0 on success, < 0 on error
 * @hash_update:	Update hash operation
 *			hash: is pointer to data structure allocated with
 *			      hash_alloc
 *			return: 0 on success, < 0 on error
 * @hash_final		Final hash operation
 *			hash: is pointer to data structure allocated with
 *			      hash_alloc
 *			return: 0 on success, < 0 on error
 * @hash_desc_zero	Zeroization of hash state buffer
 *
 * Assumptions:
 *
 * 1. Hash operation will not sleep
 * 2. The hash' volatile state information is provided with *shash by caller.
 */
struct esdm_hash_cb {
	const char *(*hash_name)(void);
	void *(*hash_alloc)(void);
	void (*hash_dealloc)(void *hash);
	u32 (*hash_digestsize)(void *hash);
	int (*hash_init)(struct shash_desc *shash, void *hash);
	int (*hash_update)(struct shash_desc *shash, const u8 *inbuf,
			   u32 inbuflen);
	int (*hash_final)(struct shash_desc *shash, u8 *digest);
	void (*hash_desc_zero)(struct shash_desc *shash);
};

#define ESDM_HASH_DIGESTSIZE_BYTES (64)
#define ESDM_HASH_DIGESTSIZE_BITS (ESDM_HASH_DIGESTSIZE_BYTES << 3)
extern const struct esdm_hash_cb *esdm_kcapi_hash_cb;

#endif /* _ESDM_HASH_KCAPI_H */
