/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef _ESDM_CRYPTO_H
#define _ESDM_CRYPTO_H

#include <stdint.h>
#include <sys/types.h>

/* Definitions for cryptographic backends */

/*
 * struct esdm_drng_cb - cryptographic callback functions defining a DRNG
 * @drng_name		Name of DRNG
 * @drng_selftest	Perform selftest
 * @drng_alloc:		Allocate DRNG -- the provided integer should be used for
 *			sanity checks.
 *			return: allocated data structure or PTR_ERR on error
 * @drng_dealloc:	Deallocate DRNG
 * @drng_seed:		Seed the DRNG with data of arbitrary length drng: is
 *			pointer to data structure allocated with drng_alloc
 *			return: >= 0 on success, < 0 on error
 * @drng_generate:	Generate random numbers from the DRNG with arbitrary
 *			length
 */
struct esdm_drng_cb {
	const char *(*drng_name)(void);
	int (*drng_selftest)(void);
	int (*drng_alloc)(void **drng, uint32_t sec_strength);
	void (*drng_dealloc)(void *drng);
	int (*drng_seed)(void *drng, const uint8_t *inbuf, size_t inbuflen);
	ssize_t (*drng_generate)(void *drng, uint8_t *outbuf, size_t outbuflen);
};

/*
 * struct esdm_hash_cb - cryptographic callback functions defining a hash
 * @hash_name		Name of Hash used for reading entropy pool arbitrary
 *			length
 * @hash_selftest	Perform a selftest
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
 * @hash_alloc		Allocate a hash context
 *			return: 0 on success, < 0 on error
 * @hash_dealloc	Deallocate hash context
 *
 * Assumptions:
 *
 * 1. Hash operation will not sleep
 * 2. The hash' volatile state information is provided with *shash by caller.
 */
struct esdm_hash_cb {
	const char *(*hash_name)(void);
	int (*hash_selftest)(void);
	uint32_t (*hash_digestsize)(void *hash);
	int (*hash_init)(void *hash);
	int (*hash_update)(void *hash, const uint8_t *inbuf, size_t inbuflen);
	int (*hash_final)(void *hash, uint8_t *digest);
	void (*hash_desc_zero)(void *hash);
	int (*hash_alloc)(void **ctx);
	void (*hash_dealloc)(void *ctx);
};

#endif /* _ESDM_CRYPTO_H */
