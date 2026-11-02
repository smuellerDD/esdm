/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Security strength and seed sizes of the ESDM, shared by the ESDM and its
 * kernel module esdm_es
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * Both sides have to agree on them: the entropy buffer of the module holds a
 * seed of ESDM_DRNG_INIT_SEED_SIZE_BYTES, and the IOCTL interface of
 * /dev/esdm_es (esdm_es_ioctl.h) hands it over as a structure of that size -
 * with the SP800-90C oversampling of a CONFIG_CRYPTO_FIPS kernel, or without
 * it. The ESDM reads either of them (ESDM_DRNG_OVERSAMPLE_SEED_SIZE_BYTES,
 * ESDM_DRNG_SECURITY_STRENGTH_BYTES), whichever the module was built with.
 *
 * Whether the oversampling applies is up to the includer: it defines
 * ESDM_SEED_BUFFER_INIT_ADD_BITS - and ESDM_OVERSAMPLE_ES_BITS - as the values
 * below or as 0, the ESDM from its build configuration (config.h), the module
 * from CONFIG_CRYPTO_FIPS.
 */

#ifndef _ESDM_SEED_SIZES_H
#define _ESDM_SEED_SIZES_H

/* Security strength of ESDM -- this must match DRNG security strength */
#define ESDM_DRNG_SECURITY_STRENGTH_BYTES 32
#define ESDM_DRNG_SECURITY_STRENGTH_BITS (ESDM_DRNG_SECURITY_STRENGTH_BYTES * 8)

/*
 * SP800-90C oversampling, where it applies: the bits an entropy source is to
 * deliver in addition for every request, and the bits the initial seed holds
 * in addition to the security strength.
 */
#define ESDM_SP80090C_OVERSAMPLE_ES_BITS 64
#define ESDM_SP80090C_SEED_BUFFER_INIT_ADD_BITS 128

/* The seed, with the initial oversampling the includer applies */
#define ESDM_DRNG_INIT_SEED_SIZE_BITS                                          \
	(ESDM_DRNG_SECURITY_STRENGTH_BITS + ESDM_SEED_BUFFER_INIT_ADD_BITS)
#define ESDM_DRNG_INIT_SEED_SIZE_BYTES (ESDM_DRNG_INIT_SEED_SIZE_BITS >> 3)

/* The seed with the initial oversampling - of a module with CRYPTO_FIPS */
#define ESDM_DRNG_OVERSAMPLE_SEED_SIZE_BYTES                                   \
	((ESDM_DRNG_SECURITY_STRENGTH_BITS +                                   \
	  ESDM_SP80090C_SEED_BUFFER_INIT_ADD_BITS) >>                          \
	 3)

#endif /* _ESDM_SEED_SIZES_H */
