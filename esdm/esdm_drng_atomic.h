/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_DRNG_ATOMIC_H
#define _ESDM_DRNG_ATOMIC_H

#include "esdm_drng_mgr.h"

/*
 * This header file currently is a stub for adding an atomic DRNG. An atomic
 * DRNG is usable in atomic context, i.e. it will never sleep. The notion
 * of an atomic DRNG comes from the LRNG kernel patch series where atomic
 * contexts are present which must not use code paths that have the capability
 * to sleep (e.g. with locks or with a memory allocation). In user space,
 * currently there is no need for such atomic behavior. Yet, leave the stubs
 * in the code to (a) be as close as possible to the LRNG patch series and (b)
 * keep our options open in the future in case a need arises for an atomic
 * behavior.
 */

#ifdef ESDM_DRNG_ATOMIC
void esdm_drng_atomic_reset(void);
void esdm_drng_atomic_seed_drng(struct esdm_drng *drng);
void esdm_drng_atomic_force_reseed(void);
struct esdm_drng *esdm_get_atomic(void);
#else /* ESDM_DRNG_ATOMIC */
static inline void esdm_drng_atomic_reset(void)
{
}
static inline void esdm_drng_atomic_seed_drng(struct esdm_drng *drng)
{
	(void)drng;
}
static inline void esdm_drng_atomic_force_reseed(void)
{
}
static inline struct esdm_drng *esdm_get_atomic(void)
{
	return NULL;
}
#endif /* ESDM_DRNG_ATOMIC */

#endif /* _ESDM_DRNG_ATOMIC_H */
