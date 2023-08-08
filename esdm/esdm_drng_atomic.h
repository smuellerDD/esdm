/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_DRNG_ATOMIC_H
#define _ESDM_DRNG_ATOMIC_H

#include "esdm_drng_mgr.h"

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
