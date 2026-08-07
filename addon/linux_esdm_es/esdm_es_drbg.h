/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM Slow Entropy Source: shared DRBG-based post-processing
 *
 * The interrupt and scheduler entropy sources both compress their per-CPU
 * events into seed material with an internal DRBG, identically so - only the
 * ring, the DRBG instance and the entropy rate differ, which struct
 * esdm_es_drbg captures.
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_DRBG_H
#define _ESDM_ES_DRBG_H

#include <linux/types.h>

#include "esdm_es_mgr_cb.h" /* struct entropy_buf, enum esdm_internal_es */

struct esdm_es_ring;

/*
 * struct esdm_es_drbg - per-source description of the DRBG post-processing
 * @ring:		per-CPU event ring feeding this DRBG
 * @drbg_state:		internal DRBG state; NULL until registration completes
 * @domain_separation:	personalization / domain separation string used as
 *			additional input to drbg_generate()
 * @domain_separation_len: length of @domain_separation in bytes
 * @es:			entropy-source id for SP800-90B startup / health queries
 * @entropy_bits:	number of events that must be collected for
 *			security-strength bits of entropy
 * @name:		human-readable source name used in log messages
 */
struct esdm_es_drbg {
	struct esdm_es_ring *ring;
	void *drbg_state;
	const char *domain_separation;
	u32 domain_separation_len;
	enum esdm_internal_es es;
	u32 entropy_bits;
	const char *name;
};

/* Currently available entropy across the source's per-CPU pools. */
u32 esdm_es_drbg_avail_entropy(const struct esdm_es_drbg *drbg);

/* Collect events and post-process them with the internal DRBG into @eb. */
void esdm_es_drbg_pool_extract(const struct esdm_es_drbg *drbg,
			       struct entropy_buf *eb, u32 requested_bits);

#endif /* _ESDM_ES_DRBG_H */
