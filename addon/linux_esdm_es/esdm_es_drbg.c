// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM Slow Entropy Source: shared DRBG-based post-processing
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/list.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>

#include "esdm_es_drbg.h"
#include "esdm_es_ring.h"
#include "esdm_drbg_kcapi.h"
#include "esdm_health.h"

/* Return entropy of unused events present in all per-CPU pools. */
u32 esdm_es_drbg_avail_entropy(const struct esdm_es_drbg *drbg)
{
	u32 events;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(drbg->es))
		return 0;

	events = esdm_es_ring_avail_events(drbg->ring);

	if (esdm_sp80090c_compliant()) {
		/*
		 * reading >= 256 bit will use two DRBG extractions
		 * with ESDM_OVERSAMPLE_ES_BITS additionally used in each
		 */
		return esdm_reduce_by_osr(esdm_reduce_by_osr(
			esdm_data_to_entropy(events, drbg->entropy_bits)));
	} else {
		return esdm_data_to_entropy(events, drbg->entropy_bits);
	}
}

/* process events and return one DRBG output block
 *
 * Length is capped with DRBG's security strength */
static bool esdm_es_drbg_pool_extract_block(const struct esdm_es_drbg *drbg,
					    uint8_t *block, size_t partial_len,
					    u32 *returned_bits)
{
	u32 collected_events, collected_ent_bits, requested_events,
		returned_ent_bits, requested_bits;
	LIST_HEAD(seedlist);
	bool ok = false;
	int ret;

	/* init returned bits with 0, increase, if generate successful */
	*returned_bits = 0;

	if ((partial_len << 3) >
	    esdm_drbg_cb->drbg_sec_strength(drbg->drbg_state)) {
		pr_warn("more bits than DRBG security strength requested\n");
		goto out;
	}

	/* Always request DRBG security strength for each block, generate less
	 * bytes with DRBG, if advised by partial_len */
	requested_bits = esdm_drbg_cb->drbg_sec_strength(drbg->drbg_state);
	if (!esdm_drbg_cb->drbg_is_initialized(drbg->drbg_state)) {
		requested_events = esdm_entropy_to_data(
			requested_bits + esdm_init_osr(), drbg->entropy_bits);
	} else {
		requested_events = esdm_entropy_to_data(
			requested_bits + esdm_compress_osr(),
			drbg->entropy_bits);
	}

	collected_events =
		esdm_es_ring_collect(drbg->ring, requested_events, &seedlist);

	collected_ent_bits =
		esdm_data_to_entropy(collected_events, drbg->entropy_bits);
	/* Apply oversampling: discount requested oversampling rate */
	if (!esdm_drbg_cb->drbg_is_initialized(drbg->drbg_state)) {
		returned_ent_bits = esdm_reduce_by_init_osr(collected_ent_bits);
	} else {
		returned_ent_bits = esdm_reduce_by_osr(collected_ent_bits);
	}

	pr_debug(
		"obtained %u bits by collecting %u bits of entropy from %s-based noise source\n",
		returned_ent_bits, collected_ent_bits, drbg->name);

	if (esdm_drbg_cb->drbg_sec_strength(drbg->drbg_state) >
	    returned_ent_bits) {
		pr_warn("returned bits too small in %s-based noise source: %u\n",
			drbg->name, returned_ent_bits);
		goto out;
	}

	/* insert gathered entropy as additional input, HMAC-DRBG will insert
	 * this into his state before generating output! */
	ret = esdm_drbg_cb->drbg_seed(drbg->drbg_state, &seedlist);
	if (ret) {
		pr_warn("unable to seed drbg in %s-based noise source\n",
			drbg->name);
		goto out;
	}

	ret = esdm_drbg_cb->drbg_generate(drbg->drbg_state, block, partial_len,
					  (u8 *)drbg->domain_separation,
					  drbg->domain_separation_len);
	if (ret != partial_len) {
		pr_warn("unable to generate drbg output in %s-based noise source: %i\n",
			drbg->name, ret);
	} else {
		*returned_bits = min(requested_bits, 8 * partial_len);
		ok = true;
	}

out:
	esdm_es_ring_release(drbg->ring);
	return ok;
}

/*
 * Collect all per-CPU pools, process with internal DRBG and return the output
 * to be used as seed data for seeding a DRNG.
 * The caller must not guarantee backtracking resistance, as the internal
 * cryptographic post-processing with a DRBG is always used.
 * The function will only copy as much data as entropy is available into the
 * caller-provided output buffer (further restricted by the internal DRBG's
 * security strength).
 *
 * This function handles the translation from the number of received events into
 * an entropy statement. The conversion depends on the source's entropy rate
 * which defines how many events must be received to obtain 256 bits of entropy.
 * With this value, esdm_data_to_entropy converts a given data size (received
 * events, requested amount of data, etc.) into an entropy statement.
 * esdm_entropy_to_data does the reverse.
 *
 * With DRBG-based cryptographic post-processing only full blocks can be read.
 * This is done in esdm_es_drbg_pool_extract_block.
 *
 * @drbg: description of the source's ring and DRBG post-processing
 * @eb: entropy buffer to store entropy
 * @requested_bits: Requested amount of entropy
 */
void esdm_es_drbg_pool_extract(const struct esdm_es_drbg *drbg,
			       struct entropy_buf *eb, u32 requested_bits)
{
	const u32 esdm_security_strength =
		esdm_drbg_cb->drbg_sec_strength(drbg->drbg_state);
	const u32 full_blocks =
		esdm_full_blocks(requested_bits, esdm_security_strength);
	u32 done;

	/* only set entropy, when generate was successful */
	eb->e_bits = 0;

	/*
	 * Defense in depth: the extraction loop below writes requested_bits/8
	 * bytes into the fixed-size eb->e. The es-manager validates
	 * requested_bits against the allowed seed sizes, but guard locally so a
	 * future manager change can never drive an overflow of eb->e here.
	 */
	if (requested_bits > ESDM_DRNG_INIT_SEED_SIZE_BITS)
		return;

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(drbg->es)) {
		return;
	}

	/*
	 * Only deliver, when at least all requested blocks are available, one compress osr for the
	 * default case (no initialize with additional 64 Bit) is already counted in esdm_es_drbg_avail_entropy()
	 * add additional 64 bit in order to match 128 extra bit on full init
	 */
	if (esdm_es_drbg_avail_entropy(drbg) <
	    full_blocks * esdm_security_strength +
		    full_blocks * esdm_compress_osr()) {
		return;
	}

	done = 0;
	while (done < requested_bits) {
		u32 bits_returned;
		bool ok = esdm_es_drbg_pool_extract_block(
			drbg, eb->e + (done >> 3),
			min(esdm_security_strength, requested_bits - done) >> 3,
			&bits_returned);
		if (!ok) {
			pr_warn("DRBG block extract failed, bits returned: %u!\n",
				bits_returned);
			memzero_explicit(eb->e, sizeof(eb->e));
			goto out;
		}
		done += esdm_security_strength;
	}
	eb->e_bits = requested_bits;

out:
	return;
}
