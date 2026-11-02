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
#include "esdm_es_timer_common.h"
#include "esdm_drbg_kcapi.h"
#include "esdm_health.h"

/*
 * The rate to credit the events by: the one the caller asks for, but never more
 * entropy per event than the module was loaded with.
 */
static u32 esdm_es_drbg_rate(const struct esdm_es_drbg *drbg, u32 entropy_rate)
{
	return max_t(u32, drbg->entropy_bits, entropy_rate);
}

/* Return entropy of unused events present in all per-CPU pools. */
u32 esdm_es_drbg_avail_entropy(const struct esdm_es_drbg *drbg,
			       u32 entropy_rate)
{
	u32 events, rate = esdm_es_drbg_rate(drbg, entropy_rate);

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(drbg->es))
		return 0;

	/* A timer found too coarse after registration delivers no entropy */
	if (!esdm_highres_timer())
		return 0;

	events = esdm_es_ring_avail_events(drbg->ring);

	if (esdm_sp80090c_compliant()) {
		/*
		 * reading >= 256 bit will use two DRBG extractions
		 * with ESDM_OVERSAMPLE_ES_BITS additionally used in each
		 */
		return esdm_reduce_by_osr(
			esdm_reduce_by_osr(esdm_data_to_entropy(events, rate)));
	} else {
		return esdm_data_to_entropy(events, rate);
	}
}

/* process events and return one DRBG output block
 *
 * Length is capped with DRBG's security strength */
static bool esdm_es_drbg_pool_extract_block(const struct esdm_es_drbg *drbg,
					    void *drbg_state, uint8_t *block,
					    size_t partial_len, u32 rate,
					    u32 *returned_bits)
{
	u32 collected_events, collected_ent_bits, requested_events,
		returned_ent_bits, requested_bits;
	LIST_HEAD(seedlist);
	bool ok = false;
	int ret;

	/* init returned bits with 0, increase, if generate successful */
	*returned_bits = 0;

	if ((partial_len << 3) > esdm_drbg_cb->drbg_sec_strength(drbg_state)) {
		pr_warn("more bits than DRBG security strength requested\n");
		goto out;
	}

	/* Always request DRBG security strength for each block, generate less
	 * bytes with DRBG, if advised by partial_len */
	requested_bits = esdm_drbg_cb->drbg_sec_strength(drbg_state);
	if (!esdm_drbg_cb->drbg_is_initialized(drbg_state)) {
		requested_events = esdm_entropy_to_data(
			requested_bits + esdm_init_osr(), rate);
	} else {
		requested_events = esdm_entropy_to_data(
			requested_bits + esdm_compress_osr(), rate);
	}

	collected_events =
		esdm_es_ring_collect(drbg->ring, requested_events, &seedlist);

	collected_ent_bits = esdm_data_to_entropy(collected_events, rate);
	/* Apply oversampling: discount requested oversampling rate */
	if (!esdm_drbg_cb->drbg_is_initialized(drbg_state)) {
		returned_ent_bits = esdm_reduce_by_init_osr(collected_ent_bits);
	} else {
		returned_ent_bits = esdm_reduce_by_osr(collected_ent_bits);
	}

	pr_debug(
		"obtained %u bits by collecting %u bits of entropy from %s-based noise source\n",
		returned_ent_bits, collected_ent_bits, drbg->name);

	if (esdm_drbg_cb->drbg_sec_strength(drbg_state) > returned_ent_bits) {
		pr_warn("returned bits too small in %s-based noise source: %u\n",
			drbg->name, returned_ent_bits);
		/* nothing reached the DRBG, leave the events in the ring */
		esdm_es_ring_discard(drbg->ring);
		return false;
	}

	/* insert the gathered entropy into the DRBG state as a reseed before
	 * generating output */
	ret = esdm_drbg_cb->drbg_seed(drbg_state, &seedlist);
	if (ret) {
		pr_warn("unable to seed drbg in %s-based noise source\n",
			drbg->name);
		goto out;
	}

	ret = esdm_drbg_cb->drbg_generate(drbg_state, block, partial_len,
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
	/* a ring reset since the collection invalidated the seed events */
	if (!esdm_es_ring_release(drbg->ring) && ok) {
		pr_warn("%s-based noise source reset during extraction\n",
			drbg->name);
		memzero_explicit(block, partial_len);
		*returned_bits = 0;
		ok = false;
	}
	return ok;
}

/*
 * Collect all per-CPU pools, post-process with the internal DRBG and return the
 * output as seed data. Backtracking resistance is inherent in that DRBG, so the
 * caller need not provide it. Only as much data as entropy is available is
 * copied out, further restricted by the DRBG's security strength.
 *
 * The number of received events is translated into an entropy statement via the
 * source's entropy rate (esdm_data_to_entropy and its inverse
 * esdm_entropy_to_data). Only full blocks can be read, see
 * esdm_es_drbg_pool_extract_block().
 *
 * @drbg: description of the source's ring and DRBG post-processing
 * @eb: entropy buffer to store entropy
 * @requested_bits: Requested amount of entropy
 * @entropy_rate: events per security strength bits of entropy the caller
 *		  credits, see esdm_es_drbg_rate()
 */
void esdm_es_drbg_pool_extract(const struct esdm_es_drbg *drbg,
			       struct entropy_buf *eb, u32 requested_bits,
			       u32 entropy_rate)
{
	/*
	 * The DRBG is published by the deferred registration work, which may
	 * run concurrently, and is NULL until then. Pairs with its
	 * smp_store_release().
	 */
	void *drbg_state = smp_load_acquire(&drbg->drbg_state);
	u32 esdm_security_strength, full_blocks, done, gen,
		rate = esdm_es_drbg_rate(drbg, entropy_rate);

	/* only set entropy, when generate was successful */
	eb->e_bits = 0;

	if (!drbg_state)
		return;

	esdm_security_strength = esdm_drbg_cb->drbg_sec_strength(drbg_state);
	if (!esdm_security_strength)
		return;

	/*
	 * Defense in depth: the extraction loop below writes requested_bits/8
	 * bytes into the fixed-size eb->e. The es-manager validates
	 * requested_bits against the allowed seed sizes, but guard locally so a
	 * future manager change can never drive an overflow of eb->e here.
	 */
	if (requested_bits > ESDM_DRNG_INIT_SEED_SIZE_BITS)
		return;

	/*
	 * Each block detects a reset between its own collection and release,
	 * but one request spans several blocks: a reset between two of them
	 * leaves earlier blocks derived from invalidated events. Check the
	 * generation across the whole request, too.
	 *
	 * Take it before the startup test checks here and in
	 * esdm_es_drbg_avail_entropy(): a health test failure re-arms the
	 * startup test with a fully ordered atomic_xchg() before its reset
	 * increments the generation under the ring lock. A generation read
	 * after that increment is ordered by the lock after the re-arming, so
	 * the checks below see the startup test running again. A generation
	 * read before it differs from the one read at the end. Taken after
	 * the checks, a failure in between would go unnoticed: the request
	 * would be served from events collected after the failure only, while
	 * the startup test still runs.
	 */
	gen = esdm_es_ring_gen(drbg->ring);

	/* Only deliver entropy when SP800-90B self test is completed */
	if (!esdm_sp80090b_startup_complete_es(drbg->es)) {
		return;
	}

	full_blocks = esdm_full_blocks(requested_bits, esdm_security_strength);

	/*
	 * Only deliver, when at least all requested blocks are available, one compress osr for the
	 * default case (no initialize with additional 64 Bit) is already counted in esdm_es_drbg_avail_entropy()
	 * add additional 64 bit in order to match 128 extra bit on full init
	 */
	if (esdm_es_drbg_avail_entropy(drbg, rate) <
	    full_blocks * esdm_security_strength +
		    full_blocks * esdm_compress_osr()) {
		return;
	}

	done = 0;
	while (done < requested_bits) {
		u32 bits_returned;
		bool ok = esdm_es_drbg_pool_extract_block(
			drbg, drbg_state, eb->e + (done >> 3),
			min(esdm_security_strength, requested_bits - done) >> 3,
			rate, &bits_returned);
		if (!ok) {
			pr_warn("DRBG block extract failed, bits returned: %u!\n",
				bits_returned);
			memzero_explicit(eb->e, sizeof(eb->e));
			goto out;
		}
		done += esdm_security_strength;
	}

	if (esdm_es_ring_gen(drbg->ring) != gen) {
		pr_warn("%s-based noise source reset during extraction\n",
			drbg->name);
		memzero_explicit(eb->e, sizeof(eb->e));
		goto out;
	}

	eb->e_bits = requested_bits;

out:
	return;
}
