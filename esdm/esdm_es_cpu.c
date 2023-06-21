/*
 * ESDM Fast Entropy Source: CPU-based entropy source
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <stdio.h>

#include "build_bug_on.h"
#include "es_cpu/cpu_random.h"
#include "esdm_config.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_aux.h"
#include "esdm_es_cpu.h"
#include "esdm_node.h"
#include "helper.h"
#include "mutex.h"
#include "ret_checkers.h"

static uint32_t esdm_cpu_data_multiplier = 0;

static int esdm_cpu_init(void)
{
	esdm_cpu_data_multiplier = 0;
	return 0;
}

static uint32_t esdm_cpu_entropylevel(uint32_t requested_bits)
{
	return esdm_fast_noise_entropylevel(esdm_config_es_cpu_entropy_rate(),
					    requested_bits);
}

static uint32_t esdm_cpu_poolsize(void)
{
	return esdm_cpu_entropylevel(esdm_security_strength());
}

static uint32_t esdm_get_cpu_data(uint8_t *outbuf, uint32_t requested_bits)
{
	uint32_t i;

	/* operate on full blocks */
	BUILD_BUG_ON(ESDM_DRNG_SECURITY_STRENGTH_BYTES % sizeof(unsigned long));
	BUILD_BUG_ON(ESDM_SEED_BUFFER_INIT_ADD_BITS %
		     sizeof(unsigned long));
	/* ensure we have aligned buffers */
	BUILD_BUG_ON(ESDM_KCAPI_ALIGN % sizeof(unsigned long));

	for (i = 0; i < (requested_bits >> 3);
	     i += sizeof(unsigned long)) {
		/*
		 * The cast is appropriate as the thread local heap is aligned
		 * to ESDM_KCAPI_ALIGN bits
		 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		if (!cpu_es_get((unsigned long *)(outbuf + i))) {
#pragma GCC diagnostic pop
			esdm_config_es_cpu_entropy_rate_set(0);
			return 0;
		}
	}

	return requested_bits;
}

static uint32_t
esdm_get_cpu_data_compress(uint8_t *outbuf, uint32_t requested_bits,
			   uint32_t multiplier)
{
#if defined(ESDM_HASH_SHA512)
	LC_HASH_CTX_ON_STACK(shash, lc_sha512);
	bool shash_free = false;
#elif defined(ESDM_HASH_SHA3_512)
	LC_HASH_CTX_ON_STACK(shash, lc_sha3_512);
	bool shash_free = false;
#else
	void *shash;
	bool shash_free = true;
#endif
	const struct esdm_hash_cb *hash_cb;
	struct esdm_drng *drng = esdm_drng_node_instance();
	uint32_t ent_bits = 0, i, partial_bits = 0, digestsize, digestsize_bits,
	    full_bits;

	mutex_reader_lock(&drng->hash_lock);
	hash_cb = drng->hash_cb;

	if (shash_free) {
		if (hash_cb->hash_alloc) {
			if (hash_cb->hash_alloc((void **)&shash))
				goto err;
		}
	}

	digestsize = hash_cb->hash_digestsize(shash);
	digestsize_bits = digestsize << 3;
	/* Cap to maximum entropy that can ever be generated with given hash */
	esdm_cap_requested(digestsize_bits, requested_bits);
	full_bits = requested_bits * multiplier;

	/* Calculate oversampling for SP800-90C */
	if (esdm_sp80090c_compliant()) {
		/* Complete amount of bits to be pulled */
		full_bits += ESDM_OVERSAMPLE_ES_BITS * multiplier;
		/* Full blocks that will be pulled */
		multiplier = full_bits / requested_bits;
		/* Partial block in bits to be pulled */
		partial_bits = full_bits - (multiplier * requested_bits);
	}

	if (hash_cb->hash_init(shash))
		goto out;

	/* Hash all data from the CPU entropy source */
	for (i = 0; i < multiplier; i++) {
		ent_bits = esdm_get_cpu_data(outbuf, requested_bits);
		if (!ent_bits)
			goto out;

		if (hash_cb->hash_update(shash, outbuf, ent_bits >> 3))
			goto err;
	}

	/* Hash partial block, if applicable */
	ent_bits = esdm_get_cpu_data(outbuf, partial_bits);
	if (ent_bits &&
	    hash_cb->hash_update(shash, outbuf, ent_bits >> 3))
		goto err;

	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "pulled %u bits from CPU RNG entropy source\n", full_bits);
	ent_bits = requested_bits;

	/* Generate the compressed data to be returned to the caller */
	if (requested_bits < digestsize_bits) {
		uint8_t digest[ESDM_MAX_DIGESTSIZE];

		if (hash_cb->hash_final(shash, digest))
			goto err;

		/* Truncate output data to requested size */
		memcpy(outbuf, digest, requested_bits >> 3);
		memset_secure(digest, 0, digestsize);
	} else {
		if (hash_cb->hash_final(shash, outbuf))
			goto err;
	}

out:
	if (shash)
		hash_cb->hash_desc_zero(shash);
	if (shash_free && shash)
		hash_cb->hash_dealloc(shash);
	mutex_reader_unlock(&drng->hash_lock);
	esdm_drng_put_instances();
	return ent_bits;

err:
	ent_bits = 0;
	goto out;
}

/*
 * If CPU entropy source requires does not return full entropy, return the
 * multiplier of how much data shall be sampled from it.
 */
static uint32_t esdm_cpu_multiplier(void)
{
	unsigned long __maybe_unused v;

	if (esdm_cpu_data_multiplier > 0)
		return esdm_cpu_data_multiplier;

	esdm_cpu_data_multiplier = cpu_es_multiplier();
	if (!esdm_cpu_data_multiplier)
		esdm_cpu_data_multiplier = 1;

	/* Apply configured multiplier */
	esdm_cpu_data_multiplier = max_uint32(esdm_cpu_data_multiplier,
					      ESDM_CPU_FULL_ENT_MULTIPLIER);

	logger(LOGGER_DEBUG, LOGGER_C_ES, "Setting CPU ES multiplier to %u\n",
	       esdm_cpu_data_multiplier);

	return esdm_cpu_data_multiplier;
}

static int
esdm_cpu_switch_hash(struct esdm_drng __unused *drng, int __unused node,
		     const struct esdm_hash_cb __unused *new_cb,
		     const struct esdm_hash_cb __unused *old_cb)
{
	uint32_t digestsize, multiplier, curr_ent_rate;

	digestsize = esdm_get_digestsize();
	multiplier = esdm_cpu_multiplier();
	curr_ent_rate = esdm_config_es_cpu_entropy_rate();

	/*
	 * It would be security violation if the new digestsize is smaller than
	 * the set CPU entropy rate.
	 */
	if (multiplier > 1 && digestsize < curr_ent_rate)
		logger(LOGGER_WARN, LOGGER_C_ES,
		       "Compression hash has smaller digest size than CPU entropy rate\n");

	esdm_config_es_cpu_entropy_rate_set(
		min_uint32(digestsize, curr_ent_rate));
	return 0;
}

/*
 * esdm_cpu_get() - Get CPU entropy source entropy
 *
 * @eb: entropy buffer to store entropy
 * @requested_bits: requested entropy in bits
 */
static void esdm_cpu_get(struct entropy_es *eb_es, uint32_t requested_bits,
			 bool __unused unsused)
{
	uint32_t ent_bits, multiplier = esdm_cpu_multiplier();

	if (multiplier <= 1) {
		ent_bits = esdm_get_cpu_data(eb_es->e, requested_bits);
	} else {
		ent_bits = esdm_get_cpu_data_compress(eb_es->e, requested_bits,
						      multiplier);
	}

	ent_bits = esdm_cpu_entropylevel(ent_bits);
	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "obtained %u bits of entropy from CPU RNG entropy source\n",
		 ent_bits);
	eb_es->e_bits = ent_bits;
}

static void esdm_cpu_es_state(char *buf, size_t buflen)
{
	const struct esdm_drng *esdm_drng_init = esdm_drng_init_instance();
	uint32_t multiplier = esdm_cpu_multiplier();

	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 " Hash for compressing data: %s\n"
		 " Available entropy: %u\n"
		 " Data multiplier: %u\n",
		 (multiplier <= 1) ?
			"N/A" : esdm_drng_init->hash_cb->hash_name(),
		 esdm_cpu_poolsize(),
		 multiplier);
}

static bool esdm_cpu_active(void)
{
#ifdef ESDM_CPU_ES_IMPLEMENTED
	return true;
#else
	return false;
#endif
}

struct esdm_es_cb esdm_es_cpu = {
	.name			= "CPU",
	.init			= esdm_cpu_init,
	.fini			= NULL,
	.monitor_es		= NULL,
	.get_ent		= esdm_cpu_get,
	.curr_entropy		= esdm_cpu_entropylevel,
	.max_entropy		= esdm_cpu_poolsize,
	.state			= esdm_cpu_es_state,
	.reset			= NULL,
	.active			= esdm_cpu_active,
	.switch_hash		= esdm_cpu_switch_hash,
};
