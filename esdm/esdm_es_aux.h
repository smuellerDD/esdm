/*
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

#ifndef _ESDM_ES_AUX_H
#define _ESDM_ES_AUX_H

#include "esdm.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr_cb.h"

extern struct esdm_es_cb esdm_es_aux;

/****************************** Helper code ***********************************/

/* Obtain the security strength of the ESDM in bits */
static inline uint32_t esdm_security_strength(void)
{
	/*
	 * We use a hash to read the entropy in the entropy pool. According to
	 * SP800-90B table 1, the entropy can be at most the digest size.
	 * Considering this together with the last sentence in section 3.1.5.1.2
	 * the security strength of a (approved) hash is equal to its output
	 * size. On the other hand the entropy cannot be larger than the
	 * security strength of the used DRBG.
	 */
	return min_t(uint32_t, ESDM_FULL_SEED_ENTROPY_BITS,
		     esdm_get_digestsize());
}

static inline uint32_t esdm_get_seed_entropy_osr(bool fully_seeded)
{
	uint32_t requested_bits = esdm_security_strength();

	/* Apply oversampling during initialization according to SP800-90C */
	if (esdm_sp80090c_compliant() && !fully_seeded)
		requested_bits += ESDM_SEED_BUFFER_INIT_ADD_BITS;
	return requested_bits;
}

#endif /* _ESDM_ES_AUX_H */
