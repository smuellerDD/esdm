/*
 * Test of the AIS 20/31 NTG.1 seeding decision
 *
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esdm.h"
#include "esdm_definitions.h"
#include "esdm_es_jent.h"
#include "esdm_es_mgr.h"
#include "esdm_es_mgr_cb.h"

#if defined(ESDM_AIS2031_NTG1_SEEDING_STRATEGY) && defined(ESDM_ES_JENT)

/*
 * The seeding decision is fed with a prepared entropy buffer, so the verdict
 * depends on the configured policy alone and not on what the entropy sources
 * of the test machine happen to deliver.
 */
static bool ntg1_seeded(const uint32_t *e_bits_per_es)
{
	struct entropy_buf eb;
	uint32_t i, collected = 0;

	memset(&eb, 0, sizeof(eb));

	for_each_esdm_es (i) {
		eb.entropy_es[i].e_bits = e_bits_per_es[i];
		collected += e_bits_per_es[i];
	}

	return esdm_fully_seeded(true, collected, &eb);
}

static int check(const char *desc, const uint32_t *e_bits_per_es, bool expected)
{
	bool seeded = ntg1_seeded(e_bits_per_es);

	printf("%s: fully seeded %s, expected %s\n", desc,
	       seeded ? "true" : "false", expected ? "true" : "false");

	return (seeded == expected) ? 0 : 1;
}

int main(void)
{
	uint32_t e_bits[esdm_ext_es_last];
	uint32_t i, other = esdm_ext_es_last, second = esdm_ext_es_last;
	int ret = 0;

	/* Two entropy sources next to the jitter RNG are needed below. */
	for_each_esdm_es (i) {
		if (i == (uint32_t)esdm_ext_es_jitter)
			continue;
		if (other == esdm_ext_es_last)
			other = i;
		else if (second == esdm_ext_es_last)
			second = i;
	}

	if (second == esdm_ext_es_last) {
		printf("Less than three entropy sources compiled in\n");
		return 77;
	}

	printf("Jitter RNG is NTG.1 conformant on its own: %s\n",
	       esdm_jent_ntg1() ? "true" : "false");

	/*
	 * The jitter RNG alone carries NTG.1 only if it is operated in its own
	 * NTG.1 mode, otherwise it is one source out of the two that NTG.1
	 * asks for.
	 */
	memset(e_bits, 0, sizeof(e_bits));
	e_bits[esdm_ext_es_jitter] = ESDM_AIS2031_NPTRNG_MIN_ENTROPY;
	ret += check("jitter RNG alone", e_bits, esdm_jent_ntg1());

	/* Below the required entropy the jitter RNG does not suffice either. */
	memset(e_bits, 0, sizeof(e_bits));
	e_bits[esdm_ext_es_jitter] = ESDM_AIS2031_NPTRNG_MIN_ENTROPY - 1;
	ret += check("jitter RNG alone, one bit short", e_bits, false);

	/*
	 * The exemption belongs to the jitter RNG, not to any single source
	 * delivering the same amount of entropy.
	 */
	memset(e_bits, 0, sizeof(e_bits));
	e_bits[other] = ESDM_AIS2031_NPTRNG_MIN_ENTROPY;
	ret += check("other entropy source alone", e_bits, false);

	/* Two sources always fulfill the requirement. */
	memset(e_bits, 0, sizeof(e_bits));
	e_bits[other] = ESDM_AIS2031_NPTRNG_MIN_ENTROPY;
	e_bits[second] = ESDM_AIS2031_NPTRNG_MIN_ENTROPY;
	ret += check("two other entropy sources", e_bits, true);

	return ret ? 1 : 0;
}

#else /* ESDM_AIS2031_NTG1_SEEDING_STRATEGY && ESDM_ES_JENT */

int main(void)
{
	printf("NTG.1 seeding strategy or jitter RNG entropy source not compiled in\n");

	return 77;
}

#endif /* ESDM_AIS2031_NTG1_SEEDING_STRATEGY && ESDM_ES_JENT */
