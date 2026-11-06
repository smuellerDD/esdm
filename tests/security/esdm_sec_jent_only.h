/*
 * Helpers of the security tests running the ESDM with the Jitter RNG as the
 * only credited entropy source
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

#ifndef ESDM_SEC_JENT_ONLY_H
#define ESDM_SEC_JENT_ONLY_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_jent.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT)

/* NTG.1 seeding wants a second source - see esdm_fully_seeded() */
static inline bool esdm_sec_needs_second_source(void)
{
	return esdm_ntg1_2024_compliant() && !esdm_jent_ntg1();
}

/*
 * One seed's worth plus the oversampling of the conditioning, so the auxiliary
 * pool counts as a source. Only into an empty pool, so that nothing is left
 * once the initial seeding collected it.
 */
static inline void esdm_sec_feed_aux(void)
{
	uint8_t seed[2 * ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	size_t i;

	if (esdm_avail_entropy_aux())
		return;

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;
	esdm_pool_insert_aux(seed, sizeof(seed),
			     ESDM_DRNG_SECURITY_STRENGTH_BITS +
				     esdm_compress_osr());
}

/* The counters of the DRNG serving ordinary requests */
struct esdm_sec_counters {
	unsigned int instances;
	uint32_t requests_since_fully_seeded;
};

static inline void esdm_sec_counters_cb(const struct esdm_drng_stats *stats,
					void *priv)
{
	struct esdm_sec_counters *counters = (struct esdm_sec_counters *)priv;

	if (!strcmp(stats->type, "prediction resistance"))
		return;

	counters->instances++;
	counters->requests_since_fully_seeded =
		stats->requests_since_fully_seeded;
}

static inline struct esdm_sec_counters esdm_sec_counters_get(void)
{
	struct esdm_sec_counters counters;

	memset(&counters, 0, sizeof(counters));
	esdm_drng_stats_foreach(esdm_sec_counters_cb, &counters);

	return counters;
}

static inline void esdm_sec_sleep(time_t sec, long nsec)
{
	struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };

	nanosleep(&ts, NULL);
}

static inline bool esdm_sec_buf_is_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return false;
	}

	return true;
}

#endif /* ESDM_TESTMODE && ESDM_ES_JENT */

#endif /* ESDM_SEC_JENT_ONLY_H */
