/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_HEALTH_H
#define _ESDM_HEALTH_H

#include "esdm_es_mgr_cb.h"

/************************** Configuration parameters **************************/
/*
config ESDM_RCT_BROKEN
	bool "SP800-90B RCT with dangerous low cutoff value"
	depends on ESDM_HEALTH_TESTS
	depends on BROKEN
	default n
	help
	  This option enables a dangerously low SP800-90B repetitive
	  count test (RCT) cutoff value which makes it very likely
	  that the RCT is triggered to raise a self test failure.

	  This option is ONLY intended for developers wanting to
	  test the effectiveness of the SP800-90B RCT health test.

	  If unsure, say N.

config ESDM_APT_BROKEN
	bool "SP800-90B APT with dangerous low cutoff value"
	depends on ESDM_HEALTH_TESTS
	depends on BROKEN
	default n
	help
	  This option enables a dangerously low SP800-90B adaptive
	  proportion test (APT) cutoff value which makes it very
	  likely that the APT is triggered to raise a self test
	  failure.

	  This option is ONLY intended for developers wanting to
	  test the effectiveness of the SP800-90B APT health test.

	  If unsure, say N.

# Default taken from SP800-90B sec 4.4.1 - significance level 2^-30
config ESDM_RCT_CUTOFF
	int
	default 30 if !ESDM_RCT_BROKEN
	default 1 if ESDM_RCT_BROKEN

# Default taken from SP800-90B sec 4.4.1 - significance level 2^-60
config ESDM_RCT_CUTOFF_PERMANENT
	int
	default 60 if !ESDM_RCT_BROKEN
	default 2 if ESDM_RCT_BROKEN
 */

/*
 * The RCT applies the aforementioned significance level. Based on the formula
 * in SP800-90B section 4.4.1, when exceeding the threshold, a health alarm is
 * triggered. When applying an oversampling rate, this value is multiplied
 * by the used oversampling rate at compile time. As the OSR is an integer,
 * rounding errors occur when the actual OSR contains fractions. At compile
 * time, the OSR will always be rounded down to the nearest integer value
 * to be conservative.
 */
#define CONFIG_ESDM_RCT_CUTOFF 30
#define CONFIG_ESDM_RCT_CUTOFF_PERMANENT 60


/*
 * See the SP 800-90B comment #10b for the corrected cutoff for the SP 800-90B
 * APT.
 * http://www.untruth.org/~josh/sp80090b/UL%20SP800-90B-final%20comments%20v1.9%2020191212.pdf
 * In in the syntax of R, this is C = 2 + qbinom(1 − 2^(−30), 511, 2^(-1/osr)).
 * (The original formula wasn't correct because the first symbol must
 * necessarily have been observed, so there is no chance of observing 0 of these
 * symbols.)
 *
 * For the alpha < 2^-53, R cannot be used as it uses a float data type without
 * arbitrary precision. A SageMath script is used to calculate those cutoff
 * values.
 *
 * For any value above 14, this yields the maximal allowable value of 512
 * (by FIPS 140-2 IG 7.19 Resolution # 16, we cannot choose a cutoff value that
 * renders the test unable to fail).
 *
 * The definitions are for an significance level of 2^-30 and 2^-60
 */
#define CONFIG_ESDM_APT_CUTOFF_1 325
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_1 355

#define CONFIG_ESDM_APT_CUTOFF_2 422
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_2 447

#define CONFIG_ESDM_APT_CUTOFF_3 459
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_3 479

#define CONFIG_ESDM_APT_CUTOFF_4 477
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_4 494

#define CONFIG_ESDM_APT_CUTOFF_5 488
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_5 502

#define CONFIG_ESDM_APT_CUTOFF_6 494
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_6 507

#define CONFIG_ESDM_APT_CUTOFF_7 499
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_7 510

#define CONFIG_ESDM_APT_CUTOFF_8 502
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_8 512

#define CONFIG_ESDM_APT_CUTOFF_9 505
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_9 512

#define CONFIG_ESDM_APT_CUTOFF_10 507
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_10 512

#define CONFIG_ESDM_APT_CUTOFF_11 508
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_11 512

#define CONFIG_ESDM_APT_CUTOFF_12 509
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_12 512

#define CONFIG_ESDM_APT_CUTOFF_13 510
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_13 512

#define CONFIG_ESDM_APT_CUTOFF_14 511
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_14 512

#define CONFIG_ESDM_APT_CUTOFF_15 512
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_15 512

/******************************************************************************/

enum esdm_health_res {
	esdm_health_pass, /* Health test passes on time stamp */
	esdm_health_fail_use, /* Time stamp unhealthy, but mix in */
	esdm_health_fail_drop /* Time stamp unhealthy, drop it */
};

bool esdm_sp80090b_startup_complete_es(enum esdm_internal_es es);
bool esdm_sp80090b_compliant(enum esdm_internal_es es);

enum esdm_health_res esdm_health_test(u32 now_time, enum esdm_internal_es es);
void esdm_health_disable(void);

#endif /* _ESDM_HEALTH_H */
