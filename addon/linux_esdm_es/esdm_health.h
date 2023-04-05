/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
	default 31 if !ESDM_RCT_BROKEN
	default 1 if ESDM_RCT_BROKEN

# Default taken from SP800-90B sec 4.4.1 - significance level 2^-80
config ESDM_RCT_CUTOFF_PERMANENT
	int
	default 81 if !LRNG_RCT_BROKEN
	default 2 if LRNG_RCT_BROKEN

# Default taken from SP800-90B sec 4.4.2 - significance level 2^-30
config ESDM_APT_CUTOFF
	int
	default 325 if !ESDM_APT_BROKEN
	default 32 if ESDM_APT_BROKEN

# Default taken from SP800-90B sec 4.4.2 - significance level 2^-80
config ESDM_APT_CUTOFF_PERMANENT
	int
	default 371 if !LRNG_APT_BROKEN
	default 33 if LRNG_APT_BROKEN
 */

#define CONFIG_ESDM_RCT_CUTOFF 31
#define CONFIG_ESDM_RCT_CUTOFF_PERMANENT 81

#define CONFIG_ESDM_APT_CUTOFF 325
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT 371



/******************************************************************************/

enum esdm_health_res {
	esdm_health_pass,		/* Health test passes on time stamp */
	esdm_health_fail_use,		/* Time stamp unhealthy, but mix in */
	esdm_health_fail_drop		/* Time stamp unhealthy, drop it */
};

bool esdm_sp80090b_startup_complete_es(enum esdm_internal_es es);
bool esdm_sp80090b_compliant(enum esdm_internal_es es);

enum esdm_health_res esdm_health_test(u32 now_time, enum esdm_internal_es es);
void esdm_health_disable(void);

#endif /* _ESDM_HEALTH_H */
