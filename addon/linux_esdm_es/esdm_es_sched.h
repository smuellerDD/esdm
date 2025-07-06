/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_SCHED_H
#define _ESDM_ES_SCHED_H

#include "esdm_es_mgr_cb.h"

/************************** Configuration parameters **************************/
/*
int "Scheduler Entropy Source Entropy Rate"
	depends on ESDM_SCHED
	range 256 4294967295 if ESDM_SCHED_DFLT_TIMER_ES
	range 4294967295 4294967295 if !ESDM_SCHED_DFLT_TIMER_ES
	default 256 if ESDM_SCHED_DFLT_TIMER_ES
	default 4294967295 if !ESDM_SCHED_DFLT_TIMER_ES
	help
	  The ESDM will collect the configured number of context switches
	  triggered by the scheduler to obtain 256 bits of entropy. This
	  value can be set to any between 256 and 4294967295. The ESDM
	  guarantees that this value is not lower than 256. This lower
	  limit implies that one interrupt event is credited with one bit
	  of entropy. This value is subject to the increase by the
	  oversampling factor, if no high-resolution timer is found.

	  In order to effectively disable the scheduler entropy source,
	  the option has to be set to 4294967295. In this case, the
	  scheduler entropy source will still deliver data but without
	  being credited with entropy.
 */
#define CONFIG_ESDM_SCHED_ENTROPY_RATE 768

/*
config ESDM_RUNTIME_ES_CONFIG
	bool "Enable runtime configuration of entropy sources"
	help
	  When enabling this option, the ESDM provides the mechanism
	  allowing to alter the entropy rate of each entropy source
	  during boot time and runtime.

	  Each entropy source allows its entropy rate changed with
	  a kernel command line option. When not providing any
	  option, the default specified during kernel compilation
	  is applied.
 */
#undef CONFIG_ESDM_RUNTIME_ES_CONFIG

/******************************************************************************/

void __init esdm_sched_es_init(bool highres_timer);

extern struct esdm_es_cb esdm_es_sched;

int __init esdm_es_sched_module_init(void);
void esdm_es_sched_module_exit(void);

#endif /* _ESDM_ES_SCHED_H */
