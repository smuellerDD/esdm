/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_TESTING_H
#define _ESDM_TESTING_H

/************************** Configuration parameters **************************/
/*
config LRNG_RAW_SCHED_HIRES_ENTROPY
	bool "Interface to obtain raw unprocessed scheduler noise source data"
	depends on LRNG_SCHED
	select LRNG_TESTING
	select LRNG_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned high resolution time stamp noise that
	  is collected by the LRNG for the Scheduler-based noise source
	  for statistical analysis. Extracted  noise data is not used to
	  seed the LRNG.

	  The raw noise data can be obtained using the lrng_raw_sched_hires
	  debugfs file. Using the option
	  lrng_testing.boot_raw_sched_hires_test=1 the raw noise of the
	  first 1000 entropy events since boot can be sampled.

config LRNG_RAW_SCHED_PID_ENTROPY
	bool "Entropy test interface to PID value"
	depends on LRNG_SCHED
	select LRNG_TESTING
	select LRNG_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned PID value that is collected by the
	  LRNG for statistical analysis. Extracted noise
	  data is not used to seed the random number generator.

	  The raw noise data can be obtained using the
	  lrng_raw_sched_pid debugfs file. Using the option
	  lrng_testing.boot_raw_sched_pid_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config LRNG_RAW_SCHED_START_TIME_ENTROPY
	bool "Entropy test interface to task start time value"
	depends on LRNG_SCHED
	select LRNG_TESTING
	select LRNG_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned task start time value that is collected
	  by the LRNG for statistical analysis. Extracted noise
	  data is not used to seed the random number generator.

	  The raw noise data can be obtained using the
	  lrng_raw_sched_starttime debugfs file. Using the option
	  lrng_testing.boot_raw_sched_starttime_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.


config LRNG_RAW_SCHED_NVCSW_ENTROPY
	bool "Entropy test interface to task context switch numbers"
	depends on LRNG_SCHED
	select LRNG_TESTING
	select LRNG_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned task numbers of context switches that
	  are collected by the LRNG for statistical analysis. Extracted
	  noise data is not used to seed the random number generator.

	  The raw noise data can be obtained using the
	  lrng_raw_sched_nvcsw debugfs file. Using the option
	  lrng_testing.boot_raw_sched_nvcsw_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config LRNG_SCHED_PERF
	bool "LRNG scheduler entropy source performance monitor"
	depends on LRNG_SCHED
	select LRNG_TESTING
	select LRNG_TESTING_RECORDING
	help
	  With this option, the performance monitor of the LRNG
	  scheduler event handling code is enabled. The file provides
	  the execution time of the interrupt handler in cycles.

	  The scheduler performance data can be obtained using
	  the lrng_sched_perf debugfs file. Using the option
	  lrng_testing.boot_sched_perf=1 the performance data of
	  the first 1000 entropy events since boot can be sampled.
*/
#undef CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY
#undef CONFIG_ESDM_RAW_SCHED_PID_ENTROPY
#undef CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY
#undef CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY
#undef CONFIG_ESDM_SCHED_PERF

/******************************************************************************/

#ifdef CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY
bool esdm_raw_sched_hires_entropy_store(u32 value);
#else	/* CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY */
static inline bool
esdm_raw_sched_hires_entropy_store(u32 value) { return false; }
#endif	/* CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY */

#ifdef CONFIG_ESDM_RAW_SCHED_PID_ENTROPY
bool esdm_raw_sched_pid_entropy_store(u32 value);
#else	/* CONFIG_ESDM_RAW_SCHED_PID_ENTROPY */
static inline bool
esdm_raw_sched_pid_entropy_store(u32 value) { return false; }
#endif	/* CONFIG_ESDM_RAW_SCHED_PID_ENTROPY */

#ifdef CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY
bool esdm_raw_sched_starttime_entropy_store(u32 value);
#else	/* CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY */
static inline bool
esdm_raw_sched_starttime_entropy_store(u32 value) { return false; }
#endif	/* CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY */

#ifdef CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY
bool esdm_raw_sched_nvcsw_entropy_store(u32 value);
#else	/* CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY */
static inline bool
esdm_raw_sched_nvcsw_entropy_store(u32 value) { return false; }
#endif	/* CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY */

#ifdef CONFIG_ESDM_SCHED_PERF
bool esdm_sched_perf_time(u32 start);
#else /* CONFIG_ESDM_SCHED_PERF */
static inline bool esdm_sched_perf_time(u32 start) { return false; }
#endif /*CONFIG_ESDM_SCHED_PERF */

#if defined(CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY) ||			\
    defined(CONFIG_ESDM_RAW_SCHED_PID_ENTROPY) ||			\
    defined(CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY) ||		\
    defined(CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY) ||			\
    defined(CONFIG_ESDM_SCHED_PERF)
int __init esdm_raw_init(struct dentry *esdm_raw_debugfs_root);
#else
static inline int esdm_raw_init(struct dentry *esdm_raw_debugfs_root)
{
	return 0;
}
#endif

#endif /* _ESDM_TESTING_H */
