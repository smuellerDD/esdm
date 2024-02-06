/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_TESTING_H
#define _ESDM_TESTING_H

/************************** Configuration parameters **************************/
/*

comment "Interrupt Entropy Source Test Interfaces"

config ESDM_RAW_HIRES_ENTROPY
	bool "Interface to obtain raw unprocessed IRQ noise source data"
	default y
	depends on ESDM_IRQ
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned high resolution time stamp noise that
	  is collected by the ESDM for statistical analysis. Extracted
	  noise data is not used to seed the ESDM.

	  The raw noise data can be obtained using the esdm_raw_hires
	  debugfs file. Using the option esdm_testing.boot_raw_hires_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config ESDM_RAW_JIFFIES_ENTROPY
	bool "Entropy test interface to Jiffies of IRQ noise source"
	depends on ESDM_IRQ
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned Jiffies that is collected by
	  the ESDM for statistical analysis. This data is used for
	  seeding the ESDM if a high-resolution time stamp is not
	  available. If a high-resolution time stamp is detected,
	  the Jiffies value is not collected by the ESDM and no
	  data is provided via the test interface. Extracted noise
	  data is not used to seed the random number generator.

	  The raw noise data can be obtained using the esdm_raw_jiffies
	  debugfs file. Using the option esdm_testing.boot_raw_jiffies_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config ESDM_RAW_IRQ_ENTROPY
	bool "Entropy test interface to IRQ number noise source"
	depends on ESDM_IRQ
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned interrupt number that is collected by
	  the ESDM for statistical analysis. Extracted noise data is
	  not used to seed the random number generator.

	  The raw noise data can be obtained using the esdm_raw_irq
	  debugfs file. Using the option esdm_testing.boot_raw_irq_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config ESDM_RAW_RETIP_ENTROPY
	bool "Entropy test interface to RETIP value of IRQ noise source"
	depends on ESDM_IRQ
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned return instruction pointer value
	  that is collected by the ESDM for statistical analysis.
	  Extracted noise data is not used to seed the random number
	  generator.

	  The raw noise data can be obtained using the esdm_raw_retip
	  debugfs file. Using the option esdm_testing.boot_raw_retip_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config ESDM_RAW_REGS_ENTROPY
	bool "Entropy test interface to IRQ register value noise source"
	depends on ESDM_IRQ
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned interrupt register value that is
	  collected by the ESDM for statistical analysis. Extracted noise
	  data is not used to seed the random number generator.

	  The raw noise data can be obtained using the esdm_raw_regs
	  debugfs file. Using the option esdm_testing.boot_raw_regs_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config ESDM_RAW_ARRAY
	bool "Test interface to ESDM raw entropy IRQ storage array"
	depends on ESDM_IRQ
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw noise data that is collected by the ESDM
	  in the per-CPU array for statistical analysis. The purpose
	  of this interface is to verify that the array handling code
	  truly only concatenates data and provides the same entropy
	  rate as the raw unconditioned noise source when assessing
	  the collected data byte-wise.

	  The data can be obtained using the esdm_raw_array debugfs
	  file. Using the option esdm_testing.boot_raw_array=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config ESDM_IRQ_PERF
	bool "ESDM interrupt entropy source performance monitor"
	depends on ESDM_IRQ
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  With this option, the performance monitor of the ESDM
	  interrupt handling code is enabled. The file provides
	  the execution time of the interrupt handler in
	  cycles.

	  The interrupt performance data can be obtained using
	  the esdm_irq_perf debugfs file. Using the option
	  esdm_testing.boot_irq_perf=1 the performance data of
	  the first 1000 entropy events since boot can be sampled.

comment "Scheduler Entropy Source Test Interfaces"

config ESDM_RAW_SCHED_HIRES_ENTROPY
	bool "Interface to obtain raw unprocessed scheduler noise source data"
	depends on ESDM_SCHED
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned high resolution time stamp noise that
	  is collected by the ESDM for the Scheduler-based noise source
	  for statistical analysis. Extracted  noise data is not used to
	  seed the ESDM.

	  The raw noise data can be obtained using the esdm_raw_sched_hires
	  debugfs file. Using the option
	  esdm_testing.boot_raw_sched_hires_test=1 the raw noise of the
	  first 1000 entropy events since boot can be sampled.

config ESDM_RAW_SCHED_PID_ENTROPY
	bool "Entropy test interface to PID value"
	depends on ESDM_SCHED
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned PID value that is collected by the
	  ESDM for statistical analysis. Extracted noise
	  data is not used to seed the random number generator.

	  The raw noise data can be obtained using the
	  esdm_raw_sched_pid debugfs file. Using the option
	  esdm_testing.boot_raw_sched_pid_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config ESDM_RAW_SCHED_START_TIME_ENTROPY
	bool "Entropy test interface to task start time value"
	depends on ESDM_SCHED
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned task start time value that is collected
	  by the ESDM for statistical analysis. Extracted noise
	  data is not used to seed the random number generator.

	  The raw noise data can be obtained using the
	  esdm_raw_sched_starttime debugfs file. Using the option
	  esdm_testing.boot_raw_sched_starttime_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.


config ESDM_RAW_SCHED_NVCSW_ENTROPY
	bool "Entropy test interface to task context switch numbers"
	depends on ESDM_SCHED
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  The test interface allows a privileged process to capture
	  the raw unconditioned task numbers of context switches that
	  are collected by the ESDM for statistical analysis. Extracted
	  noise data is not used to seed the random number generator.

	  The raw noise data can be obtained using the
	  esdm_raw_sched_nvcsw debugfs file. Using the option
	  esdm_testing.boot_raw_sched_nvcsw_test=1
	  the raw noise of the first 1000 entropy events since boot
	  can be sampled.

config ESDM_SCHED_PERF
	bool "ESDM scheduler entropy source performance monitor"
	depends on ESDM_SCHED
	select ESDM_TESTING
	select ESDM_TESTING_RECORDING
	help
	  With this option, the performance monitor of the ESDM
	  scheduler event handling code is enabled. The file provides
	  the execution time of the interrupt handler in cycles.

	  The scheduler performance data can be obtained using
	  the esdm_sched_perf debugfs file. Using the option
	  esdm_testing.boot_sched_perf=1 the performance data of
	  the first 1000 entropy events since boot can be sampled.
*/

#undef CONFIG_ESDM_RAW_HIRES_ENTROPY
#undef CONFIG_ESDM_RAW_JIFFIES_ENTROPY
#undef CONFIG_ESDM_RAW_IRQ_ENTROPY
#undef CONFIG_ESDM_RAW_RETIP_ENTROPY
#undef CONFIG_ESDM_RAW_REGS_ENTROPY
#undef CONFIG_ESDM_RAW_ARRAY
#undef CONFIG_ESDM_IRQ_PERF

#undef CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY
#undef CONFIG_ESDM_RAW_SCHED_PID_ENTROPY
#undef CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY
#undef CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY
#undef CONFIG_ESDM_SCHED_PERF

/******************************************************************************/

#ifdef CONFIG_ESDM_RAW_HIRES_ENTROPY
bool esdm_raw_hires_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_HIRES_ENTROPY */
static inline bool esdm_raw_hires_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_HIRES_ENTROPY */

#ifdef CONFIG_ESDM_RAW_JIFFIES_ENTROPY
bool esdm_raw_jiffies_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_JIFFIES_ENTROPY */
static inline bool esdm_raw_jiffies_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_JIFFIES_ENTROPY */

#ifdef CONFIG_ESDM_RAW_IRQ_ENTROPY
bool esdm_raw_irq_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_IRQ_ENTROPY */
static inline bool esdm_raw_irq_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_IRQ_ENTROPY */

#ifdef CONFIG_ESDM_RAW_RETIP_ENTROPY
bool esdm_raw_retip_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_RETIP_ENTROPY */
static inline bool esdm_raw_retip_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_RETIP_ENTROPY */

#ifdef CONFIG_ESDM_RAW_REGS_ENTROPY
bool esdm_raw_regs_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_REGS_ENTROPY */
static inline bool esdm_raw_regs_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_REGS_ENTROPY */

#ifdef CONFIG_ESDM_RAW_ARRAY
bool esdm_raw_array_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_ARRAY */
static inline bool esdm_raw_array_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_ARRAY */

#ifdef CONFIG_ESDM_IRQ_PERF
bool esdm_perf_time(u32 start);
#else /* CONFIG_ESDM_IRQ_PERF */
static inline bool esdm_perf_time(u32 start)
{
	return false;
}
#endif /*CONFIG_ESDM_IRQ_PERF */

#ifdef CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY
bool esdm_raw_sched_hires_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY */
static inline bool esdm_raw_sched_hires_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY */

#ifdef CONFIG_ESDM_RAW_SCHED_PID_ENTROPY
bool esdm_raw_sched_pid_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_SCHED_PID_ENTROPY */
static inline bool esdm_raw_sched_pid_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_SCHED_PID_ENTROPY */

#ifdef CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY
bool esdm_raw_sched_starttime_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY */
static inline bool esdm_raw_sched_starttime_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY */

#ifdef CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY
bool esdm_raw_sched_nvcsw_entropy_store(u32 value);
#else /* CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY */
static inline bool esdm_raw_sched_nvcsw_entropy_store(u32 value)
{
	return false;
}
#endif /* CONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY */

#ifdef CONFIG_ESDM_SCHED_PERF
bool esdm_sched_perf_time(u32 start);
#else /* CONFIG_ESDM_SCHED_PERF */
static inline bool esdm_sched_perf_time(u32 start)
{
	return false;
}
#endif /*CONFIG_ESDM_SCHED_PERF */

#ifdef ESDM_TESTING

int __init esdm_test_init(void);
void __exit esdm_test_exit(void);

#else

static inline int __init esdm_test_init(void)
{
	return 0;
}
static inline void __exit esdm_test_exit(void)
{
}

#endif

#endif /* _ESDM_TESTING_H */
