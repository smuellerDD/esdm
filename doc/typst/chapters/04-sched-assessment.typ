#import "../template.typ": *

= Scheduler Entropy Source Assessment <sec:sched-assessment>

An entropy assessment of the scheduler-based entropy sources is not provided
yet. Both variants are therefore credited with no entropy by default:

- The scheduler entropy source of the kernel module `esdm_es` (section
  @sec:sched-events) is not built by default (`BUILD_ES_SCHED=0` in the
  Makefile of kernel/esdm\_es), and the ESDM credits it with no entropy
  (meson option `es_sched_entropy_rate` is 0). The kernel module processes
  the time stamps of the task wakeups like those of the interrupt entropy
  source assessed in chapter @sec:irq-assessment: the same GCD handling and
  health tests, a per-CPU ring and the conditioning with a DRBG instance of
  its own. Built with `BUILD_TESTING=1`, the kernel module provides the raw
  noise source data in the file
  `/sys/kernel/debug/esdm_es/esdm_raw_sched_hires`, which `esdm-getrawentropy`
  reads by default, and records the first events after its scheduler hook is
  registered for the restart test when it is loaded with the module
  parameter `boot_raw_sched_hires_test=1`. The steps of section
  @sec:90b-reuse apply to this data likewise.

- The eBPF-based scheduler entropy source (section @sec:ebpf, meson option
  `es_sched_ebpf`) is disabled by default and its entropy rate
  `es_sched_ebpf_entropy_rate` is 0.
  The directory tests/es\_ebpf\_testing provides the measurement tooling for
  it, built with the meson option `es_ebpf_testing`: `esdm-ebpf-collect`
  records the time differences of successive scheduling events of one CPU,
  `analyze_non_iid.sh` performs the SP800-90B assessment of them and
  `analyze_restart.sh` the restart test of SP800-90B section 3.1.4. The
  README of that directory derives the entropy rate and the oversampling rate
  (`es_sched_ebpf_osr`) to configure from the measured min-entropy per event,
  which must be determined for every deployment environment. The same applies
  to the eBPF-based interrupt entropy source (meson options `es_irq_ebpf`,
  `es_irq_ebpf_entropy_rate` and `es_irq_ebpf_osr`).
