# Raw Entropy Measurement of the eBPF Entropy Sources

This directory contains the measurement tooling for the eBPF-based
scheduler and interrupt entropy sources (`es_sched_ebpf`, `es_irq_ebpf`).
It serves the same purpose as the `esdm_raw_*` debugfs interfaces of the
`linux_esdm_es` kernel add-on: obtaining raw, unconditioned noise source
data for an SP800-90B / AIS 20/31 entropy assessment.

**The tooling is for measurement and validation only.** Build it with
`-Des_ebpf_testing=enabled` and never enable that option in production
builds. The collector refuses to run when the kernel FIPS mode is enabled,
and the ESDM server itself never records raw data.

## Measurement procedure

1. Build ESDM with the eBPF entropy sources and the testing support:

       meson setup build -Des_sched_ebpf=enabled -Des_irq_ebpf=enabled \
             -Des_ebpf_testing=enabled
       ninja -C build

2. Collect at least 10,000,000 raw events per environment as root. Perform
   one collection on an idle system and one under load (e.g.
   `stress-ng --cpu N --io N`):

       sudo ./build/addon/es_ebpf_testing/esdm-ebpf-collect \
            --source sched --events 10000000 --out sched_idle.bin

   The tool reports the timestamp tier in use: tier 2 reads the CPU cycle
   counter through the perf subsystem, tier 3 falls back to the monotonic
   clock. Measure every tier available on the target environment (force
   tier 3 with `--tier 3`) - the entropy rate must be configured for the
   tier the deployment will effectively use.

3. Run the SP800-90B assessment (requires the NIST
   [SP800-90B_EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment)
   tool):

       ./analyze_sp80090b.sh sched_idle.bin

   The script computes per-CPU time stamp deltas, extracts the 8 and 4
   least significant bits, runs the non-IID track and reports the
   worst-case min-entropy per event together with a suggested
   `es_sched_ebpf_entropy_rate` value (safety divisor 2).

4. Optionally prepare the data for the AIS 20/31 test procedures:

       ./analyze_ais31.sh sched_idle.bin

5. Repeat for `--source irq` if the interrupt source shall be credited
   (note: the default and recommended credit for the interrupt source is 0
   because the kernel RNG consumes the same events).

## Choosing the entropy rate

Use the **minimum** suggested rate across all measured environments and
load profiles, and configure it at build time
(`-Des_sched_ebpf_entropy_rate=N`) or at runtime through the ESDM
configuration interface. The shipped default of 0 keeps the source
uncredited until this measurement has been performed for the deployment
environment.

## Output file format

`esdm-ebpf-collect` writes verbatim `struct esdm_ebpf_raw_rec` records (16
bytes each, host endianness): `u32 type` (always 3), `u32 cpu`,
`u64 timestamp`. The timestamps are raw and pre-folding; per-CPU analysis
is mandatory as the streams of different CPUs are interleaved.
