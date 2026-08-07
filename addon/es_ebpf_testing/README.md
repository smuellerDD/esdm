# Raw Entropy Measurement of the eBPF Entropy Sources

This directory contains the measurement tooling for the eBPF-based
scheduler and interrupt entropy sources (`es_sched_ebpf`, `es_irq_ebpf`).
It serves the same purpose as the `esdm_raw_*` debugfs interfaces of the
`linux_esdm_es` kernel add-on: obtaining raw, unconditioned noise source
data for an SP800-90B entropy assessment.

The assessment uses the NIST SP800-90B test suite throughout. The BSI
AIS 20/31 statistical test procedures A and B are not applicable here:
they assess the output of a physical noise source (classes PTG.\*),
whereas the eBPF entropy sources are non-physical true RNGs (class
NTG.1), for which AIS 20/31 requires a min-entropy justification of the
kind SP800-90B produces rather than those test procedures.

**The tooling is for measurement and validation only.** Build it with
`-Des_ebpf_testing=enabled` and never enable that option in production
builds. The collector refuses to run when the kernel FIPS mode is enabled,
and the ESDM server itself never records raw data.

## Measurement procedure

1. Build ESDM with the eBPF entropy sources, the testing support and the
   validation helpers - `esdm-extractlsb` is what turns the collected deltas into
   the byte stream the NIST tools assess:

       meson setup build -Des_sched_ebpf=enabled -Des_irq_ebpf=enabled \
             -Des_ebpf_testing=enabled -Dvalidation-helpers=enabled
       ninja -C build

2. Collect at least 1,000,000 deltas **per CPU** as root - the estimator
   warns below that. The CPUs are separate noise sources, so collect and
   assess them one at a time. Perform one collection on an idle system and
   one under load (e.g. `stress-ng --cpu N --io N`):

       sudo ./build/addon/es_ebpf_testing/esdm-ebpf-collect \
            --source sched --cpu 0 --events 1000000 --out sched_idle_cpu0.txt

   The output is one decimal time delta per line: the time between two
   successive events of that CPU. Without `--cpu` the deltas of all CPUs go
   into one stream in arrival order, which is convenient for a quick look but
   mixes independent noise sources and cannot be split again - do not assess
   it.

   The time stamps are read with `bpf_ktime_get_ns()` (the monotonic clock),
   the same source the deployed entropy sources use - the entropy rate must
   be configured for the environment the deployment actually runs in, as the
   clock resolution differs notably between bare metal and virtualized
   systems.

   The deltas are formed in the eBPF program, each between two events its CPU
   observed back to back. A record the ring buffer had no room for therefore
   costs a sample and distorts nothing - the collection simply runs a little
   longer until the requested number of deltas is on file.

   The timer granularity is always divided out of the time stamps, exactly
   as the ESDM server does, so that the assessed signal is the one that
   actually enters the entropy pool. The undivided time stamps cannot be
   collected: they report close to zero entropy on coarse clock sources
   (notably the monotonic clock in virtualized environments) whose low-order
   bits are constant, which is precisely what the granularity removal
   addresses.

3. Run the SP800-90B assessment (requires the NIST
   [SP800-90B_EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment)
   tools). `analyze_non_iid.sh` does the three steps of it - collect,
   `esdm-extractlsb`, `ea_non_iid` - for one CPU:

       sudo ./analyze_non_iid.sh --source sched --cpu 0 --events 1000000 \
            ea_out_cpu0

   `esdm-extractlsb` keeps the least significant bits of every delta and writes
   one byte each; the `FF` mask selects the low 8, which is where the timing
   entropy sits. `ea_non_iid` reports `min(H_original, 8 X H_bitstring)`, the
   per-event min-entropy `H` under the non-IID track. The script passes that
   output through as it stands.

   Doing it by hand is two commands:

       ./build/addon/test/esdm-extractlsb raw.txt raw-8.bin 1000000 FF
       ea_non_iid raw-8.bin 8

   Repeat for every CPU that shall be credited and take the **minimum**
   across all of them and all load profiles.

   nixpkgs packages the estimators as `sp800-90b-entropyassessment`. The
   flake runs both scripts in a VM:

       nix build -L .#checks.x86_64-linux.ebpf_raw

   That check exists to keep the tooling working, not to produce an entropy
   claim - a VM is not a deployment environment, and its result must not be
   used as one. Its restart run is a token 4 x 16 matrix for the same reason.

4. Validate the estimate with the restart test of SP800-90B section 3.1.4.
   It checks `H_I` - what step 3 measured - against the samples the source
   delivers immediately after a restart, when it has the least state to draw
   on:

       sudo ./analyze_restart.sh --source sched --cpu 0 <H_I> restart_cpu0

   One row is one run of `esdm-ebpf-collect`: every run loads and attaches
   its own copy of the eBPF programs, so each row starts from a freshly
   initialized source - zeroed per-CPU state, no previous time stamp and an
   unlearned timer granularity. **1000 restarts of 1000 samples each** are
   required; anything smaller is not a valid restart test, and the script
   says so. Expect it to take a long time - it is 1000 program loads.

   `--bits` has to match the stream `H_I` was measured on. The test fails
   when `min(H_r, H_c) < H_I / 2`; on success the entropy that may be
   claimed is `min(H_I, H_r, H_c)`. A failed *sanity check* means the
   restart data is degenerate - rows or columns that repeat - and the source
   may not be credited at all.

   Note that a restart here is a restart of the entropy source, not of the
   system. Where the evaluation requires the noise source to be assessed
   across system restarts, collect one row per boot instead and concatenate
   them.

5. Repeat for `--source irq` if the interrupt source shall be credited
   (note: the default and recommended credit for the interrupt source is 0
   because the kernel RNG consumes the same events).

## Choosing the entropy rate and the oversampling rate

From the measured per-event min-entropy `H`, the entropy rate is
`floor(H * 256 / 64)` - an event contributes its 64 bit delta, so 256 bits of
data are four events - and the oversampling rate is `ceil(1 / H)`.

The two have to agree. The accounting credits the smaller of what each yields,
`min(rate / 4, 1 / OSR)` bits per event, and `OSR` is a whole number: an event
measured above 1 bit cannot be claimed as such, because `OSR = 1` is the most
precise setting there is. `analyze_non_iid.sh` caps its suggestion at
`4 / OSR` accordingly.

Use the **minimum** across all measured environments, CPUs, bit widths and
load profiles, and configure it at build time
(`-Des_sched_ebpf_entropy_rate=N`) or at runtime through the ESDM
configuration interface. The shipped default of 0 keeps the source
uncredited until this measurement has been performed for the deployment
environment.

The same measurement determines the oversampling rate the SP800-90B
health tests are parameterized with, configured at build time
(`-Des_sched_ebpf_osr=N`, `-Des_irq_ebpf_osr=N`). It is the number of
events required per bit of entropy, `OSR = ceil(1 / H)` for the measured
min-entropy `H` per event - rounded **up**, so the RCT and APT cutoffs are
never less strict than the measurement warrants. Keep it consistent with
the entropy rate: an event contributes its 64 bit delta, so 256 bits of data
are four events and a rate above `4 / OSR` claims more than the assessment
supports - the accounting caps it and the server logs a warning on startup.
The shipped default of 1 is the strictest setting and matches the uncredited
default.

## Output format

`esdm-ebpf-collect` writes one decimal time delta per line, which is the
input format of `esdm-extractlsb`. A delta is the time between two events of one
CPU, with the timer granularity already divided out.

The eBPF program forms them, always between two events the CPU observed back
to back, and hands each one over on its own. Nothing user space receives can
therefore span a gap: a record the ring buffer had no room for is a sample
that never arrives, not a delta stretched across the ones it swallowed. Two
events yield no delta at all - the first one a CPU sees, and the first one
after a reset, whose predecessor was taken before the timer granularity was
known.

`--events` counts written deltas, so an interrupted collection yields exactly
the requested number and the losses show up as a longer collection rather than
a shorter assessment.
