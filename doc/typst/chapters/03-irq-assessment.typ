#import "../template.typ": *
#import "../plots/histogram.typ": histogram

// Unnumbered display equation (LaTeX equation*/displaymath).
#let display(body) = math.equation(block: true, numbering: none, body)
// "Output_Entropy" as used throughout the SP800-90B calculations.
#let OE = math.italic("Output_Entropy")

= Interrupt Entropy Source Assessment <sec:irq-assessment>

This section documents the entropy assessment and the compliance with various
standards of the interrupt entropy source. All other entropy sources are
treated as black boxes by the ESDM and must therefore deliver their own
entropy assessment.

The interrupt entropy source assessed here is the one of the Linux kernel
module `esdm_es` found in kernel/esdm\_es: the hook patches for the supported
kernel versions invoke the kernel module for every interrupt, the kernel
module health tests the time stamps, collects them in per-CPU rings and
conditions them with a DRBG, and the ESDM obtains the result with the IOCTLs
of the device file /dev/esdm\_es (section @sec:irq-processing). The
eBPF-based interrupt entropy source observes the same noise source on a stock
Linux kernel, but processes it differently (section @sec:ebpf): it is not
covered by this chapter and is credited with no entropy by default (chapter
@sec:sched-assessment).

The entropy sources of the auxiliary pool, the Jitter RNG and the CPU-based
entropy source are all not related to the interrupt entropy source. Thus, the
combination of all those entropy sources is subject to the SP800-90C
assessment provided in section @sec:sp80090c.

== Noise Source Behavior <sec:noise-source>

The noise source component of an entropy source contains the
non-deterministic, entropy-producing activity. For the interrupt entropy
source this is the timing of the arrival of interrupts. The general behavior
of the noise source can be characterized by analyzing the time stamps of the
arrival time. Before performing this analysis, a recap of the noise source is
important:

- When an interrupt occurs, the kernel module obtains a high-resolution time
  stamp with `random_get_entropy`. Technically it may be a cycle counter
  offered by the CPU that produces the time stamp which is unrelated to time,
  but provides a fast-moving counter. When it is loaded, the kernel module
  reads the time stamp 1,024 times back to back and registers the interrupt
  entropy source only if the time stamp changed at least 16 times – otherwise
  no high-resolution timer is present.

- The time stamp is divided by the greatest common divisor (GCD) that is
  calculated by using the first 100 time stamps after the kernel module is
  loaded or the entropy source is reset, which themselves are processed
  undivided. A GCD of 1,000 or more marks the
  timer as too coarse: the entropy source then credits no entropy.

- After the division with the GCD, the time stamp is subject to the health
  tests (section @sec:health-tests). A time stamp passing them is stored as a
  64 bit value in the per-CPU ring of the kernel module. These values are now
  subject to post-processing via the DRBG of the kernel module and the DRNG
  of the ESDM.

#par(first-line-indent: 0pt)[Considering these static and never-changing
steps, the noise source rests on the variations of the time stamps divided by
the GCD, which are found in their least significant bits. The measurements
presented in the following and in appendix @sec:measurements were obtained
with earlier versions of the interrupt entropy source, which used the 8
least-significant bits of the time stamp divided by the GCD and discarded the
higher-order bits. An analysis of the noise source therefore focuses on these
8 bits. These 8 bits are subsequently referenced as “raw noise source data”.
The raw entropy interface of the current kernel module (section
@sec:ig718-testing) provides the difference of two successive time stamps of
a CPU divided by the GCD as a 64 bit value, of which the least significant
bits are extracted for the analysis.]

=== Distribution of Raw Data <sec:raw-distribution>

If the noise source would operate perfectly, an equi-distribution of the raw
noise source data is to be expected. Various tests have been conducted on most
major CPUs as outlined in appendix @sec:measurements. Using the runtime data,
a common pattern of the raw noise source data emerges that can be seen with
figure @fig:riscv. This figure uses the 1,000,000 traces of the raw noise
source data from the IRQ entropy source on the RISC-V, i.e. a system with
less-then-average entropy rate.

#figure(
  histogram("riscv"),
  caption: [RISC-V Raw Noise Source Data Distribution],
) <fig:riscv>

Figure @fig:riscv shows the following characteristics:

- A histogram of the number of time stamps received for each of the 256
  possible time stamp values is depicted.

- The 25% and 75% quartiles of the distribution are marked with the two green
  lines. They are at the time stamp value of 63 and 192, respectively

- The mean of the distribution is marked with the red line which is 127.45.

- The median of the distribution is marked with the blue line at 128.

- The black line marks the distribution of the time stamps.

- The standard derivation is not depicted, but it is at 73.89.

- The variation coefficient is not shown in the figure, but it is 0.579801.

#par(first-line-indent: 0pt)[The figure together with the mentioned
statistical values clearly shows that it is close to an equi-distribution.
This means that the raw noise source data for an entropy source instance on a
less-than-ideal hardware still exhibit a distribution that is close to the
expected entropy source for a perfect operation. The distributions of most
tested systems are always close to an equi-distribution as shown with the
table below.]

To verify that the distribution is an equi-distribution, a Chi-Squared
Goodness-of-Fit test is applied. For the mentioned RISC-V system, the
following values are observed:

- Asymptotic significance P: 0.2343

- Degrees of freedom: 255

#par(first-line-indent: 0pt)[The degrees of freedom shows that indeed all 256
possible timing values are covered. Applying an alpha of 5%, the Chi-Squared
test indicates that the observed data set is an equi-distribution.]

With the table below, the statistical properties for the different tested
systems are listed.

#{
  set text(size: 10pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  show table.cell: set align(center + top)
  table(
    // As wide as in the original, which extends into the right margin.
    columns: (83pt,) + (41pt,) * 8,
    table.header(
      [Test System], [25% Quar\u{AD}tile], [Median], [Mean],
      [75% Quar\u{AD}tile], [Std. Deriv.], [Var. Coeff.], [$chi^2$ P],
      [$chi^2$ DF],
      table.hline(stroke: 0.8pt),
    ),
    [AMD Ryzen 5950X - 64-bit KVM environment],
      [64], [128], [127.6], [192], [73.88], [0.58], [0.0523], [255],
    [AMD EPYC Milan 7713 2 sockets 128 cores 8-way NUMA],
      [63], [127], [127.48], [192], [73.91], [0.58], [0.4458], [255],
    [ARMv7 rev 5],
      [68], [128], [121.05], [191], [72.95], [0.60], [0], [255],
    [ARMv7 rev 5 (Freescale i.MX53)#footnote[USBArmory MK I]],
      [63], [128], [127.52], [192], [74], [0.58], [0.4693], [255],
    [ARMv7 rev 5 (Freescale i.MX6 Ultralite)#footnote[USBArmory MK II]],
      [63], [127], [127.15], [191], [73.96], [0.58], [0], [255],
    [ARM 64 bit AppliedMicro X-Gene Mustang Board],
      [63], [128], [127.54], [192], [73.94], [0.58], [0.7229], [255],
    [Intel Atom Z530 – using GUI],
      [64], [128], [127.58], [192], [73.93], [0.58], [0.3181], [255],
    [Intel Sandy Bridge Clang Compile],
      [62], [125], [125.86], [187], [73.24], [0.58], [0.9347], [252],
    [Intel i7 8565U Whiskey Lake – 32-bit KVM environment],
      [64], [128], [127.53], [192], [73.91], [0.58], [0.2893], [255],
    [Intel i7 8565U Whiskey Lake],
      [63], [127], [127.37], [191], [73.86], [0.58], [0], [255],
    [Intel Xeon E7 4870 8 sockets 160 CPUs 8-way NUMA],
      [64], [127], [127.44], [191], [73.89], [0.58], [0], [255],
    [Intel Xeon Gold 6234],
      [64], [126], [126.75], [190], [73.88], [0.58], [0],
      [127#footnote[Tested without GCD.]],
    [IBM POWER 8 LE 8286-42A],
      [63], [127], [127.66], [191], [73.86], [0.58], [0], [255],
    [IBM POWER 7 BE 8202-E4C],
      [64], [128], [130.07], [192], [73.96], [0.57], [0], [255],
    [IBM System Z z13 (machine 2964)],
      [56], [120], [118.27], [184], [73.58], [0.62], [0], [235],
    [IBM System Z z15 (machine 8561)],
      [58], [122], [124.3], [192], [73.54], [0.59], [0], [239],
    [MIPS Atheros AR7241 rev 1#footnote[Ubiquiti Nanostation M5 (xm)]],
      [64], [128], [127.55], [191], [73.88], [0.58], [0.5646], [255],
    [MIPS Lantiq 34Kc V5.6#footnote[AVM Fritz Box 7490]],
      [64], [127], [127.49], [191], [73.85], [0.58], [0], [255],
    [Qualcomm IPQ4019 ARMv7#footnote[AVM Fritz Box 7520]],
      [63], [127], [127.4], [191], [73.9], [0.58], [0], [255],
    [SiFive HiFive Unmatched RISC-V U74],
      [63], [127], [127.45], [192], [73.89], [0.58], [0.2343], [255],
  )
}

The Chi-Squared asymptotic significance shows for some systems that an
equi-distribution is not applicable, i.e. when the $chi^2$ P value is less
than 0.05. Yet, when considering the other statistical values, the actual
distribution is neither skewed nor otherwise loop-sided. When looking at the
distribution, it becomes evident that some time stamps have a higher
likelihood than others which hint to special properties of the system. This
observation applies to all measurements which do not follow an
equi-distribution based on the Chi-Squared Goodness-of-Fit test. This allows
the conclusion that the min-entropy estimates given in appendix
@sec:measurements can be considered to illustrate the real entropy rate.

For example, the distribution for the USB Armory Mark II system shown with
figure @fig:usbarmory indicates that all time stamp values divisible by 8 are
only chosen two-thirds as often as the rest.

#figure(
  histogram("usbarmory-mk2"),
  caption: [USB Armory Mark II: Raw Noise Source Data],
) <fig:usbarmory>

Another example is a specific ARMv7 system which contains a very periodic
timer interrupt. Figure @fig:armv7 shows that the time stamp has a pattern but
still exhibits a distribution that does not contradict the expectation to
deliver entropy at the rate calculated in appendix @sec:measurements. In the
worst case that the timer interrupt only causes the raw noise source data
which would exhibit a clear pattern, the stuck health test would identify this
pattern with the second discrete derivative and disregards time stamp for
entropy collection.

#figure(
  histogram("armv7-timer"),
  caption: [Periodic timer interrupt: Specific ARMv7 System Raw Noise Source
    Data],
) <fig:armv7>

A similar effect is visible on an IBM System Z z13 system shown with figure
@fig:systemz. Again, the shown pattern does not contradict the entropy rate
calculated for this system in appendix @sec:measurements.

#figure(
  histogram("systemz-z13"),
  caption: [IBM System Z Raw Noise Source Data],
) <fig:systemz>

=== Greatest Common Divisor Assessment <sec:gcd>

The behavior of the GCD application can be clearly seen with the following
figures and numbers obtained for an Intel Atom Z530 system whose GCD is 4.

Without the application of the GCD, the distribution of the time stamp is
given with figure @fig:without-gcd

#figure(
  histogram("atom-without-gcd"),
  caption: [Without GCD - Raw Noise Source Data Distribution],
) <fig:without-gcd>

Figure @fig:without-gcd shows the following characteristics:

- A histogram of the number of time stamps received for each of the 256
  possible time stamp values is depicted.

- The 25% and 75% quartiles of the distribution are marked with the two green
  lines. They are at the time stamp value of 63 and 188, respectively

- The mean of the distribution is marked with the red line which is 125.99.

- The median of the distribution is marked with the blue line at 128.

- The standard derivation is not depicted, but it is at 73.84.

- The variation coefficient is not shown in the figure, but it is 0.586089.

- $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.4263

- $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 63

#par(first-line-indent: 0pt)[When applying the GCD, and obtaining a new
measurement, the distribution shown with figure @fig:with-gcd emerges:]

#figure(
  histogram("atom-with-gcd"),
  caption: [With GCD - Raw Noise Source Data Distribution],
) <fig:with-gcd>

Figure @fig:with-gcd shows the following characteristics:

- A histogram of the number of time stamps received for each of the 256
  possible time stamp values is depicted.

- The 25% and 75% quartiles of the distribution are marked with the two green
  lines. They are at the time stamp value of 64 and 192, respectively

- The mean of the distribution is marked with the red line which is 127.58.

- The median of the distribution is marked with the blue line at 124.

- The standard derivation is not depicted, but it is at 73.93.

- The variation coefficient is not shown in the figure, but it is 0.579468.

- $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.3181

- $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

#par(first-line-indent: 0pt)[This shows that the application of the GCD
removes the “unused” time stamp values without changing the overall
distribution.]

=== Worst and Regular Case Distribution <sec:worst-regular>

The measurements shown in appendix @sec:measurements commonly are obtained by
applying a worst-case which triggers as much interrupts as possible in the
shortest amount of time.

To compare the distributions of the time stamp between the worst case and a
regular case of normal system use, the USB Armory mark I system was tested
twice with the following result values:

- Worst case

  - 25% quartile: 64
  - Median: 128
  - Mean: 127.6
  - 75% quartile: 192
  - Standard derivation: 73.91
  - Variation coefficient: 0.579221
  - $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.9445
  - $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

- Regular case

  - 25% quartile: 63
  - Median: 128
  - Mean: 127.52
  - 75% quartile: 192
  - Standard derivation: 74
  - Variation coefficient: 0.580276
  - $chi^2$ P value for equi-distribution Goodness-of-Fit test: 0.4693
  - $chi^2$ degrees of freedom for equi-distribution Goodness-of-Fit test: 255

#par(first-line-indent: 0pt)[The values indicate no statistical significant
difference allowing the conclusion that both distributions are very
similar.]

== FIPS 140-2 Compliance <sec:fips1402>

FIPS 140-2 specifies entropy source compliance in FIPS 140-2 IG 7.18. This
section analyzes each requirement for compliance. The general requirement to
comply with SP800-90B @sp80090b is analyzed in section @sec:sp80090b.

=== FIPS 140-2 IG 7.18 Requirement For Statistical Testing <sec:ig718-testing>

The ESDM is provided with the following testing tools:

- Raw Entropy Tests: The tests obtain the raw unconditioned and unprocessed
  noise information and records it for analysis with the SP800-90B non-IID
  statistical test tool. The test tool includes the gathering of raw entropy
  for one execution run as well as for the restart tests required in SP800-90B
  section 3.1.4. The tool adjusts the data to be processed by the SP800-90B
  statistical test tool. The SP800-90B statistical test tool provides the
  SP800-90B minimum entropy values.

#par(first-line-indent: 0pt)[In particular the first test covers the test
requirement of FIPS 140-2 IG 7.18.]

The kernel module provides the raw noise source data when it is compiled with
the option `BUILD_TESTING=1` of its Makefile: the file
`/sys/kernel/debug/esdm_es/esdm_raw_hires` delivers the difference of two
successive time stamps of a CPU divided by the GCD – undivided while the GCD
is not yet calculated – as a 64 bit value for each interrupt event. When the kernel module is loaded with the module parameter
`boot_raw_hires_test=1`, it records the first 1,024 interrupt events after it
registered its interrupt hook for the restart tests. The tools
`esdm-getrawentropy`, which reads this file when given with its option
`--debugfs-file`, and `esdm-extractlsb`, which extracts the bits to be
processed by the SP800-90B statistical test tool, are found in
tests/validation-helpers and are built with the meson option
`validation-helpers`.

=== FIPS 140-2 IG 7.18 Heuristic Analysis <sec:ig718-heuristic>

FIPS 140-2 IG 7.18 requires a heuristic analysis compliant to SP800-90B
section 3.2.2. The discussion of this SP800-90B requirement list is given in
section @sec:sp80090b.

=== FIPS 140-2 IG 7.18 Additional Comment 1 <sec:ig718-c1>

The first test referenced in section @sec:ig718-testing covers this
requirement.

The test collects the time stamps of interrupts as they are received by the
kernel module. Instead of having these interrupts processed by the kernel
module to add them to the per-CPU ring, they are sent to a user space
application for storing them to disk.

The collection of the interrupt data for the raw entropy testing is invoked
from the same code path that would otherwise add it to the per-CPU ring.
Thus, the test collects the data of the exact same time stamps that would
otherwise have been used by the ESDM as noise data. Thus, the testing does
not alter the ESDM processing.

However, the tester performing the test should observe the following caveat:
the raw entropy data obtained with the user space tool should be stored on
“disk space” that will not generate interrupts as otherwise the testing would
itself generate new interrupts and thus alter the measurement. For example, a
ramdisk can be used to store the raw entropy data while the test is ongoing.
On common Linux environments, the path `/dev/shm` is usually a ramdisk that
can readily be used as a target for storing the raw entropy data. If that
partition is non-existent, the tester should mount a ramdisk or use different
backing store that is guaranteed to not generate any interrupts when writing
data to it.

=== FIPS 140-2 IG 7.18 Additional Comment 2 <sec:ig718-c2>

The lowest entropy yield is analyzed by gathering raw entropy data received
from interrupts that come in high frequency. In this case, the time stamps
would be close together where the variations and thus the entropy provided
with these time stamps would be limited.

The extreme case would be to send a flood of ICMP echo request messages with a
size of only one byte to the system under test from a neighboring system that
has a close proximity with very little network latency. Each ICMP request
would trigger an interrupt as it is processed by the network card. The most
extreme case can be achieved when executing the ESDM in a virtual machine
where the VMM host sends a ping flood to the virtual machine. In this case,
network latency would be reduced to a minimum. In the subsequent sections,
test results are shown which are generated with an ESDM executing in a virtual
machine where the host sends a flood of ICMP echo request messages to trigger
a worst case measurement.

The entropy is not considered to degrade when using the hardware within the
environmental constraints documented for the used CPU. The online health tests
are intended to detect entropy source degradation. In case of online health
test failures, section @sec:health-tests explains the applied actions.

=== FIPS 140-2 IG 7.18 Additional Comment 3 <sec:ig718-c3>

The ESDM uses the following conditioning components:

- For collecting of entropy data from the entropy source, the time stamps are
  concatenated in the per-CPU rings of the kernel module.

- For reading the per-CPU rings and compressing the entropy data, the DRBG of
  the kernel module is used: the time stamps are the seed of a reseed of the
  DRBG, which then generates the output. The DRBG is the XDRBG-256 over the
  SHAKE256 of the kernel when the kernel provides its SHA-3 library
  (`CONFIG_CRYPTO_LIB_SHA3`), which is required from Linux 7.2 on, and the
  SP800-90A HMAC DRBG with SHA-512 of the kernel crypto API otherwise. The
  security strength of the ESDM is the minimum of the DRBG security strength
  of the ESDM and the security strength of 256 bits of the DRBG of the kernel
  module following @sp80090b section 3.1.5.1.1 table 1. The HMAC DRBG can be
  tested via ACVT, the kernel module verifies the XDRBG-256 with a
  known-answer test when it is loaded.

=== FIPS 140-2 IG 7.18 Additional Comment 4 <sec:ig718-c4>

The restart test is covered by the first test documented in section
@sec:ig718-testing.

=== FIPS 140-2 IG 7.18 Additional Comment 6 <sec:ig718-c6>

The entropy assessment usually shows this conclusion – tests performed on
Intel x86-based systems show the following conclusions:

The entropy rate for all devices validated with the raw entropy tests
outlined in section @sec:ig718-testing show that the minimum entropy values
are always above one bit of entropy per four data bits. The data bits are the
least significant bits of the time stamp generated by the raw noise.

Assuming the worst case that all other bits in the time delta have no
entropy, that entropy value above one bit of entropy applies to one time
stamp.

The kernel module continuously gathers time stamps to be combined with a DRBG
which is entropy preserving. The kernel module credits each time stamp with
$1 \/ #raw("ESDM_ES_OSR")$ bits of entropy, where the oversampling rate
`ESDM_ES_OSR` is set in its Makefile to a value between 1 and 25, 3 by
default. It delivers data to the DRNG only in blocks of 256 bits for which it
gathered the necessary time stamps. For example, with the default
oversampling rate the kernel module needs 768 time stamps for one block and
delivers no data to the DRNG as long as it received fewer time stamps. This
effectively implies that the ESDM assumes that one third of a bit of entropy
is received per time stamp.

As the kernel module maintains a DRBG, the entropy content of its output
cannot be larger than the security strength of the DRBG of 256 bits. The
per-CPU rings hold the time stamps received until the ESDM requests data –
once a ring is full, newly received time stamps are dropped until the next
request takes time stamps from it.

This implies that the ESDM data generated from the DRBG has (close to) 1 bit
of entropy per data bit.

=== FIPS 140-2 IG 7.18 Additional Comment 9 <sec:ig718-c9>

N/A as the raw entropy is a non-IID source and processed with the non-IID
SP800-90B statistical tests as documented in section @sec:ig718-testing.

== SP800-90B Compliance <sec:sp80090b>

This chapter analyzes the compliance of the ESDM to the SP800-90B @sp80090b
standard considering the FIPS 140-2 implementation guidance 7.18 which alters
some of the requirements mandated by SP800-90B.

=== SP800-90B Section 3.1.1 <sec:90b-311>

The collection of raw data for the SP800-90B entropy testing documented in
section @sec:ig718-testing uses 1,000,000 consecutive time stamps obtained in
one execution round.

The restart tests documented in section @sec:ig718-testing perform 1,000
restarts collecting 1,000 consecutive time stamps.

=== SP800-90B Section 3.1.2 <sec:90b-312>

The entropy assessment of the raw entropy data including the restart tests
follows the non-IID track.

=== SP800-90B Section 3.1.3 <sec:90b-313>

Please see section @sec:ig718-c6: The entropy of the raw noise source data is
believed to have more than one bit of entropy per time stamp to allow to
conclude that one output block of the ESDM has (close to) one bit of entropy
per data bit. Yet, the kernel module credits only one bit of entropy per
`ESDM_ES_OSR` time stamps, i.e. a third of a bit per interrupt event with the
default oversampling rate, which can be configured at compile time.

The first test referenced in section @sec:ig718-testing performs the following
operations to provide the SP800-90B minimum entropy estimate:

+ Gathering of the raw entropy data of the time stamps.

+ Obtaining the four least significant bits of each time stamp and concatenate
  them to form a bit stream.

+ The bit stream is processed with the SP800-90B entropy testing tool to
  gather the minimum entropy.

#par(first-line-indent: 0pt)[For example, on an Intel Core i7 Skylake system
executing the ESDM in a KVM guest, the SP800-90B tool shows the following
minimum entropy values when multiplying the SP800-90B tool bit-wise minimum
entropy by four since four bits are processed: 3.452064.]

=== SP800-90B Section 3.1.4 <sec:90b-314>

For the restart tests, the raw entropy data is collected for the first 1,000
interrupt events received by the ESDM after a reboot of the operating system.
That means, for one collection of raw entropy the test system is rebooted.
This implies that for gathering the 1,000 restart samples, the test system is
rebooted 1,000 times. The kernel module records the time stamps of the
restart tests when it is loaded with the module parameter
`boot_raw_hires_test=1` (section @sec:ig718-testing). As the kernel module
registers its interrupt hook only once the Linux kernel RNG is initialized,
these are the first interrupt events after that point in time.

Each restart test round stores its time stamps in an individual file.

After all raw entropy data is gathered, a matrix is generated where each line
in the matrix lists the time stamp of one restart test round. The first column
of the matrix, for example, therefore contains the first time stamp for each
boot cycle of the Linux kernel with the ESDM.

The SP800-90B minimum entropy values column and row-wise is calculated the
same way as outlined above:

+ Gathering of the raw restart entropy data of the time stamps.

+ Obtaining the four least significant bits of each time stamp either
  row-wise or column-wise and concatenate them to form a bit stream. There are
  1,000 bit streams row-wise, and 1,000 bit streams column-wise boundary
  generated.

+ The bit streams are processed with the SP800-90B entropy testing tool to
  gather the minimum entropy.

#par(first-line-indent: 0pt)[In a following step, the sanity check outlined
in SP800-90B section 3.1.4.3 is applied to the restart test results. The steps
given in 3.1.4.3 are applied.]

For example, on an Intel Core i7 Skylake system executing the ESDM in a KVM
guest, the SP800-90B tool shows the following minimum entropy values when
multiplying the SP800-90B tool bit-wise minimum entropy by four since eight
bits are processed:

- Using the 8 least significant bits of the time stamps in column-wise
  assessment – lowest entropy value of all 1,000 column entries: 3.455504

- Using the 8 least significant bits of the time stamps in row-wise
  assessment – lowest entropy value of all 1,000 column entries: 3.393808

- Sanity check of the 1,000 x 1,000 matrix passes with value of one

#par(first-line-indent: 0pt)[With the shown values, the restart test
validation passes according to SP800-90B section 3.1.4.]

=== SP800-90B Section 3.1.5 <sec:90b-315>

The conditioning component applied to the interrupt entropy source is the
DRBG of the kernel module as outlined in section @sec:components: the DRBG is
seeded with the time stamps collected from the per-CPU rings and then
generates the output block handed to the ESDM. The following discussion is
applicable to both operations.

#paragraph[Truncation][The truncation operation ensures that the entropy in
that data is at maximum the truncated hash.]

The time stamps are not truncated: the kernel module stores the entire 64 bit
time stamp divided by the GCD, whereas the quantitative measurement of the
existing entropy using the SP800-90B tool set is performed using the
truncated data of its least significant bits. The kernel module implies an
entropy of $1 \/ #raw("ESDM_ES_OSR")$ bits per time stamp which means that
the entropy present in the data is always smaller as the data size.

The truncation operation of the DRBG generating at most its security strength
of 256 bits per output block verifies that the truncated data contains at
most the amount of entropy as the generated data size. The remaining part of
the data is not exported to any external entity but remains in the state of
the DRBG - when new random data is generated, the current DRBG state is
always used. This is a deviation from SP800-90B
section 3.1.5.1.2 which requires a relative reduction of entropy. This
statement is considered inconsistent with the statement implied in table 1
@sp80090b and therefore wrong depicted with the following analogy: Assume to
have a buffer of 512 bits of data having 256 bits of entropy. When hashing it
with SHA-512, the resulting message digest of 512 bits has 256 bits of
entropy. When truncating the digest to 256 bits, SP800-90B states the entropy
is 128 bits. However, SP800-90B section 3.1.5.1.1 table 1 states that full
entropy is given to approved hash functions. Assume to use a SHA-512/256 which
has a digest size of 256 bits and thus could transport 256 bits of entropy
following table 1. This SHA-512/256 hash operation calculates a SHA-512 hash
truncated to 256 bits. Albeit the cryptographic operation of SHA-512/256 is
identical to the ESDM-applied truncation#footnote[With the HMAC DRBG, the
kernel module uses a hash of SHA-512 and fills a buffer of the DRNG security
strength size, i.e. 256 bits.], SP800-90B table 1 awards 256 bits of
entropy to SHA-512/256 but at the same time SP800-90B would apply only 128
bits to the ESDM-applied truncation. Due to this inconsistency, the ESDM
applies the entropy behavior implicitly specified in table 1, i.e. the entropy
is the minimum of the available entropy and the message digest size.
Furthermore, applying the Output\_Entropy formula for a vetted conditioning
component of a truncated hash, the following calculation applies. This
calculation shows the entropy rate of a SHA-512 hash processing a buffer with
1024 bits that contains, say, 384 bits of entropy and truncating it to 256
bits. This means, the formula for
$h_("out"_("SHA-512 trunc")) = OE_("SHA-512 trunc")(1024, 256, 512, 384)$
following @sp80090b section 3.1.5.1.2 is calculated:

#display($P_"high" = 2^(-384)$)
#display($P_"low" = (1 - 2^(-384)) / (2^1024 - 1) approx 2^(-1024)$)
#display($n = min(256, 512) = 256$)
#display($psi = 2^(1024-256) dot 2^(-1024) + 2^(-384) = 2^(-256) + 2^(-384)
  approx 2^(-256) \
  U = 2^(1024-256) + sqrt(2 dot 256 dot (2^(1024-256)) dot ln(2))
  = 2^768 + sqrt(2^777 dot ln(2)) approx 2^768 \
  omega = 2^768 times 2^(-1024) = 2^(-256) \
  underline(OE_("SHA-512 trunc")(1024, 256, 512, 384)
  = -log_2(max(2^(-256), 2^(-256))) = 256)$)

Even after calculating other entropy rates using the same formula, the
following conclusion for the truncation can be applied:

#display($underline(OE_"trunc" (n_"in", n_"out", n w, h_"in")
  = min(n_"in", n_"out", n w, h_"in"))$)

This function is applied by the ESDM for hash truncation.

#paragraph[Concatenation][When applying a concatenation operation, the ESDM
simply adds the entropy delivered with each data entry part.]

#paragraph[DRBG][The input of the DRBG $n_"in"$ is fixed as it processes the
time stamps collected from the per-CPU rings for one output block.]

The output of the DRBG $n_"out"$ is fixed to its security strength of 256
bits per output block – only the second block of a request for 320 or 384
bits holds 64 or 128 bits. The kernel module generates no output at all as
long as the per-CPU rings hold too few time stamps for all blocks of a
request.

The following DRBGs are used by the kernel module depending on the kernel:

- Linux kernels providing the SHA-3 library (`CONFIG_CRYPTO_LIB_SHA3`), which
  Linux 7.2 and later require: XDRBG-256 with SHAKE256 and a state of 512 bits

- Older Linux kernels: SP800-90A HMAC DRBG with SHA-512
  (`drbg_nopr_hmac_sha512`), which requires the kernel patch exporting the
  DRBG functions

#par(first-line-indent: 0pt)[In the following, the different DRBG operations
specified in section @sec:data-processing are applied as follows:]

- Compression of entropy delivered from the interrupt entropy source when
  seeding the DRBG with the time stamps collected from the per-CPU rings.

- Generation of the output block of the interrupt entropy source from the
  DRBG state.

#par(first-line-indent: 0pt)[The requirement of @sp80090b section 3.1.6
states that when combining two or more noise sources using a vetted
conditioning component, only one noise source is to be credited with entropy.
This requirement is met as follows: according to @sp80090b section 2.2 a noise
source is the phenomenon delivering entropy. The noise source data is
post-processed with conditioning components and health tests to form an
entropy source. Based on this statement, the per-CPU rings together with the
DRBG of the kernel module form one entropy source that is compliant to
SP800-90B.]

Note, the DRBG of the kernel module ensures backward secrecy when calculating
the next round of random numbers used to fill the seed buffer used to seed
the DRBG of the ESDM from the entropy sources: what the DRBG absorbed stays in
its state and goes into all of its later output.

#paragraph[Approach for Calculating Entropy][Although the aforementioned
sections explain that the input and output sizes may not be fixed, in regular
operation they are quasi-fixed. In order to reseed a DRNG, 256 bits of entropy
are to be generated from the noise source. Although the per-CPU rings
receive interrupt time stamps continuously, only the entropy from
$256 dot #raw("ESDM_ES_OSR")$ time stamps – 768 time stamps by default – plus
the time stamps of the oversampling in FIPS mode are required as illustrated
below. When all per-CPU rings have received too little interrupt time stamps
to satisfy the 256 bit entropy request, no output data is generated. This
commonly happens during boot or at runtime when too much entropy is
requested. Therefore, the interrupt entropy source never causes (re)seed
events of the DRNG with less entropy than it credits.]

With the given combination of the DRBG as outlined above, the following
approach for the entropy calculation is taken for each of the data processing
steps outlined in section @sec:data-processing:

- Function @eq:ep-cpu:

  - $n_("in"_("DRBG"))$ equals to 64 bits times the number of time stamps
    collected from the per-CPU rings for one output block, which are
    $(256 + o) dot #raw("ESDM_ES_OSR")$ time stamps with the oversampling $o$
    of 65 bits in FIPS mode – 129 bits for the first seed of the DRBG – and of
    0 bits otherwise. With the default oversampling rate, $n_("in"_("DRBG"))$
    is 49,152 bits, and 61,632 bits in FIPS mode#footnote[The per-CPU rings
    hold 4,095 time stamps each with the default oversampling rate and grow
    with larger oversampling rates. When a different oversampling rate is
    chosen, the value needs to be adjusted accordingly. Yet, such modified
    value has no impact to the entropy analysis.].

  - $n_("out"_("DRBG"))$ is the security strength of the DRBG of 256 bits.

  - $n w_("DRBG")$ is 512 bits: the state of the XDRBG-256 and the internal
    width of SHA-512 of the HMAC DRBG.

- Function @eq:ep-all:

  - $n_("in"_("out"))$ equals to the size of the DRBG state.

  - $n_("out"_("out"))$ is the security strength of the DRBG of 256 bits.

  - $n w_("out")$ is 512 bits like $n w_("DRBG")$.

=== SP800-90B Section 3.1.5.1 <sec:90b-3151>

The DRBG of the kernel module as outlined above, which is based on SHA-512
or SHAKE256, is considered to be a vetted conditioning component. Thus the
entropy rate of the DRBG output is calculated as follows using the
aforementioned variables for the DRBG. In addition, the following
consideration applies:

- The entropy content of the input $h_("in"_("DRBG"))$: The input entropy of
  the DRBG seeded with the time stamps collected from the per-CPU rings is
  equal to the entropy provided by these time stamps and the entropy already
  present in the DRBG state considering that both data components are
  processed at the same time to form a new DRBG state. Of course, the entropy
  held in the DRBG state will never be larger than its size which is
  compliant to @sp80090b section 3.1.5.1.1 table 1.

- The entropy content of the input $h_("in"_("out"))$: The input entropy of
  the generate operation of the DRBG is equal to the entropy found in the
  DRBG state. Again, the entropy generated by the DRBG will never be larger
  than its security strength which is compliant to @sp80090b section
  3.1.5.1.1 table 1.

#paragraph[Function @eq:ep-cpu Output\_Entropy][To perform a calculation of
the Output\_Entropy of a conditioning component, the input entropy must be
considered. The heuristic input entropy awarded for one time stamp processed
by the ESDM is given in equation @eq:h-t. Due to the concatenation operation
of time stamps, the entropy of multiple time stamps can be added.]

The following calculations illustrate the formula for SHA-512 and SHA-256
with the per-CPU entropy pool of earlier versions of the interrupt entropy
source, which hashed time stamps of 8 bits, each credited with one bit of
entropy. For this hash, the entropy when 1,024 time stamps are received
is $h_("out"_("SHA-512")) = OE_("SHA-512")(8192, 512, 512, 1024)$ following
@sp80090b section 3.1.5.1.2. Therefore, the following calculation is
applicable:

#display($P_"high" = 2^(-1024)$)
#display($P_"low" = (1 - 2^(-1024)) / (2^8192 - 1) approx 2^(-8192)$)
#display($n = min(512, 512) = 512$)
#display($psi = 2^(8192-512) dot 2^(-8192) + 2^(-1024) = 2^(-512) + 2^(-1024)
  approx 2^(-512) \
  U = 2^(8192-512) + sqrt(2 dot 512 dot (2^(8192-512)) dot ln(2))
  = 2^7680 + sqrt(2^7690 dot ln(2)) approx 2^7680 \
  omega = 2^7680 times 2^(-8192) = 2^(-512) \
  underline(OE_("SHA-512")(8192, 512, 512, 1024)
  = -log_2(max(2^(-512), 2^(-512))) = 512)$)

As a complement, the same calculation is provided when only one time stamp is
received for the formula
$h_("out"_("SHA-512")) = OE_("SHA-512")(8, 512, 512, 1)$

#display($P_"high" = 2^(-1)$)
#display($P_"low" = (1 - 2^(-1)) / (2^8 - 1) approx 2^(-9)$)
#display($n = min(512, 512) = 512$)
#display($psi = 2^(8-512) dot 2^(-9) + 2^(-1) = 2^(-513) + 2^(-1)
  approx 2^(-1) \
  U = 2^(8-512) + sqrt(2 dot 512 dot (2^(8-512)) dot ln(2))
  = 2^(-504) + sqrt(2^(-494) dot ln(2)) approx 2^(-247) dot sqrt(ln(2))
  approx 2^(-248) \
  omega = 2^(-248) times 2^(-9) = 2^(-257) \
  underline(OE_("SHA-512")(8, 512, 512, 1)
  = -log_2(max(2^(-257), 2^(-1))) = 1)$)

The calculation can be generalized with the following formula:

#display($h_("out"_("SHA-512")) = OE_("SHA-512")
  = min(h_"in", n_("out"_("SHA-512")))$)

When using SHA-256, the same type of calculation can be provided. The first
set of formulas show the case when 1,024 time stamps are received and thus for
$h_("out"_("SHA-256")) = OE_("SHA-256")(8192, 256, 256, 1024)$:

#display($P_"high" = 2^(-1024)$)
#display($P_"low" = (1 - 2^(-1024)) / (2^8192 - 1) approx 2^(-8192)$)
#display($n = min(256, 256) = 256$)
#display($psi = 2^(8192-256) dot 2^(-8192) + 2^(-1024) = 2^(-256) + 2^(-1024)
  approx 2^(-256) \
  U = 2^(8192-256) + sqrt(2 dot 256 dot (2^(8192-256)) dot ln(2))
  = 2^7936 + sqrt(2^7945 dot ln(2)) approx 2^7936 \
  omega = 2^7936 times 2^(-8192) = 2^(-256) \
  underline(OE_("SHA-256")(8192, 256, 256, 1024)
  = -log_2(max(2^(-256), 2^(-256))) = 256)$)

As a complement, the same calculation is provided when only one time stamp is
received for the formula
$h_("out"_("SHA-256")) = OE_("SHA-256")(8, 256, 256, 1)$

#display($P_"high" = 2^(-1)$)
#display($P_"low" = (1 - 2^(-1)) / (2^8 - 1) approx 2^(-9)$)
#display($n = min(256, 256) = 256$)
#display($psi = 2^(8-256) dot 2^(-9) + 2^(-1) = 2^(-257) + 2^(-1)
  approx 2^(-1) \
  U = 2^(8-256) + sqrt(2 dot 256 dot (2^(8-256)) dot ln(2))
  = 2^(-248) + sqrt(2^(-239) dot ln(2)) approx 2^(-120) dot sqrt(ln(2))
  approx 2^(-121) \
  omega = 2^(-121) times 2^(-9) = 2^(-130) \
  underline(OE_("SHA-256")(8, 256, 256, 1)
  = -log_2(max(2^(-130), 2^(-1))) = 1)$)

Again, the calculation can be generalized with the following formula:

#display($h_("out"_("SHA-256")) = OE_("SHA-256")
  = min(h_"in", n_("out"_("SHA-256")))$)

Comparing the conclusions for SHA-512 and SHA-256, both allow to draw the
general conclusion that underlies the entire entropy assessment and therefore
data entropy management applied by the ESDM for all vetted conditioning
operations:

$ h_("out"_"vetted") = OE_"vetted" = min(h_"in", n_("out"_"vetted")) $
<eq:vetted>

For the function @eq:ep-cpu as applied by the kernel module in FIPS mode, the
same calculation with the parameters given in section @sec:90b-315 for one
output block of the DRBG yields
$h_("out"_("DRBG")) = OE_("DRBG")(61632, 256, 512, 321)$:

#display($P_"high" = 2^(-321)$)
#display($P_"low" = (1 - 2^(-321)) / (2^61632 - 1) approx 2^(-61632)$)
#display($n = min(256, 512) = 256$)
#display($psi = 2^(61632-256) dot 2^(-61632) + 2^(-321) = 2^(-256)
  + 2^(-321) approx 2^(-256) \
  U = 2^(61632-256) + sqrt(2 dot 256 dot (2^(61632-256)) dot ln(2))
  = 2^61376 + sqrt(2^61385 dot ln(2)) approx 2^61376 \
  omega = 2^61376 times 2^(-61632) = 2^(-256) \
  underline(OE_("DRBG")(61632, 256, 512, 321)
  = -log_2(max(2^(-256), 2^(-256))) = 256)$)

#paragraph[Function @eq:ep-all][The function @eq:ep-all uses the same DRBG
as the discussed in the preceding section. Thus, the conclusion drawn with
equation @eq:vetted applies here as well.]

#paragraph[Conclusions for Output\_Entropy][As stated in @sp80090b section
3.1.5.1.2, vetted conditioning components are allowed to claim full entropy.
In case of full entropy, the following is applied which matches exactly
analysis and conclusion of equation @eq:vetted:]

- $h_("out"_("SHA-512")) = min(h_"in", n_("out"_("SHA-512")))$,

- $h_("out"_("SHA-256")) = min(h_"in", n_("out"_("SHA-256")))$, or

- $h_("out"_("DRBG")) = min(h_"in", n_("out"_("DRBG")))$ with
  $n_("out"_("DRBG")) = 256$.

#par(first-line-indent: 0pt)[Based on that conclusion, the entropy rate for
each processing step given in section @sec:data-processing can be illustrated
in the following. This entropy assessment uses $n_"out"$ which is the
security strength of the DRBG of the kernel module of 256 bits.]

#paragraph[Heuristic Entropy Assessment][The heuristic entropy value for the
individual time stamps is defined with the following equation applicable when
a high-resolution timer is present – without a high-resolution timer the
kernel module does not load, and with a timer that the GCD shows to be too
coarse it credits no entropy:]

$ h_t = 1 / #raw("ESDM_ES_OSR") $ <eq:h-t>

Note, in order to assess whether the ESDM heuristic entropy value is
appropriate, it must be compared with the entropy analysis result received
from practical measurements such as outlined in sections @sec:90b-313 and
@sec:90b-314. This comparison must show that the heuristic entropy value is
always lower and thus more conservative than what the measurements show on
target devices.

The entropy in the concatenated time stamps collected from the interrupt as
well as scheduler per-CPU rings for one output block is calculated as the sum
of the entropy of these time stamps. As $N = (256 + o) dot
#raw("ESDM_ES_OSR")$ time stamps are collected for one output block with the
oversampling $o$ given in section @sec:90b-315, this sum is:

$ h_("CP") = sum_(n=1)^(N) (h_t)_n = 256 + o $ <eq:h-cp>

For the seeding of the DRBG of the kernel module as specified by equation
@eq:ep-cpu, the following entropy rate applies. This formula implies that the
DRBG state holds the sum of the entropy of the time stamps it is seeded with
and the entropy remained in the DRBG state capped by the security strength of
the DRBG. Time stamps received while the per-CPU ring of their CPU is full
are dropped and do not contribute.

$ h_("DRBG"_n) = min(h_("CP"_n) + h_("DRBG"_(n-1)), n_"out") $ <eq:h-pool>

Similarly, the following equation applies to the entropy of the auxiliary pool
maintenance as specified by equation @eq:ap. Note, although this entropy
source is not considered to be modeled in this chapter, the formula is still
provided illustrating the entropy accounting of the auxiliary pool, which is
an XDRBG-256 of the ESDM. This formula implies that auxiliary pool holds the
sum of the entropy of the received data capped by the size of the XDRBG state
of 512 bits. Again, this operation implies that the XDRBG compresses the
entropy available in the different input data.

$ h_("aux pool") = min(h_("in"_("aux pool")) + h_("aux pool"), 512) $
<eq:h-aux>

The following equation applies when calculating the interrupt and
scheduler-based entropy source output block as specified by equation
@eq:ep-all. The kernel module credits the output block only with the entropy
of the time stamps it collected for this block less the oversampling $o$,
capped by the security strength of the DRBG – the entropy remaining in the
DRBG state from earlier seeds is not credited. An output block is only
generated if this entropy is at least the security strength of the DRBG.

$ h_B = min(h_("CP"_n) - o, n_"out") $ <eq:h-hash-pools>

The entropy present in the interrupt and scheduler-based entropy source
buffer is the minimum of the entropy found in the output blocks and the
requested amount of bits which is equal to the security strength of the DRBG
– requests for 320 or 384 bits in FIPS mode take two output blocks:

$ "requested size"_s = "security strength" = 256 $ <eq:requested>

$ h_s = min(h_B, "requested size"_s) $ <eq:h-s>

The entropy of the temporary seed buffer following equation @eq:vetted is
simply an addition of the entropy values credited for each of the entropy
source with $h_A$ denominating the auxiliary entropy entropy rate, $h_E$
references the IRQ ES entropy rate, $h_S$ references the scheduler ES entropy
rate, $h_(E^"eBPF")$ and $h_(S^"eBPF")$ reference the entropy rates of the
eBPF-based IRQ and scheduler ES, $h_J$ covers the Jitter RNG ES entropy rate,
$h_C$ references the CPU ES entropy rate, $h_K$ references the kernel ES
entropy rate, $h_H$ denominates the HWRAND entropy source, $h_M$ the TPM 2.0
entropy source, $h_(J^"K")$ the kernel Jitter RNG entropy source, and $h_X$
the external entropy source:

$ h_T = h_A + h_E + h_S + h_(E^"eBPF") + h_(S^"eBPF") + h_J + h_C + h_K + h_H
  + h_M + h_(J^"K") + h_X $ <eq:h-t-buffer>

The result of the formulas show that the entropy is simply a sum of the
entropy of all input events capped to the security strength of the used
DRBG.

When generating the random numbers filling the interrupt entropy source
buffer, the entropy is debited by taking the time stamps from the per-CPU
rings: the time stamps for an output block are taken from the ring of the
first CPU as far as it holds time stamps, the yet missing time stamps from
the rings of the following CPUs.

For example, assume that the slow noise source buffer is filled with
$h_s = 256$ bits outside of FIPS mode, i.e. with 768 time stamps with the
default oversampling rate. Assume further, the per-CPU rings of the assumed 2
CPUs contain $N_("CPU0") = 555$ and $N_("CPU1") = 369$ time stamps. The
debit operation performs:

+ $N_("CPU0") = 555 - 555 = 0$ leaving
  $N_(s_"not debited") = 768 - 555 = 213$

+ $N_("CPU1") = 369 - 213 = 156$

=== SP800-90B Section 3.1.6 <sec:90b-316>

The ESDM uses the following noise source for the interrupt entropy source:

- The noise source of the timing of the occurrence of interrupts. The entire
  SP800-90B analysis covers this one noise source. Thus, the requirements in
  this section for the interrupt noise source are trivially met.

#par(first-line-indent: 0pt)[All data is processed by the vetted conditioning
component of the DRBG of the kernel module before it is injected as seed data
into the DRNG. Thus,
this operation complies with the last paragraph of section 3.1.6.]

=== SP800-90B Section 3.2.1 Requirement 1 <sec:90b-321-1>

This entire document is intended to provide the required analysis.

=== SP800-90B Section 3.2.1 Requirement 2 <sec:90b-321-2>

This entire document in general and chapter @sec:irq-assessment in particular
is intended to provide the required analysis.

=== SP800-90B Section 3.2.1 Requirement 3 <sec:90b-321-3>

There is no specific operating condition other than what is needed for the
operating system to run since the noise source is a complete software-based
noise source.

The only dependency the noise source has is a high-resolution timer which
does not change depending on the environmental conditions.

=== SP800-90B Section 3.2.1 Requirement 4 <sec:90b-321-4>

This document explains the architectural security boundary.

The boundary of the implementation is the source code files provided as part
of the software delivery. This source code contains API calls which are to be
used by entities using the ESDM.

=== SP800-90B Section 3.2.1 Requirement 5 <sec:90b-321-5>

The output of the DRBG of the kernel module seeded with the time stamps of
the per-CPU rings is the output of the interrupt noise source. I.e. the DRBG
generates the data that is given to the DRNG when requesting seeding with the
IOCTL `ESDM_IRQ_ENT_BUF` of /dev/esdm\_es.

The noise source output without the DRBG operation is accessed with
specific tools which add interfaces that are not present and thus not usable
when employing the ESDM in production mode. These additional interfaces are
used for gathering the data used for the analysis documented in section
@sec:90b-313. These interfaces perform the following operation:

+ Switch the kernel module into raw entropy generation mode by reading the
  raw entropy interface. This implies that each raw entropy event is fed to
  the raw entropy collection interface and not added to the per-CPU ring or
  otherwise used.

+ When an interrupt event is received, forward the difference of its time
  stamp to the time stamp of the preceding interrupt event of the CPU, both
  divided by the GCD, to a ring buffer of 1,024 entries. This operation is
  performed repeatedly until the user space application read that ring
  buffer – for the restart tests until the ring buffer is full.

+ When an application requests the reading of the ring buffer, the data is
  extracted from the kernel and the ring buffer is cleared.

#par(first-line-indent: 0pt)[With this approach, the actual interrupt events
which would be processed by the ESDM are obtained.]

The kernel interface is only present if the kernel module is compiled with
the option `BUILD_TESTING=1` of its Makefile, which defines
CONFIG\_ESDM\_RAW\_HIRES\_ENTROPY. This option should not be set in
production kernel modules. In addition, the kernel module neither creates the
interface nor hands out data while the kernel is in lockdown mode.

=== SP800-90B Section 3.2.1 Requirement 6 <sec:90b-321-6>

Please see section @sec:ig718-c1 for details how and why the raw entropy
extraction does not substantially alter the noise source behavior.

=== SP800-90B Section 3.2.1 Requirement 7 <sec:90b-321-7>

See section @sec:90b-314 for a description of the restart test.

=== SP800-90B Section 3.2.2 Requirement 1 <sec:90b-322-1>

This entire document provides the complete discussion of the noise source.

=== SP800-90B Section 3.2.2 Requirement 2 <sec:90b-322-2>

The noise source is based on the receipt of interrupts. The receipt of
interrupts follows the usage of the system. The more I/O is performed with the
system, the more interrupts are received by the ESDM. The entropy rate only is
a function of the received I/O events and the timer and does not depend on any
other system property such as physical characteristics (e.g. temperature
variations or voltage/current variations). This finding is consistent with the
fact that the noise source is a pure software-based noise source which relies
on the presence of a high-resolution timer. Note, the used timer is a cycle
counter that increments with a given rate.

=== SP800-90B Section 3.2.2 Requirement 3 <sec:90b-322-3>

See sections @sec:90b-3151 for a discussion of the entropy provided by the
interrupt noise source.

A stochastic model is not provided.

=== SP800-90B Section 3.2.2 Requirement 4 <sec:90b-322-4>

The noise source is expected to execute in the kernel address space. This
implies that the operating system process isolation and memory separation
guarantees that adversaries cannot gain knowledge about the ESDM operation.

=== SP800-90B Section 3.2.2 Requirement 5 <sec:90b-322-5>

The output of the noise source is non-IID as it rests on the execution time of
a fixed set of CPU operations and instructions.

=== SP800-90B Section 3.2.2 Requirement 6 <sec:90b-322-6>

The noise source generates the data via the DRBG generate function as
outlined in section @sec:90b-315.

The DRBG generates fixed-length output blocks of 256 bits. Instead of output
blocks with less entropy, no data is generated as outlined in section
@sec:90b-3151.

=== SP800-90B Section 3.2.2 Requirement 7 <sec:90b-322-7>

N/A as no additional noise source is implemented with the interrupt entropy
source.

Though, the ESDM employs complete self-contained other entropy sources which
may be compliant to SP800-90B by itself. To seed the DRNG maintained by the
ESDM, the output of all entropy sources are concatenated compliant to
SP800-90C as outlined in section @sec:sp80090c.

=== SP800-90B Section 3.2.3 Requirement 1 <sec:90b-323-1>

The conditioning component is the DRBG of the kernel module. See section
@sec:90b-315 for a discussion of the input and output sizes.

=== SP800-90B Section 3.2.3 Requirement 2 <sec:90b-323-2>

The HMAC DRBG of the kernel crypto API used for the conditioning component
is ACVP-testable. The XDRBG-256 is verified with its known-answer test when
the kernel module is loaded. The kernel module compiles the XDRBG-256
implementation of the ESDM, which the ESDM test suite verifies against the
known answer of its reference implementation.

=== SP800-90B Section 3.2.3 Requirement 3 <sec:90b-323-3>

For the defined DRBGs, no key is required: their state is derived from the
seed data only.

=== SP800-90B Section 3.2.3 Requirement 4 <sec:90b-323-4>

For the defined DRBGs, no key is required: their state is derived from the
seed data only.

=== SP800-90B Section 3.2.3 Requirement 5 <sec:90b-323-5>

The conditioning component is the DRBG of the kernel module. See section
@sec:90b-3151 for a discussion of the narrowest internal width and the output
block size.

=== SP800-90B Section 3.2.4 Requirement 1 <sec:90b-324-1>

Test tools for measuring raw entropy are provided with the ESDM source code in
tests/validation-helpers. These tools can be used by everybody without
further knowledge of the ESDM.

=== SP800-90B Section 3.2.4 Requirement 2 <sec:90b-324-2>

The operation of the test tools for gathering raw data are discussed in
section @sec:90b-313. This explanation shows that the raw unconditioned data
is obtained.

=== SP800-90B Section 3.2.4 Requirement 3 <sec:90b-324-3>

The provided tools for gathering raw entropy contains exact steps how to
perform the tests. These steps do not require any knowledge of the noise
source.

=== SP800-90B Section 3.2.4 Requirement 4 <sec:90b-324-4>

The raw entropy tools can be executed on the same environment that hosts the
ESDM. Thus, the data is generated under normal operating conditions.

=== SP800-90B Section 3.2.4 Requirement 5 <sec:90b-324-5>

The raw entropy tools can be executed on the same environment that hosts the
ESDM. Thus, the data is generated on the same hardware and operating system
that executes the ESDM.

=== SP800-90B Section 3.2.4 Requirement 6 <sec:90b-324-6>

The test tools are publicly available with the ESDM source code (appendix
@sec:source-code) allowing the replication of any raw entropy measurements.

=== SP800-90B Section 3.2.4 Requirement 7 <sec:90b-324-7>

Please see section @sec:ig718-c1 for details how and why the raw entropy
extraction does not substantially alter the noise source behavior.

=== SP800-90B Section 4.3 Requirement 1 <sec:90b-43-1>

The implemented health tests comply with SP800-90B sections 4.4 as described
in section @sec:90b-44.

=== SP800-90B Section 4.3 Requirement 2 <sec:90b-43-2>

When either health test fails, the kernel module:

- Emits a failure log,

- Resets the noise source by discarding the time stamps collected in the
  per-CPU rings, and

- Restarts the SP800-90B startup health tests.

#par(first-line-indent: 0pt)[This implies that no data is produced by the
ESDM (including its DRNG) when using the SP800-90B compliant external
interfaces.]

Both health tests apply two cut-off values: reaching the cut-off value for
the significance level of $alpha = 2^(-30)$ triggers the reset described
above. Reaching the cut-off value for the significance level of
$alpha = 2^(-60)$ is considered a permanent failure, which in addition
restarts the counting of both health tests and causes a kernel panic if the
kernel module is loaded with the module parameter
`esdm_panic_on_permanent_health_failure=1`.

=== SP800-90B Section 4.3 Requirement 3 <sec:90b-43-3>

The following false positive probability rates are applied:

- RCT: The false positive rate is $alpha = 2^(-30)$ and therefore complies
  with the recommended false positive probability.

- APT: The cut-off value is set to 459 compliant to SP800-90B section 4.4.2
  for non-binary data at a significance level of $alpha = 2^(-30)$ with time
  stamp is assumed to at least provide $1 \/ #raw("ESDM_ES_OSR")$ bit of
  entropy, i.e. H = 1/3 with the default oversampling rate – the cut-off
  value is 325 for H = 1#footnote[Note, the referenced Excel function seems to
  be imprecise when calculating the value. The data has been obtained using
  R-Project with the formula of
  $2 + "qbinom"(1 - 2^(-30), 511, 2^(-1 \/ #raw("ESDM_ES_OSR")))$, which
  accounts for the first sample of the window being the base value. The
  cut-off values for $alpha = 2^(-60)$ are calculated with a SageMath
  script.].

=== SP800-90B Section 4.3 Requirement 4 <sec:90b-43-4>

The kernel module applies a startup health test of 1,024 noise source
samples.
Additional tests are applied. The collected noise source samples are re-used
for the generation of random numbers if the startup test was successful.

=== SP800-90B Section 4.3 Requirement 5 <sec:90b-43-5>

The noise source supports on-demand testing in the sense that the caller may
restart the kernel.

=== SP800-90B Section 4.3 Requirement 6 <sec:90b-43-6>

The health tests are applied to the raw, unconditioned time stamp data
directly obtained from the noise source before they are injected into the
per-CPU ring and further processed with the DRBG conditioning component.

=== SP800-90B Section 4.3 Requirement 7 <sec:90b-43-7>

The health tests are documented with section @sec:health-tests.

The tests are executed as follows when the kernel is booted in FIPS mode
with the kernel command line option `fips=1`:

- During startup, the RCT and the APT are applied to 1,024 samples. The
  startup test can be triggered again when the caller reboots the kernel.

- At runtime, the RCT is applied to each received time stamp. The APT collects
  512 time stamps. The APT is calculated over all 512 time stamps. If the test
  fails, the entropy source is reset to drop all existing entropy – the time
  stamps collected in the per-CPU rings – and the startup testing is
  performed again.

=== SP800-90B Section 4.3 Requirement 8 <sec:90b-43-8>

There are no currently known suspected noise source failure modes.

=== SP800-90B Section 4.3 Requirement 9 <sec:90b-43-9>

N/A as the noise source is pure software. The software is expected to execute
on hardware operating in its defined nominal operating conditions.

=== SP800-90B Section 4.4 <sec:90b-44>

The health tests described in section @sec:health-tests are applicable to
cover the requirements of SP800-90B health tests.

The SP800-90B compliant health tests are implemented with the following
rationale:

/ RCT: The Repetition Count Test implemented by the ESDM compares two
  back-to-back time stamps to verify that they are not identical. If the
  number of identical back-to-back time stamps reaches the cut-off value of
  $30 dot #raw("ESDM_ES_OSR")$, i.e. 90 with the default oversampling rate,
  the RCT test raises a failure that is reported and causes a reset of the
  entropy source. The RCT uses the a cut-off value that is based on the
  following: $alpha = 2^(-30)$ compliant to FIPS 140-2 IG 9.8 and compliant
  to SP800-90B which mandates this value to be in the range
  $2^(-40) <= alpha <= 2^(-20)$. In addition, one time stamp is assumed to at
  least provide $1 \/ #raw("ESDM_ES_OSR")$ bit of entropy, i.e. $H = 1 \/ 3$
  with the default oversampling rate. When applying these values to the
  formula given in SP800-90B section 4.4.1, the cut-off value of
  $1 + 30 dot #raw("ESDM_ES_OSR")$, i.e. 91, is calculated. The permanent
  failure applies the cut-off value calculated with $alpha = 2^(-60)$, i.e.
  $60 dot #raw("ESDM_ES_OSR")$ identical back-to-back time stamps.

  When the RCT passes, the counter is set to zero for the next time delta to
  arrive. In mathematical terms, the verification of back-to-back values being
  not identical is the calculation of the first discrete derivative of the
  time stamp to show that it is not zero. In addition, the ESDM enhances the
  RCT by calculating also the second and third discrete derivative of the time
  stamp to be concatenated with the per-CPU ring. With that, up to
  4 consecutive time stamp values are assessed. All derivatives must always be
  non-zero in order to pass the RCT. If one discrete derivative shows a zero,
  the RCT counter is increased. Thus, the addition of the second and third
  derivative makes the RCT even more conservative. Hence, the first discrete
  derivative is considered to be identical to the “approved” RCT specified in
  SP800-90B section 4.4. In addition, linear and exponential patterns are
  identified with the second and third discrete derivative, respectively. As
  the additional pattern recognition do not invalidate the mandatory pattern
  recognition, this RCT approach therefore is considered to be an enhanced
  version of the “approved” RCT and thus meets the requirement (a) of
  SP800-90B section 4.5.

/ APT: The ESDM implements the Adaptive Proportion Test as defined in
  SP800-90B section 4.4.2. As explained in other parts of the document, one
  time stamp value is assumed to have (at least) $1 \/ #raw("ESDM_ES_OSR")$
  bit of entropy. Thus, the cut-off value for the APT is 459 with the default
  oversampling rate (325 for one bit of entropy per time stamp) compliant to
  SP800-90B section 4.4.2 for non-binary data with a significance level of
  $alpha = 2^(-30)$. The permanent failure applies the cut-off value of 479
  for $alpha = 2^(-60)$. The APT is
  calculated using the four least significant bits of the time stamp. During
  initialization of the APT, a time stamp is set as a base. All subsequent
  time stamps are compared to the base time stamp. If both values are
  identical, the APT counter is increased by one. The window size for the APT
  is 512 time stamps. The implementation therefore provides an “approved”
  APT.

== NIST Clarification Requests <sec:nist>

In addition to complying with the requirements of FIPS 140-2 and SP800-90B,
NIST requests the clarification of the following questions.

=== Sensitivity of Interrupt Timing Measurements <sec:nist-sensitivity>

The question that needs to be answered is whether the logic that measures the
interrupt timing is sensitive enough to pick up the variances of the interrupt
timing.

The sensitivity implies that timing variations are picked up and measured.
This is enforced by the stuck test enforced on each interrupt time stamp. That
stuck test requires that the first, second and third discrete derivative of
the time stamp must always be non-zero to accept that time stamp. Therefore,
the time stamp must vary for the received and processed interrupts which
implies that the ESDM health test ensures that the sensitivity of the time
stamp mechanism is sufficient.

=== Dependency Between Interrupt Timing Measurements <sec:nist-dependency>

Another question that is raised by NIST asks for a rationale why there are no
dependencies between individual Jitter measurements.

The interrupts are always created by either explicit or implicit human
actions. The ESDM measures the time stamp of the occurrence of these
interrupts. Thus, the ESDM measures the effects of operations triggered by
human interventions. With the presence of a high-resolution time stamp that
operates in the nanosecond range and the assumption that only one bit of
entropy – a third of a bit with the default oversampling rate – is present in
one nanosecond time stamp of one interrupt event, the
dependency discussion therefore focuses on the one (or maybe up to four) least
significant bit of the nanosecond time stamp. With such high-resolution time
stamps and considering that only the least significant bit(s) is/are relevant
for the ESDM, dependencies are considered to be not present for these bits.

== SP800-90B Compliant Configuration <sec:90b-config>

In order to use the ESDM SP800-90B compliant, the following configurations
and settings must be made. These settings are cover requirements for the
compile-time options found in the ESDM meson configuration framework.

The following compile-time settings must be observed:

- `fips140` must be enabled.

- `es_irq` must be enabled to enable the interrupt entropy source to which the
  entropy discussion of this chapter applies to.

- Set the oversampling rate `ESDM_ES_OSR` in the Makefile of the kernel
  module such that the resulting rate of $1 \/ #raw("ESDM_ES_OSR")$ bits of
  entropy per time stamp does not exceed the rate resulting from the entropy
  assessment outlined in section @sec:90b-reuse. The configuration option
  `es_irq_entropy_rate` must be greater than zero: it caps the entropy rate
  of the kernel module, which its default of 256 leaves unchanged.

- The ESDM Linux kernel module must be enabled and compiled as documented in
  kernel/esdm\_es/README.md, which also lists the kernel patches to apply.
  The Makefile in this directory must have the interrupt entropy source
  enabled (`BUILD_ES_IRQ=1`, the default).

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The kernel must be booted with the kernel command line option of `fips=1` to
  enable the SP800-90B health test.

#par(first-line-indent: 0pt)[To verify that the SP800-90B compliance is
achieved, the file /proc/sys/kernel/random/esdm\_type or the
`esdm_rpcc_status` RPC API call provides an appropriate status indicator: the
state of the interrupt entropy source reports SP800-90B compliance once the
startup health test of the kernel module completed.]

To achieve a compliant configuration to SP800-90A and SP800-90B, the following
requirements must be met:

- All requirements for SP800-90B documented in section @sec:90b-config must be
  met.

- The ESDM compile time option `drng_hash_drbg` must be enabled which provides
  the SP800-90A DRBG of the builtin crypto backend, or another crypto backend
  must be selected with an SP800-90A DRBG.

#par(first-line-indent: 0pt)[Only data obtained from the potentially blocking
output interfaces of the ESDM are SP800-90B compliant. If SP800-90C compliance
is requested, these interfaces are also providing SP800-90C compliant output.
Finally, the following interfaces are DRG.3 compliant:]

- /dev/random,

- `getrandom` system call invoked with a zero flag value,

- invoking the `esdm_rpcc_get_random_bytes_full` RPC API call,

- invoking the `esdm_rpcc_get_random_bytes_pr` RPC API call that provides
  access to the DRBG operated with prediction resistance,

- the read commands of the EGD sockets of the ESDM except those with the
  semantics of /dev/urandom.

#par(first-line-indent: 0pt)[Any other interface is not considered to provide
SP800-90B compliant data.]

== Reuse of SP800-90B Analysis <sec:90b-reuse>

To reuse the SP800-90B analysis provided in this document the following steps
must be performed on the target platform:

+ Obtain raw noise data through the raw noise source interface on the intended
  target platform as explained in section @sec:90b-313. The obtained raw noise
  data must be processed by the SP800-90B tool to obtain an entropy rate which
  must be above the entropy rate per time delta that is configured with the
  oversampling rate `ESDM_ES_OSR` of the kernel module: the entropy rate must
  be above $1 \/ #raw("ESDM_ES_OSR")$. For example, the tools of
  tests/validation-helpers obtain and assess 1,000,000 time deltas as
  follows:

  ```
  esdm-getrawentropy -f /sys/kernel/debug/esdm_es/esdm_raw_hires \
                     -s 1000000 -o data.out
  esdm-extractlsb data.out data.bin 1000000 FF
  ea_non_iid data.bin 8
  ```

+ Obtain the restart noise data through the raw noise source interface on the
  intended target platform as explained in section @sec:90b-313. The obtained
  raw noise data must be processed by the SP800-90B tool to verify:

  + the sanity test to apply to the noise restart data must pass, and

  + the minimum of the row-wise and column-wise entropy rate must not be less
    than half of the entropy rate from measurement (1) and the entropy
    assessment of the noise source based on the restart data must be at least
    entropy rate per time stamp mentioned in (1).

#par(first-line-indent: 0pt)[If these steps are successfully mastered the user
would now satisfy all SP800-90B criteria and thus does not need to prepare his
own SP800-90B analysis since the document we discuss here covers all other
aspects of the SP800-90B analysis.]

The tool set provided as part of ESDM library code distribution provides the
measurements and validation tools in tests/validation-helpers, which are
built with the meson option `validation-helpers`.
