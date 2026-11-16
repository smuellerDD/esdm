#import "../template.typ": *

= ESDM Specific Configurations <sec:configurations>

The ESDM offers a secure and appropriate set of features with the default
configuration. Yet, use cases may arise where the ESDM should exhibit a
different behavior. The flexibility of the ESDM allows a various
configurations that are intended to meet different requirements.

== SP800-90C Compliance <sec:sp80090c>

The specification of SP800-90C defines construction methods to design
non-deterministic as well as deterministic RNGs. As the specification is
currently in draft form, the latest available draft from January 21, 2021 is
applied.

The specification defines different types of RNGs where the following mapping
to the ESDM applies:

- The ESDM follows the construction of RBG2(NP) with the following entropy
  sources whose outputs are concatenated:

  - Auxiliary external entropy sources, such as user-space rngd, if available.
    The administrator is responsible to guarantee that this entropy source is
    compliant to SP800-90B if it alters the entropy estimator maintained by
    the ESDM via the `RNDADDENTROPY` IOCTL or the `esdm_rpcc_rnd_add_entropy`
    RPC API call. Depending on the selected entropy
    source, this may be a physical or non-physical entropy source. Note, all
    data maintained by the auxiliary pool are processed with a conditioning
    component, the XDRBG-256 based on SHAKE256. Thus, to achieve full
    SP800-90C compliance for such entropy sources, only one should feed data
    credited with entropy into the auxiliary pool.

  - Interrupt entropy source of the kernel module `esdm_es` is fully
    maintained as part of the ESDM and is the only entropy source subject
    to a full entropy analysis following section @sec:sp80090b. Furthermore,
    it is claimed to be fully SP800-90B compliant.

  - Scheduler entropy source of the kernel module `esdm_es` is fully
    maintained as part of the ESDM. An entropy analysis is not provided yet
    as outlined in chapter @sec:sched-assessment. Thus, it is credited with no
    entropy by default.

  - The eBPF-based interrupt and scheduler entropy sources are fully
    maintained as part of the ESDM. Their entropy rate must be determined for
    the deployment environment as outlined in chapter @sec:sched-assessment.
    Until then, they are credited with no entropy, the default of the meson
    configuration options `es_irq_ebpf_entropy_rate` and
    `es_sched_ebpf_entropy_rate`. Note, at most one of the interrupt and
    scheduler-based entropy sources may be credited with entropy.

  - The Jitter RNG entropy source is used by the ESDM. This entropy source is
    a fully self-contained SP800-90B entropy source. Its SP800-90B compliance
    must be assessed separately. If SP800-90B compliance cannot be
    demonstrated, it must be awarded to credit zero bits of entropy with the
    configuration documented in section @sec:jent-entropy or by completely
    disabling it by not selecting the meson configuration option of `es_jent`.

  - The kernel Jitter RNG entropy source is used by the ESDM if the meson
    configuration option `es_jent_kernel` is selected. It obtains data from
    the Jitter RNG of the kernel crypto API. Its SP800-90B compliance must be
    assessed separately. If SP800-90B compliance cannot be demonstrated, it
    must be awarded to credit zero bits of entropy with the meson
    configuration option `es_jent_kernel_entropy_rate=0` or by completely
    disabling it.

  - The CPU entropy source is used by the ESDM, if available. On Intel, this
    uses RDSEED. This entropy source is a fully self-contained SP800-90B
    entropy source. Its SP800-90B compliance must be assessed separately. If
    SP800-90B compliance cannot be demonstrated, it must be awarded to credit
    zero bits of entropy with the configuration documented in section
    @sec:cpu-entropy or by completely disabling it by not selecting the meson
    configuration option of `es_cpu`.

  - The Linux kernel RNG entropy source is used by the ESDM. As the kernel RNG
    is not SP800-90B compliant, the ESDM credits it with zero bits of entropy
    when operating compliant to SP800-90C.

  - The Linux HWRAND entropy source is used by the ESDM, if available. Its
    SP800-90B compliance must be assessed separately. If SP800-90B compliance
    cannot be demonstrated, it must be awarded to credit zero bits of entropy
    with the meson configuration option `es_hwrand_entropy_rate=0`, the
    default, or by completely disabling it by not selecting the meson
    configuration option of `es_hwrand`.

  - The TPM 2.0 entropy source is used by the ESDM, if available. Its
    SP800-90B compliance must be assessed separately. If SP800-90B compliance
    cannot be demonstrated, it must be awarded to credit zero bits of entropy
    with the meson configuration option `es_tpm2_entropy_rate=0`, the default,
    or by completely disabling it by not selecting the meson configuration
    option of `es_tpm2`.

  - The external entropy source (section @sec:ext-es) is used by the ESDM if a
    provider socket is configured with the meson configuration option
    `es_ext_path` or the `esdm-server` option `--es_ext`. The provider is a
    separate process, such as `esdm-es-pkcs11` serving the random number
    generator of a PKCS\#11 token or `esdm-es-pcsc` serving a smart card.
    Its SP800-90B compliance must be assessed separately. If SP800-90B
    compliance cannot be demonstrated, it must be awarded to credit zero bits
    of entropy with the meson configuration option `es_ext_entropy_rate=0` or
    the `esdm-server` option `--es_ext_entropy_rate 0`.

  By applying Method 2 of section 3.3 in SP800-90C, the entropy provided by
  all entropy sources can be added which is applied when the ESDM constructs
  the temporary seed buffer as shown with equation @eq:t. The data of the
  entropy sources credited with zero bits of entropy is not part of the seed
  but is inserted into the DRBG as additional input, as SP800-90C section
  2.6 allows for entropy sources that are not validated.

- During instantiation of the DRBG, the ESDM tries to seed the DRBG with at
  least (DRBG security strength) + 128 bits = 384 bits of entropy. Only when
  this amount of entropy was obtained to seed the DRBG is considered to be
  fully seeded and is allowed to produce output.

  If the SP800-90C construction is to be used as the “randomness source”
  following bullet 5 of section “Note to Reviewer” in the SP800-90C document
  to seed another DRBG with a security strength of 256 bits, either the hash
  DRBG should be used as they are capable of transporting up to 512 bits of
  entropy and are initially seeded with 384 bits of entropy. Thus, the
  SP800-90C seeding requirement of providing 384 bits of entropy can be
  satisfied.

  The DRNG instance operated with prediction resistance is reseeded with
  fresh entropy right before every chunk of output it generates, requesting
  (DRBG security strength) + 64 bits = 320 bits of entropy. The chunk holds
  at most the injected entropy less these 64 bits of oversampling and at most
  the security strength of 256 bits. It is intended to meet the RBG3(RS)
  construction of SP800-90C section 6.5.1.2.

- Reseeding of the DRBG can be triggered by either writing data into
  /dev/random while not all DRNGs are fully seeded or by the `RNDRESEEDCRNG`
  IOCTL. The ESDM guarantees that the
  reseed operation is only performed if at least 256 bits of entropy is
  available if operated compliant to SP800-90C. If this is not available, the
  reseed is attempted during the next generate operation. Yet, the generate
  operation is conducted in any case until the request size based limits
  outlined below are reached. Nonwithstanding, the ESDM always
  attempts to obtain 256 bits of entropy for reseeding. This is considered
  appropriate because the upper limit when a reseed is ultimately triggered is
  $2^20$ generate operations or after 10 minutes, whatever is reached earlier.
  If the DRNG cannot be reseeded it will continue to operate until the next
  time this threshold is reached. The DRNG will revert to an unseeded stage if
  it cannot be reseeded by the time it serviced $2^30$ generate requests since
  the last successful seeding operation. In addition, an SP800-90C compliant
  build applies request size based limits: a DRNG starts no request after it
  generated $2^17$ bits without a successful reseed – a request started
  before is completed – and attempts a reseed after 98,304 bits, three
  quarters of that limit, unless smaller values are configured with the meson
  configuration options `drng_reseed_threshold_bits` and
  `drng_max_reseed_bits`. Furthermore, an asynchronous reseed worker reseeds
  every DRNG once its reseed interval elapsed, regardless of whether data is
  requested from it.

#par(first-line-indent: 0pt)[The requirements from section 6.3 SP800-90C are
met as follows:]

+ The administrator must use an SP800-90A DRBG, such as the Hash DRBG of the
  default configuration, to satisfy the requirement.

+ The DRBG can be ACVTS-tested to show compliance to SP800-90A. The entropy
  sources are to be assessed pursuant to SP800-90B as outlined in the above
  listing.

+ See the above listing for the reseeding support.

+ If an entropy source is not validated, its entropy estimation must be set to
  zero as outlined in the above listing.

+ N/A as the ESDM is claimed to conform with RBG2(NP).

+ The entropy sources are listed above. By using concatenation of the output
  of all entropy sources, the Method 2 SP800-90C is implemented. The entropy
  of all entropy sources are added.

+ Technically it is possible that all DRBG security strengths can be chosen as
  the DRBG supports all security strengths. Yet, the ESDM interfaces currently
  only support the highest security strength of 256 bits to ensure that it can
  be used for all use cases.

+ The entropy source output is destroyed immediately after it was used to
  (re)seed the DRBG.

+ N/A as the ESDM does not use a CTR DRBG without derivation function: with
  the GnuTLS crypto backend, whose CTR DRBG has none, the ESDM applies the
  block cipher derivation function of SP800-90A and provides the CTR DRBG
  with seed material of exactly its seed length.

+ The ESDM attempts to instantiate a DRBG with 3/2s bits of entropy. Only if
  this succeeds, the DRBG becomes available. The ESDM attempts to reseed a
  DRBG with s bits of entropy. See the rationale above for the discussion
  about the minimum entropy size of the reseeding operation of 256 bits.

+ The DRBG only provides output once it is fully seeded as mandated by
  SP800-90C.

+ An error occurring in the interrupt entropy source triggers a reset of the
  interrupt entropy source as outlined in section @sec:health-tests. If the
  other entropy sources are subject to a health test failures, SP800-90B
  mandates that they do not produce entropy. Before the first initialization
  of the DRBG, it is subject to a power-on self test. The ESDM performs
  power-up self tests as outlined in section @sec:self-tests, which it
  repeats every 10 minutes. The ESDM only provides random numbers while the
  self tests of the cryptographic primitives passed.

+ This requirement is implicitly met by the fact that the ESDM only provides
  DRBGs with the maximum security strength of 256 bits.

=== RBG2(P) Construction Method <sec:rbg2p>

It is possible to convert the ESDM into the SP800-90C type of RBG2(P). This
approach requires that only physical entropy sources are credited with
entropy. The following specific settings must be applied in addition to the
general configurations listed in the next section:

- Configure the interrupt entropy source to not credited entropy: compile the
  ESDM with the meson configuration option of `es_irq_entropy_rate=0`. This
  setting ensures that the interrupt entropy source still collects data, but
  it is not credited with entropy. If it shall be completely disabled, the
  compile time option of `es_irq` must be unset.

- Configure the scheduler entropy source to not credited entropy: compile the
  ESDM with the meson configuration option of `es_sched_entropy_rate=0`. This
  setting ensures that the scheduler entropy source still collects data, but
  it is not credited with entropy. If it shall be completely disabled, the
  compile time option of `es_sched` must be unset.

- Configure the eBPF-based interrupt and scheduler entropy sources to not
  credit entropy: compile the ESDM with the meson configuration options of
  `es_irq_ebpf_entropy_rate=0` and `es_sched_ebpf_entropy_rate=0`, the
  defaults. If they shall be completely disabled, the compile time options of
  `es_irq_ebpf` and `es_sched_ebpf` must be unset, the defaults.

- Configure the Jitter RNG entropy source to not credit entropy: compile the
  ESDM with the meson configuration option of `es_jent_entropy_rate=0`. If the
  value is set to 0, the entropy source still collects data, but it is not
  credited with entropy. If it shall be completely disabled, the compile time
  option of `es_jent` must be unset.

- Configure the kernel RNG entropy source to not credit entropy: compile the
  ESDM with the meson configuration option of `es_kernel_entropy_rate=0`. If
  the value is set to 0, the entropy source still collects data, but it is not
  credited with entropy. If it shall be completely disabled, the compile time
  option of `es_kernel` must be unset.

- Configure the kernel Jitter RNG entropy source to not credit entropy:
  compile the ESDM with the meson configuration option of
  `es_jent_kernel_entropy_rate=0`. If it shall be completely disabled, the
  compile time option of `es_jent_kernel` must be unset, the default.

- Adjust the entropy rate of the CPU entropy source as needed: compile the
  ESDM with the meson configuration option of `es_cpu_entropy_rate=256` when
  full entropy is assumed to be provided by the CPU entropy source. In
  general, set any value between 0 and 256 if the default value is not
  appropriate. If the value is set to 0, still collects data, but it is not
  credited with entropy. If it shall be completely disabled, the compile time
  option of `es_cpu` must be unset.

- Adjust the entropy rate of the HWRAND entropy source as needed: compile the
  ESDM with the meson configuration option of `es_hwrand_entropy_rate=256`
  when full entropy is assumed to be provided by the configured HWRAND entropy
  source. Ensure that the intended HWRAND entropy source is set in
  /sys/devices/virtual/misc/hw\_random/rng\_current. In general, set any value
  between 0 and 256 if the default value is not appropriate. If the value is
  set to 0, still collects data, but it is not credited with entropy. If it
  shall be completely disabled, the compile time option of `es_hwrand` must be
  unset.

- Adjust the entropy rate of the TPM 2.0 entropy source as needed: compile
  the ESDM with the meson configuration option `es_tpm2_entropy_rate=256`
  when full entropy is assumed to be provided by the TPM 2.0. In general, set
  any value between 0 and 256 if the default value of 0 is not appropriate.
  If it shall be completely disabled, the compile time option of `es_tpm2`
  must be unset.

- Adjust the entropy rate of the external entropy source as needed: the ESDM
  credits it with the entropy its provider claims, at most at the rate
  configured with the meson configuration option `es_ext_entropy_rate` or the
  `esdm-server` option `--es_ext_entropy_rate`, or else at the rate its
  provider declares. Only a provider serving a physical entropy
  source may be credited with entropy.

- If other hardware entropy sources are considered deliver entropy, they may
  inject data into the ESDM via the IOCTL `RNDADDENTROPY`, the RPC API call
  `esdm_rpcc_rnd_add_entropy`, or as an external entropy source. Note, only
  physical entropy sources must provide data that is credited with entropy.
  Any other data fed into the ESDM via those interfaces must not be credited
  with entropy.

#par(first-line-indent: 0pt)[Important note: The entropy rate provided by the
CPU entropy source plus all other physical entropy sources together must
ensure they provide sufficient entropy. “Sufficient entropy” is provided when
the entropy rate equals the hash type used by the ESDM. Considering the
default message digest of SHA2-512, 512 bits of entropy should be provided.]

Naturally, the hardware entropy sources that are credited with entropy must
be compliant to SP800-90B.

In case the RBG2(P) construction method is achieved, the following additional
requirement from section 6.3 SP800-90C is met:

- Requirement 5: With the required configuration mentioned before the ESDM
  will only count the physical entropy sources towards fulfilling the
  requested amount of entropy.

=== SP800-90C Compliant Configuration <sec:90c-config>

SP800-90C compliance is only achieved when all of the following settings are
achieved.

The following compile-time settings must be observed:

- The meson configuration option `sp80090c` is set. This option guarantees the
  following:

  - The final conditioning operation applied to the auxiliary pool as well as
    to the eBPF-based entropy sources require 64 additional bits of entropy
    when obtaining data for the temporary seed buffer, as does the kernel
    module `esdm_es` for the interrupt and scheduler entropy sources in a
    kernel booted with `fips=1`. This complies with the
    requirement specified in section 4.3.2 SP800-90C about vetted conditioning
    components. This ensures the conditioning components provide full
    entropy.

  - When the DRNG is initially seeded, it is attempted to be seeded with 384
    bits of entropy at least. This complies with the requirement specified in
    section 6.2.1 bullet 2 of SP800-90C requiring 3/2s bits of entropy for the
    initial seeding. Note, the ESDM does not apply a stepwise seeding during
    initialization: the ESDM will guarantee that at least 384 bits of entropy
    are collectively pulled from all entropy sources before the DRNG is
    considered to be fully seeded. Only if this is achieved, the SP800-90C
    compliant-marked interfaces of the ESDM specified in section
    @sec:health-tests will produce random numbers.

  - The request size based reseeding limits outlined in section
    @sec:sp80090c are applied.

- The meson configuration option `ais2031_drg3` must not be set. It applies
  the oversampling of the entropy sources without the request size based
  reseeding limits and without claiming SP800-90C compliance.

- Enable `es_irq` to use the interrupt entropy source compliant to SP800-90B as
  outlined in section @sec:90b-config if the interrupt entropy source is
  considered to be compliant to SP800-90B by accepting the assessment in
  chapter @sec:irq-assessment and by applying the testing of the entropy
  source as outlined in section @sec:90b-reuse on the target system. This also
  requires the compilation of the ESDM Linux kernel module documented in
  kernel/esdm\_es/README.md.

- Enable `es_sched` configure the scheduler entropy source compliant to
  SP800-90B as outlined in section @sec:sched-assessment if the scheduler
  entropy source is considered to be compliant to SP800-90B by an assessment
  of the entropy source on the target system as outlined in chapter
  @sec:sched-assessment. This also requires the compilation of the ESDM Linux
  kernel module documented in kernel/esdm\_es/README.md.

- The ESDM must be compiled with the meson configuration options of
  `es_irq_ebpf_entropy_rate=0` and `es_sched_ebpf_entropy_rate=0`, the
  defaults, unless the respective eBPF-based entropy source is considered to
  be compliant to SP800-90B by an assessment of the entropy source on the
  target system as outlined in chapter @sec:sched-assessment.

- The ESDM must be compiled with the meson configuration option of
  `es_cpu_entropy_rate=0` or unset the option `es_cpu` unless the CPU-based
  entropy source (e.g. RDSEED on Intel) has an SP800-90B compliant entropy
  assessment and comply with all requirements from SP800-90B.

- The ESDM must be compiled with the meson configuration option of
  `es_hwrand_entropy_rate=0`, the default, or unset the option `es_hwrand`
  unless the HWRAND entropy source has an SP800-90B compliant entropy
  assessment and comply with all requirements from SP800-90B.

- The ESDM must be compiled with the meson configuration option of
  `es_tpm2_entropy_rate=0`, the default, or unset the option `es_tpm2` unless
  the TPM 2.0 entropy source has an SP800-90B compliant entropy assessment
  and comply with all requirements from SP800-90B.

- The ESDM must be compiled with the meson configuration option of
  `es_jent_kernel_entropy_rate=0` or unset the option `es_jent_kernel`, the
  default, unless the kernel Jitter RNG has an SP800-90B compliant entropy
  assessment and comply with all requirements from SP800-90B.

- The ESDM must be compiled with the meson configuration option of
  `es_ext_entropy_rate=0` unless the external entropy source has an
  SP800-90B compliant entropy assessment and comply with all requirements
  from SP800-90B.

- The ESDM must be compiled with the meson configuration option of
  `es_jent_entropy_rate=0` or unset the option `es_jent` unless the Jitter RNG
  entropy source has an SP800-90B compliant entropy assessment and comply with
  all requirements from SP800-90B#footnote[At the time of writing, the user
  space Jitter RNG is SP800-90B compliant. Patches ensuring the in-kernel
  variant is SP800-90B compliant as well when into the kernel for version
  5.8.].

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- Filling up the ESDM with entropy using either a user-space RNGD via the
  IOCTL `RNDADDENTROPY` or the RPC API call `esdm_rpcc_rnd_add_entropy` is
  allowed. However, the caller is only allowed to
  claim entropy associated with the data and thus increase the ESDM entropy
  estimation if the entropy source is SP800-90B compliant with its own entropy
  assessment.

#par(first-line-indent: 0pt)[To verify that the SP800-90C compliance is
achieved, the file /proc/sys/kernel/random/esdm\_type provides an appropriate
status indicator. The SP800-90C compliant is ensured only for the respectively
marked ESDM interfaces specified in section @sec:health-tests. All other
interfaces are not providing SP800-90C compliant random numbers.]

It is permissible to use the ESDM DRBG output to seed another DRBG when using
the prediction resistance `esdm_rpcc_get_random_bytes_pr` RPC API call, using
`getrandom(2)` with the `GRND_RANDOM` flag, opening /dev/random with the
`O_SYNC` flag, or reading from the EGD socket serving the prediction
resistance DRNG. See the details given for the API call
`esdm_get_random_bytes_pr` in section @sec:components.

=== FIPS 140 Compliant Configuration <sec:fips140-config>

FIPS 140 compliance is only achieved when all of the following settings are
achieved.

The following compile-time settings must be observed:

- The meson configuration option `fips140` is set. This option guarantees the
  following:

  - The option `sp80090c` is automatically enabled together with its
    request size based reseeding limits.

  - Power-on self tests are performed

  - The integrity of the `esdm-server` executable and of the ESDM library is
    verified with HMAC reference values. These are to be written at
    installation time with `esdm-tool`, a missing reference value is a failed
    integrity test.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The ESDM along with the scheduler and/or interrupt ES must be operated in
  FIPS mode to ensure the oversampling for the conditioning and the initial
  seeding of the DRBG is applied. This is achieved with the kernel command
  line option of `fips=1` – for the ESDM server alone also if the environment
  variable `ESDM_SERVER_FORCE_FIPS` is set when starting the ESDM server.

== AIS 20 / 31 <sec:ais2031>

The German BSI defines construction methods of RNGs with AIS 20/31 with the
revision from 2011. In particular, this document defines different classes of
RNGs where the ESDM is capable of meeting class NTG.1. The NTG.1 compliance is
achieved when using /dev/random with the `O_SYNC` flag during opening, by
using `getrandom(2)` with the `GRND_RANDOM` flag, by reading from the EGD
socket serving the prediction resistance DRNG, or by using the
`esdm_rpcc_get_random_bytes_pr` RPC API call.

With the revision 3.0 of AIS 20/31 from 2024, the ESDM provides
configurations for the NTG.1 seeding strategy as well as for the classes
DRG.3 and DRG.4 as outlined in the following sections.

The NTG.1 from AIS 20/31 of 2011 requirements are met as follows:

- NTG.1.1: The ESDM offers interfaces to collect raw unconditioned entropy as
  outlined in section @sec:test-interfaces.

- NTG.1.2: The ESDM maintains an entropy estimator for the auxiliary pool as
  well as each entropy source. The credit operation of the ESDM is documented in
  section @sec:components. To outline the debit operation section
  @sec:90b-3151 provides several examples showing the approach. For each of
  the fast entropy sources, the ESDM obtains the entropy estimate when
  fetching data from them and applies this estimate when seeding the DRNG.

- NTG.1.3: The ESDM provides a compile-time switchable DRNG support using an
  SP800-90A Hash DRBG with a SHA-512 core. Furthermore, the ESDM allows using
  a ChaCha20-based DRNG which is documented in section @sec:chacha20. The
  other crypto backends provide SP800-90A DRBGs (OpenSSL, Botan, GnuTLS), the
  XDRBG with SHAKE256 (leancrypto) and the ChaCha20 DRNG of Botan. All those
  DRNGs – the ChaCha20 DRNG of Botan only from Botan 3.14.0 on, which
  operates it with fast key erasure – are characterized as DRG.3 since they
  all support backward secrecy and use contemporary cryptographic primitives
  for the state transition as well as output generation.

- NTG.1.4: Due to the blocking behavior and only returning as many bits of
  data as entropy is available via /dev/random opened with `O_SYNC`, or
  `getrandom(2)` with the flag `GRND_RANDOM` the ESDM meets the requirement.

- NTG.1.5: The output functions of the offered DRNGs are all based on
  contemporary cryptographic primitives. Therefore, the output is assumed that
  it cannot be distinguished from random number output sequences of an ideal
  RNG. This is supported by the fact that the SP800-90A DRBGs are successfully
  passing the NIST CAVP test suite. The ChaCha20 DRNG can be tested using the
  #link("https://www.chronox.de/chacha20_drng.html")[ChaCha20 DRNG stand-alone
  implementation] which is derived from the ESDM implementation. The tester
  can verify that both operate identical because the power-on self test in the
  stand-alone ChaCha20 DRNG implementation is identical to the ESDM power-up
  self test found in esdm/esdm\_builtin\_chacha20.c.

- NTG.1.6: Using the entropy analysis tools such as the NIST SP800-90B test
  tools, results shown in appendix @sec:measurements can be obtained for the
  interrupt entropy source. For the second entropy source, such assessment
  must be performed as well. For example, the
  #link("https://www.chronox.de/jent")[Jitter RNG] is provided with a
  complete independent entropy assessment. When comparing the results with the
  heuristic entropy estimate, it is clear that the ESDM collects more entropy
  than it credits. Further, considering the mathematical operations processing
  the raw entropy data outlined in section @sec:90b-315, the processing is
  considered to not destroy entropy.

=== NTG.1 (AIS 20/31 2011) Compliant Configuration <sec:ntg1-2011>

To achieve NTG.1 compliant operation, the following configuration must be
applied. It is permissible to use the configuration in parallel with the
SP800-90B and SP800-90C configurations.

The following compile-time settings must be observed:

- None.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The caller must use /dev/random and open it with `O_SYNC`, the
  `getrandom(2)` API call with the flag `GRND_RANDOM`, the EGD socket serving
  the prediction resistance DRNG, or the `esdm_rpcc_get_random_bytes_pr` RPC
  API call is used.

#par(first-line-indent: 0pt)[To verify that the NTG.1 compliance is achieved,
the file /proc/sys/kernel/random/esdm\_type provides an appropriate status
indicator. The NTG.1 compliant is ensured only for the respectively marked
ESDM interfaces specified in section @sec:90b-config. All other interfaces are
not providing NTG.1 compliant random numbers.]

=== NTG.1 (AIS 20/31 3.0 2024) Compliant Configuration <sec:ntg1-2022>

To achieve NTG.1 compliant operation, the following configuration must be
applied. It is permissible to use the configuration in parallel with the
SP800-90B and SP800-90C configurations. With `es_jent_ntg1`, however, the
Jitter RNG alone brings a DRNG to the fully seeded level once it delivered
240 bits of entropy, without the 384 bits the SP800-90C configuration
requires for the initial seed being checked (`esdm_fully_seeded`). In
parallel with the SP800-90C configuration, the entropy rate of the Jitter
RNG must therefore let it deliver the full seed - its default rate does.

The following compile-time settings must be observed for AIS 20/31 version
3.0 (2024):

- The ESDM compile time option of `ais2031_ntg1` must be enabled.

- The ESDM must have access to two entropy sources which are capable of
  delivering 240 bits of entropy each for the initial seeding of a DRNG –
  after it, one entropy source is sufficient. For example, the interrupt
  entropy source can deliver 256 bits of entropy. In addition, the Jitter RNG
  entropy source is capable of delivering 240 bits of entropy when compiling
  the ESDM with the meson configuration option of `es_jent_entropy_rate=240`
  or a larger value, such as its default of 256. See section
  @sec:jent-entropy for details on the Jitter RNG entropy rate.

- Alternatively, the Jitter RNG is operated in its own NTG.1 mode with the
  meson configuration option `es_jent_ntg1`, which requires the Jitter RNG
  library version 3.7.0 or later with support for secure memory. Such a
  Jitter RNG is NTG.1 conformant on
  its own: the ESDM seeds a DRNG from it alone once it delivered 240 bits of
  entropy, without a second entropy source.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- None.

#par(first-line-indent: 0pt)[To verify that the NTG.1 compliance is achieved,
the file /proc/sys/kernel/random/esdm\_type provides an appropriate status
indicator. The NTG.1 compliant is ensured only for the respectively marked
ESDM interfaces specified in section @sec:90b-config. All other interfaces are
not providing NTG.1 compliant random numbers.]

=== DRG.3 / DRG.4 (AIS 20/31 3.0 2024) Compliant Configuration <sec:drg3-drg4>

AIS 20/31 version 3.0 from 2024 defines the classes DRG.3 and DRG.4 for the
deterministic part of the ESDM. The ESDM provides the following mutually
exclusive compile time options for them, which can be combined with the
NTG.1 configuration of section @sec:ntg1-2022:

- `ais2031_drg3`: The ESDM applies the oversampling of the entropy sources of
  the `sp80090c` option – 128 additional bits of entropy for the initial seed
  of a DRNG and 64 additional bits of entropy from the conditioning
  components – without the request size based reseeding limits, which belong
  to DRG.4. Such a build does not claim SP800-90C compliance.

- `ais2031_drg4`: The request size based reseeding limits are capped to the
  values required by DRG.4.10: a DRNG instance starts no request after it
  generated $2^17$ bits without a successful reseed – a request started
  before is completed in generate operations of $2^19$ bits at most – and
  attempts a reseed after three quarters of that limit. Smaller values
  configured with the meson configuration options
  `drng_reseed_threshold_bits` and `drng_max_reseed_bits` are kept. A DRG.4
  build satisfies DRG.3 as well.

#par(first-line-indent: 0pt)[The DRNG must provide backward secrecy as
outlined for NTG.1.3 in section @sec:ais2031. To verify that the DRG.3 or
DRG.4 compliance is achieved, the status of the ESDM lists DRG.3, and for
DRG.4 also DRG.4, among the standards it complies with.]

=== DRG.4 / PTG.3 Compliant Configuration <sec:drg4-ptg3>

The ESDM allows a configuration that would make the ESDM compliant to the
requirements of a DRG.4 as well as a PTG.3. This is achieved by deconfiguring
all entropy sources except one that provides the data from a PTG.2 entropy
source. For example, an rngd can be created having access to a smart card that
is provides a PTG.2 entropy source, or the external entropy source providers
`esdm-es-pkcs11` or `esdm-es-pcsc` serve such a smart card. In this case, all
other entropy sources must be deactivated using the following compile-time
configuration.

The PTG.3 naturally can only be claimed if the PTG.2 entropy source is part of
the validation. If the PTG.2 entropy source is not part of the validation, a
DRG.4 must be claimed instead.

For achieving such compliance claim, the following compile-time configuration
must be applied:

- The ESDM compile time option of `ais2031_drg4` must be enabled to apply the
  reseeding limits of DRG.4 as outlined in section @sec:drg3-drg4.

- The ESDM must be compiled with the following setting to ensure the
  interrupt entropy source is not credited with entropy:
  `es_irq_entropy_rate=0`. The same applies to the scheduler-based and the
  eBPF-based entropy sources with `es_sched_entropy_rate=0`,
  `es_irq_ebpf_entropy_rate=0` and `es_sched_ebpf_entropy_rate=0`.

- Configure the Jitter RNG entropy source to not credit entropy: compile the
  ESDM with the compile-time option of `es_jent_entropy_rate=0`. If the value
  is set to 0, the entropy source is not credited with entropy. The same
  applies to the kernel Jitter RNG entropy source with
  `es_jent_kernel_entropy_rate=0`.

- Adjust the entropy rate of the CPU entropy source to zero: compile the ESDM
  with the compile-time option of `es_cpu_entropy_rate=0`. If the value is
  set to 0, the entropy source is not credited with entropy.

- Adjust the entropy rate of the kernel RNG entropy source to zero: compile
  the ESDM with the compile-time option of `es_kernel_entropy_rate=0`.

- Adjust the entropy rate of the HWRAND and TPM 2.0 entropy sources to zero:
  compile the ESDM with the compile-time options of
  `es_hwrand_entropy_rate=0` and `es_tpm2_entropy_rate=0`, the defaults. If
  the value is set to 0, the entropy source is not credited with entropy.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The PTG.2 entropy source delivers its entropy to the ESDM via either the
  `esdm_rpcc_rnd_add_entropy` RPC API call, via the /dev/random IOCTL
  `RNDADDENTROPY`, or as the external entropy source.
