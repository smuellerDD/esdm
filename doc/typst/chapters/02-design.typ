#import "../template.typ": *

= ESDM Design <sec:design>

The ESDM can be characterized with figure @fig:big-picture which provides a
big picture of the ESDM processing and components.

#figure(
  image("../figures/big-picture.svg", width: 92%),
  caption: [ESDM Big Picture],
) <fig:big-picture>

The colors indicate the different entropy sources managed by the ESDM.

The ESDM introduces the concept of slow and fast entropy sources. Fast entropy
sources provide entropy at the time of request. A slow entropy source collects
data over time into an entropy pool.

The entropy sources that are under full control of the ESDM, also called the
internal entropy sources, comprise of the following. At most one of them may be
credited with entropy, as they all measure the timing of related events - the
build system refuses a configuration crediting two of them, and setting the
entropy rate of one of them at runtime sets the others to zero
(`esdm_config_timing_es_rate_set`):

- The cyan marked parts refer to the scheduler entropy source of the kernel
  module `esdm_es` (`kernel/esdm_es`) that feeds per-CPU rings with the time
  stamps of task wakeups. The time stamps of these rings are post-processed
  with a DRBG of the kernel module when seeding of the DRNG is to be
  performed.

- The orange marked parts refer to the interrupt entropy source of the same
  kernel module which has an identical architecture compared to the
  scheduler-based entropy source: the time stamps of interrupts are fed in
  per-CPU rings to post-process them with a DRBG.

- The light cyan and light orange marked parts refer to the eBPF-based
  scheduler and interrupt entropy sources which collect the same event timing
  on a Linux kernel without patches: eBPF programs record the time between
  successive context switches or interrupts, which the ESDM conditions with an
  XDRBG-256 pool of its own.

#par(first-line-indent: 0pt)[The following external entropy sources are
present. These entropy sources are expected to be fully self-contained. The
ESDM only requests data from them and expects that the entropy estimate
provided with the data is correct:]

- The auxiliary pool collects data from external entropy sources which deliver
  data at times not controllable by the ESDM.

- The CPU entropy source obtains data from a potentially existing source in
  the CPU like RDSEED on Intel CPUs.

- The Jitter RNG entropy source is another external entropy source, provided
  by the Jitter RNG library in user space and by the Jitter RNG of the Linux
  kernel crypto API.

- The random number generator provided with the `getrandom` system call can be
  enabled at compile time to serve as an entropy source.

- Using the Linux hardware random number generator (/dev/hwrng) as seed source
  that may obtain data from various hardware sources including TPM v2.0.

- The random number generator of a TPM 2.0 accessed via its resource manager
  device.

- An external entropy source developed outside of the ESDM which is served by
  a process of its own over a Unix domain socket - such as `esdm-es-pkcs11`,
  which serves the random number generator of a PKCS\#11 token.

#par(first-line-indent: 0pt)[The ESDM treats all external and internal entropy
sources equally. It can handle the situations where one or more entropy
sources returns little or no entropy.]

The interrupt entropy source is assessed in chapter @sec:irq-assessment which
provides its complete entropy assessment; an assessment of the scheduler
entropy sources is not provided yet (chapter @sec:sched-assessment). All other
entropy sources are
expected to provide their own entropy assessment supporting the claim of the
supplied entropy that is credited by the ESDM for these sources. The ESDM
treats these additional entropy sources as black boxes and take their claimed
entropy rate at face value. The ESDM, however, guarantees that all entropy
sources are processed in compliance with defined standards.

The different colors used in figure @fig:big-picture depict the different
entropy sources mentioned before.

The ESDM offers various interfaces to obtain random numbers as depicted in
figure @fig:interfaces.

#figure(
  image("../figures/interfaces.svg", width: 95%),
  caption: [ESDM Interfaces To Obtain Random Numbers],
) <fig:interfaces>

Based on this figure, the following types of interfaces are available which
are marked with the different colors in figure @fig:interfaces. Each type of
interface can be selectively enabled and disabled at compile time:

- Linux RNG interfaces: The common interfaces found from today's Linux kernels
  include /dev/random, /dev/urandom, the `getrandom` system call or the
  `getentropy` C-library wrapper. These interfaces behave identically to the
  Linux RNG and thus allow the ESDM to act as a drop-in replacement. When not
  compiling those, the ESDM can be operated in parallel with the Linux RNG and
  all user space software divert to use the ESDM.

- The ESDM also exports a set of Unix Domain Sockets to /run which can be
  used directly, albeit it is not advised to be used as the protocol offered
  by those sockets is defined to be not stable, i.e. it can change from one
  version to another. These are the RPC sockets `esdm-rpc-unpriv.socket` and
  `esdm-rpc-priv.socket`, whose directories are configured with the meson
  options `esdm-server-rpc-path-unprivileged` and
  `esdm-server-rpc-path-privileged`.

- To wrap the mentioned Unix Domain Sockets, the ESDM RPC library is available
  which offers a stable API.

- The ESDM server optionally serves the protocol of the Entropy Gathering
  Daemon (EGD) on the sockets `esdm-egd.socket` and `esdm-egd-pr.socket` for
  legacy consumers, see section @sec:egd. The client library
  `libesdm_egd_client`, the OpenSSL RAND providers based on it and the kernel
  module `esdm_cdev` use this interface. Unlike the other interfaces, it is
  enabled at runtime, with the options `--egd_socket` and `--egd_socket_pr` of
  the ESDM server or with its systemd socket units.

- OpenSSL 3 RAND providers route the random number requests of OpenSSL to the
  ESDM, either over the RPC interface or over the EGD interface.

- The ESDM library provides the heart of the ESDM functionality. It could be
  directly used by a calling application. Yet, it is advised to use the RPC
  interface as it is provided by a daemon that uses the ESDM library already.

#par(first-line-indent: 0pt)[The ESDM consists of the following components:]

- `libesdm.so`: The ESDM provides a library with the core of the ESDM. The
  DRNG and entropy source managers together with all entropy sources and
  cryptographic algorithm implementations are implemented with this library.
  This library is wrapped by the `esdm-server` listed below. The API for using
  the library is exported by and documented with `esdm.h`.

  The library is provided in case a user wants to employ the ESDM in his
  projects instead of the `esdm-server`. Yet, the `esdm-server` provides a
  wrapping daemon to the ESDM library that is intended to be commonly used.

  In addition, the ESDM can be configured with the options specified in
  `esdm_config.h`. This would need to be performed by the consuming
  application. When using the tools below, this library can be ignored.

- `esdm-server`: The ESDM server provides the RPC server that encapsulates the
  ESDM with its random number generator and the entropy source management.
  When starting the server, the mentioned Unix Domain Sockets are created that
  allows clients to request services including random numbers.

  The server must be started as root. It isolates itself into new mount,
  cgroup and network namespaces, initializes the ESDM - including the entropy
  sources requiring privileges, e.g. it loads the eBPF programs - and its
  status shared memory segment, creates its sockets and then permanently drops
  its privileges to an unprivileged user (option `--username`, `nobody` by
  default).

  The ESDM server can either be started manually or with the provided (and
  installed) systemd unit file. When using systemd, start the server with
  ‘systemctl start esdm-server‘.

  A wrapper library to access the ESDM server RPC interface is provided with
  `libesdm_rpc_client.so`. Its API is specified and documented with
  `esdm_rpc_client.h`.

  The `esdm-server` is the backend to all of the following ESDM components.

  Note: The Unix domain sockets of the `esdm-server` are only visible in the
  respective mount namespace. If you have multiple mount namespaces, you need
  to start the daemon in each mount namespace or make the files otherwise
  available if its services shall be available there.

- `esdm-cuse-random`: The ESDM CUSE daemon creates a device file that behaves
  identically to /dev/random. It must be started as root. Reading, writing and
  IOCTLs are implemented in an ABI-compatible way.

  The ESDM CUSE daemon can either be started manually or with the provided
  (and installed) systemd unit file. When using systemd, start the server with
  ‘systemctl start esdm-cuse-random‘. Although the daemon creates a
  /dev/random device, the actual visible operation is atomic (a bind mount)
  for both creation and destruction of the new device file which implies that
  the daemon can be started and stopped at any time during runtime of the
  Linux OS.

  Note: The bind mount is only visible in the respective mount namespace. If
  you have multiple mount namespaces, you need to start these daemons in each
  mount namespace or make the files otherwise available if their services
  shall be available there.

- `esdm-cuse-urandom`: Same as esdm-cuse-random but behaving like
  /dev/urandom.

- `esdm-proc`: This FUSE file system implements all files found on a Linux
  system under /proc/sys/kernel/random but pointing to the ESDM server:
  `boot_id`, `uuid`, `entropy_avail`, `poolsize`, `write_wakeup_threshold`,
  `urandom_min_reseed_secs` and, in addition, `esdm_type` which provides the
  status of the ESDM. This
  process is required to ensure that all interfaces are provided by ESDM. For
  details about the provided files, see the `random(4)` man page. Note, the
  kernel exports the /proc/sys/kernel/random information also as
  `sysctl(8)`. This interface is not covered by ‘esdm-proc‘.

- `libesdm-getrandom.so`: The library provides a wrapper to the `getrandom`
  and `getentropy` Linux C-library calls. To use the library for other
  consumers, use one of the following considerations:

  - Use `LD_PRELOAD="/path/to/libesdm-getrandom.so"` with the intended
    application.

  - Add the library to `/etc/ld.so.preload` for a system-wide replacement.

  - Compile the application or library with the following options:

    - `LDFLAGS += -Wl,--wrap=getrandom,--wrap=getentropy`
    - `LDFLAGS += -lesdm-getrandom`

  Process 1 and processes embedding `libesdm.so`, such as the `esdm-server`,
  use the `getrandom` system call of the kernel.

- `esdm-kernel-seeder`: The daemon draws random data from the ESDM server and
  inserts it into the Linux kernel RNG periodically - required when the
  interrupt entropy source of the kernel module deprives the kernel RNG of its
  interrupt entropy.

- `esdm-tool`: The tool interacts with the ESDM server: it shows the status of
  the ESDM, obtains random numbers, triggers the self tests, runs performance
  and stress tests and creates the reference values of the FIPS integrity
  test. The systemd unit `esdm-wait-until-fully-seeded.service` is implemented
  with it.

- `esdm-server-signal-helper`: The tool notifies the ESDM server about the
  suspend and the resume of the system.

- `libesdm_aux_client.so`: The library allows an external entropy provider to
  wait until the ESDM server needs entropy for its auxiliary pool
  (`esdm_aux_client.h`).

- `libesdm_egd_client.so`: A client library for the EGD interface of the ESDM
  server (`esdm_egd_client.h`).

- OpenSSL providers: `libesdm-rng-provider.so`, `libesdm-rng-provider-pr.so`
  and `libesdm-seed-src-provider.so` use the RPC interface,
  `libesdm-egd-provider.so` and `libesdm-egd-provider-pr.so` the EGD interface.

- `libesdm_es_ext.so`: The library external entropy sources are developed
  against (`esdm_es_ext.h`), see section @sec:ext-es. `esdm-es-pkcs11` and
  `esdm-es-pcsc` are providers based on it.

- `esdm-getrawentropy`, `esdm-ebpf-collect` and `esdm-extractlsb`: Tools to
  obtain and process the raw noise data of the entropy sources of the kernel
  module and of the eBPF-based entropy sources for their entropy assessment,
  see section @sec:test-interfaces.

- `esdm_es` (`kernel/esdm_es`): The kernel module providing the interrupt and
  the scheduler entropy sources, see sections @sec:irq-processing and
  @sec:sched-events.

- `esdm_cdev` (`kernel/esdm_cdev`): A kernel module serving the random
  numbers of the ESDM through the character devices `/dev/esdm_random` and
  `/dev/esdm_urandom` and the directory `/proc/esdm` - the counterpart of the
  CUSE daemons in the kernel, which leaves the kernel's own devices untouched.
  It obtains its data from the ESDM over the EGD interface, see section
  @sec:egd.

== ESDM Components <sec:components>

The ESDM consists of the following components shown in figure
@fig:big-picture:

+ The ESDM implements a DRNG. Unless using the interface providing prediction
  resistance, the DRNG always generates the requested amount of output. When
  using the SP800-90A terminology it operates without prediction resistance.
  The DRNG maintains a counter of how many generate operations were performed
  since last re-seed, a counter of the bits generated since the last re-seed
  with full entropy and a timer of the elapsed time since last re-seed. If
  either a counter or the timer reaches a threshold, the DRNG is seeded from
  the entropy sources with the available entropy.

  The ESDM maintains one DRNG instance per CPU as discussed in section
  @sec:numa.

  Depending on the used interface to request data from the DRNG, the caller
  may be put to sleep until the ESDM is fully seeded:

  + All interfaces using the `esdm_get_random_bytes` function generate data
    without waiting - but only once the ESDM is operational, i.e. its initial
    DRNG instance is fully seeded, and its cryptographic self tests passed.
    Otherwise the function returns an error.

  + All interfaces using the `esdm_get_random_bytes_full` function generate
    data only when the ESDM is fully seeded and fully initialized, and wait
    until then. The function `esdm_get_random_bytes_full_noblock` returns
    `-EAGAIN` instead of waiting.

  + When using the `esdm_get_random_bytes_pr` function, the special DRNG
    instance which operates with prediction resistance is used such that it is
    reseeded from the entropy sources and generates at most as much data as
    entropy was added. This implies the DRNG operates with
    prediction-resistance (SP800-90A terminology) or is NTG.1 compliant
    (German BSI AIS 20/31 from 2011). In addition, when the ESDM executes in
    FIPS mode, the behavior complies with all FIPS requirements allowing the
    output of the API to be claimed to be from a vetted conditioning
    component. I.e. the caller may safely use this data to seed another DRBG.
    To achieve this, the following checks are applied in the functions
    `esdm_drng_get` and `esdm_get_random_bytes_pr`:

    - Require a reseed before every output block - the ESDM requires the
      availability of at least 256 bits of entropy in its entropy sources for
      the reseed to commence.

    - Produce at most only 256 bits of random bits from the DRNG (i.e. the
      security strength of the DRNG) per reseed, and at most the entropy the
      reseed injected, less the 64 bits of oversampling of SP800-90C section
      6.5.1.2 (RBG3(RS)) with the SP800-90C oversampling in effect.

    - Serve only one prediction resistance request at a time - a concurrent
      request is answered with `-EAGAIN`.

    As the function may thus generate less data than requested, the caller
    must be prepared to receive no data at all. The function
    `esdm_get_random_bytes_pr_noblock` returns `-EAGAIN` instead of waiting
    for the ESDM to become operational and instead of returning no data.

+ The DRNG is seeded by concatenating the data from the following sources in
  case they are enabled at compile time, in this order (`esdm_es` in
  `esdm/esdm_es_mgr.c`):

  + the output of the interrupt entropy source of the kernel module,
  + the output of the scheduler entropy source of the kernel module,
  + the output of the eBPF-based interrupt entropy source,
  + the output of the eBPF-based scheduler entropy source,
  + the Jitter RNG if available,
  + the CPU-based entropy source such as Intel RDSEED if available,
  + the kernel RNG output,
  + the Linux kernel HWRAND framework (/dev/hwrng),
  + the TPM 2.0,
  + the Jitter RNG of the Linux kernel crypto API,
  + the external entropy source served by a provider over a Unix domain
    socket, and
  + the output of the auxiliary pool.

  The entropy estimate of the data of all entropy sources are added to form
  the entropy estimate of the data used to seed the DRNG with. The ESDM
  ensures, however, that the DRNG after seeding is at maximum the security
  strength of the used DRNG implementation of 256 bits. The data of an entropy
  source configured with an entropy rate of zero, or not able to deliver any
  entropy at the time, is not part of the seed, but
  handed to the DRNG as additional input (SP800-90C section 2.6), see section
  @sec:dp-seed-buffer. The data of the eBPF-based entropy sources is part of
  the seed once their eBPF programs are loaded, whatever their entropy rate.

  The ESDM is designed such that none of these entropy sources can dominate
  the other entropy sources to provide seed data to the DRNG due to the
  following:

  + During boot time, the amount of available entropy is the trigger point to
    (re)seed the DRNG following the explanation in the next section.

  + At runtime, the DRNG reseed is triggered by either the DRNG due to
    hitting the aforementioned thresholds or by a user space caller. The
    reseed is never triggered by the entropy sources.

+ To support backward secrecy, the following steps are applied:

  + The auxiliary pool and the conditioning pools of the eBPF entropy sources
    are each an XDRBG-256: an extraction reseeds the XDRBG and generates its
    output together with its new state, so that the output never reveals the
    state of the pool.

  + The kernel module post-processes the recorded time stamps of the
    scheduler and interrupt entropy sources with a DRBG - an XDRBG-256 as well,
    or the HMAC_DRBG of the kernel crypto API on kernels without the SHA-3
    library - whose state update provides backtracking resistance.

#par(first-line-indent: 0pt)[The ESDM allows the DRNG mechanism and the used
hash to be changed at compile time by selecting one of the crypto backends
listed in section @sec:backends. Per default, an SP800-90A Hash DRBG
implementation along with a SHA-512 hash implementation is available. Both are
standard C implementations which were tested against NIST's ACVP service.]

The following subsections cover the different components of the ESDM from the
bottom to the top.

== ESDM Data Processing <sec:data-processing>

The processing of entropic data from the different entropy source before
injecting them into the DRNG is performed with the following mathematical
operations. The operation $"SHA"()$ refers to the hash operation using the
message digest implementation that is currently present, i.e. SHA-512 or
SHA3-512 depending on the crypto backend (see section @sec:backends). The
operation $"SHAKE256"(x, l)$ refers to the extendable output function SHAKE256
of the crypto backend returning $l$ bits of output for the input $x$. The
operation $"XDRBG.Extract"$ refers to the extraction of an XDRBG-256 pool
specified in section @sec:dp-aux, the operations $"DRBG.Seed"$ and
$"DRBG.Generate"$ to the DRBG of the kernel module `esdm_es`.

=== Scheduler and Interrupt Entropy Sources <sec:dp-sched-irq>

+ Time stamp: The time stamps received by the IRQ as well as the scheduler
  entropy sources of the kernel module are obtained with `random_get_entropy`
  and divided by the GCD – note the GCD is a value calculated from the first
  100 time stamps after loading the module or a reset of the entropy source
  and is fixed thereafter which
  implies that the time stamp divided by the GCD is the raw entropy value $t$,
  a 64-bit integer. Until the GCD is calculated, the time stamp is used
  undivided - the implementation is provided with function `esdm_time_process`.

+ Health test: Each time stamp is subject to the health tests of section
  @sec:health-tests. Only time stamps passing them are recorded.

+ Concatenation: The time stamps received by the IRQ and scheduler entropy
  sources are concatenated in a per-CPU ring that is capable of holding 4,095
  time stamps#footnote[The size of the ring is derived from the compile-time
  configurable oversampling rate `ESDM_ES_OSR` of the kernel module where 3
  is the default value: the ring has the smallest of 4,096, 8,192, 16,384
  and 32,768 slots that holds the time stamps of the largest request.
  However, this modification has no impact to the illustration of the data
  processing.] - when the ring is full, newly received time stamps are
  dropped - the implementation is provided with function `esdm_es_ring_add`:

  $ "CP"_"CPU" = t_(n-k) || t_(n-k+1) || ... || t_(n-1) || t_n $ <eq:cp>

=== Interrupt Entropy Source <sec:dp-irq>

+ DRBG seeding: When data is requested from the interrupt entropy source, the
  time stamps needed for one output block of the size of the security
  strength $s = 256$ bits of the DRBG are collected from the per-CPU rings of
  all CPUs and handed to the DRBG of the kernel module as seed. These are
  $ceil((s + o) dot r \/ 256)$ time stamps, $r$ being the number of time
  stamps credited with 256 bits of entropy ($256 dot "ESDM_ES_OSR"$ per
  default) and $o$ the oversampling of 65 bits (129 bits for the instantiation
  of the DRBG) when the kernel is built with `CONFIG_CRYPTO_FIPS` and booted
  with `fips=1`, and 0 otherwise. If the rings hold fewer time stamps, no data
  is generated and the time stamps remain in the rings. The first seed
  instantiates the DRBG, all later ones reseed it - the implementation is
  provided with the function `esdm_es_drbg_pool_extract_block`:

  $ "EP"_n = "DRBG.Seed"("EP"_(n-1), "CP"_("CPU0") || "CP"_("CPU1") || ...
    || "CP"_("CPUX")) $ <eq:ep-cpu>

  The DRBG is the XDRBG-256 of section @sec:xdrbg, which the kernel module
  compiles from `esdm/crypto/esdm_xdrbg.c`, over the SHAKE256 of the SHA-3
  library of the kernel (`CONFIG_CRYPTO_LIB_SHA3`), which Linux 7.2 and later
  require. On an older kernel without that library, it is the HMAC_DRBG with
  SHA-512 of the kernel crypto API.

+ Generation: One output block is generated from the DRBG with the additional
  input "ESDM_IRQ_DRBG" for domain separation, which is also the
  personalization string of the DRBG:

  $ B_n = "DRBG.Generate"("EP"_n, s, "\"ESDM_IRQ_DRBG\"") $ <eq:ep-all>

+ Concatenation: As many blocks are generated as needed for the number of bits
  $b$ requested by the ESDM (256, 320 or 384 bits), each with a seed of its
  own. The data is only delivered if the rings hold the time stamps of all
  blocks; it is then credited with $b$ bits of entropy - the implementation is
  provided with function `esdm_es_drbg_pool_extract`:

  $ E_n = "MSB"_b (B_(n,1) || ... || B_(n, ceil(b \/ s))) $ <eq:e>

=== Scheduler Entropy Source <sec:dp-sched>

The scheduler entropy source applies the same processing as the interrupt
entropy source with per-CPU rings and a DRBG instance of its own and the
additional input "ESDM_SCH_DRBG":

$ "SP"_n = "DRBG.Seed"("SP"_(n-1), "CP"_("CPU0") || "CP"_("CPU1") || ...
  || "CP"_("CPUX")) $ <eq:sp-cpu>

$ B_n = "DRBG.Generate"("SP"_n, s, "\"ESDM_SCH_DRBG\"") $ <eq:sp-all>

$ S_n = "MSB"_b (B_(n,1) || ... || B_(n, ceil(b \/ s))) $ <eq:s>

This operation is performed in process context at the time the entropy
source is requested for random data.

=== eBPF-based Scheduler and Interrupt Entropy Sources <sec:dp-ebpf>

+ Time delta: The eBPF programs obtain the time stamp of an event with
  `bpf_ktime_get_ns` and divide it by the GCD of the first 100 time stamps of
  the CPU. The time stamp is subject to the health tests of section
  @sec:health-tests. Of the time stamps passing them, the difference to the
  preceding time stamp of the same CPU passing them, a 64-bit integer $d$, is
  recorded.

+ Concatenation: The deltas are concatenated in a per-CPU batch of 64 deltas
  which is handed to a BPF ring buffer when it is full, or when no delta was
  collected for 250 ms.

+ Insertion: The ESDM reads the batches from the ring buffer and inserts the
  deltas into the XDRBG-256 conditioning pool $"XP"$ of the entropy source as
  seed data of its next reseed - the implementation is provided with the
  functions `esdm_ebpf_consume` and `esdm_xdrbg_insert`.

+ Extraction: The pool is extracted as specified for the auxiliary pool in
  section @sec:dp-aux with the additional input $alpha$ = "ESDM eBPF pool "
  followed by the name of the entropy source - the implementation is provided
  with the function `esdm_ebpf_get_ent`:

  $ E^"eBPF"_n = "XDRBG.Extract"("XP", d_(m-k) || ... || d_m, alpha) $
  <eq:ebpf>

=== Auxiliary Entropy Pool <sec:dp-aux>

The auxiliary pool $"AP"$ is an XDRBG-256 - the XDRBG over SHAKE256 (J. Kelsey,
S. Lucks, S. Müller, IACR ToSC 2024(1)) with a state $V$ of 512 bits -
implemented in `esdm/crypto/esdm_xdrbg.c`. The number of auxiliary pools is
configurable with the meson option `num-aux-pools` (one per default). Each pool
uses the additional input $alpha$ = "ESDM aux pool" followed by the index of
the pool in two bytes, which separates the pools.

+ Insertion: When new data $D_m$ is added to the auxiliary pool $"AP"$, the data
  is absorbed by the SHAKE256 context of the pool and becomes part of the seed
  of its next reseed - the implementation is provided with function
  `esdm_pool_insert_aux` and `esdm_xdrbg_insert`. Data without entropy is
  inserted into all pools, data with entropy into the one pool that can take
  most of it.

+ Reseed: When entropy is requested from the auxiliary pool, the XDRBG is
  reseeded with the data inserted since the last extraction, where
  $"encode"(alpha, n) = alpha || (85 n + |alpha|)$ appends one byte to $alpha$
  and $V'_(n-1)$ is the state left by the previous extraction:

  $ V_n = "SHAKE256"(V'_(n-1) || D_(m-k) || ... || D_m || "encode"(alpha, 1),
    512) $ <eq:ap>

  The first extraction instantiates the XDRBG with
  $V_1 = "SHAKE256"(D_1 || ... || D_m || "encode"(alpha, 0), 512)$.

+ Generation: The output $A_n$ of the size requested by the DRNG - at most the
  seed size of 256 or 384 bits - is generated together with the new state
  $V'_n$, with which the SHAKE256 context of the pool is started for the next
  reseed - the implementation is provided with the function
  `esdm_xdrbg_extract`:

  $ V'_n || A_n = "SHAKE256"(V_n || "encode"(alpha, 2), 512 + |A_n|) $ <eq:a>

#par(first-line-indent: 0pt)[The reseed and the generation together form the
operation $A_n = "XDRBG.Extract"("AP", D_(m-k) || ... || D_m, alpha)$.]

=== CPU Entropy Source <sec:dp-cpu>

+ Hashing: If the CPU entropy source provides less than full entropy, i.e.
  its data multiplier $m$ is larger than one, a message digest of $m$ times
  the amount of data to be requested from it is calculated, plus $64 dot m$
  bits with the SP800-90C oversampling in effect:

  $ C_"cond" = "SHA"(C_1 || ... || C_m) $ <eq:c-cond>

+ Truncation: If the CPU entropy source provides less than full entropy, the
  MSB defined by the requested number of bits (commonly equal to the security
  strength of the DRBG) or the applied message digest size, what ever is
  smaller, are obtained - the implementation is provided with function
  `esdm_get_cpu_data_compress` – otherwise $C_n$ is the data obtained
  directly from the CPU entropy source:

  $ C_n = "MSB"_(min("digest size", "requested bits"))(C_"cond") $ <eq:c>

=== Temporary Seed Buffer Construction <sec:dp-seed-buffer>

+ Concatenation: The temporary seed buffer $T$ used to seed the DRNG at the
  time $n$ is a concatenation of one or more of the following entropy source
  data sets, depending on the compile-time configuration, each one held in a
  slot of its own together with its entropy estimate:

  + the interrupt entropy source buffer $E$,
  + the scheduler entropy source buffer $S$,
  + the eBPF-based interrupt entropy source buffer $E^"eBPF"$,
  + the eBPF-based scheduler entropy source buffer $S^"eBPF"$,
  + the Jitter RNG output $J$,
  + the CPU entropy source output $C$,
  + the kernel RNG entropy source output $K$,
  + the Linux HWRAND framework $H$,
  + the TPM 2.0 output $M$,
  + the output of the Jitter RNG of the kernel crypto API $J^"K"$,
  + the output of the external entropy source $X$,
  + the auxiliary pool entropy source $A$, and
  + the current time $t$ (`CLOCK_MONOTONIC`)

  with the implementation is provided with function `esdm_get_seed_buffers`:

  $ T_n = E_n || S_n || E^"eBPF"_n || S^"eBPF"_n || J_n || C_n || K_n || H_n
    || M_n || J^"K"_n || X_n || A_n || t $ <eq:t>

+ Separation: The data of an entropy source that is configured with an entropy
  rate of zero, or not able to deliver any entropy at the time, other than an
  eBPF-based entropy source, is placed in the slot of a second buffer of the
  same layout, the additional input $U_n$, and the slot of that entropy source in $T_n$ is
  left empty - the implementation is provided with the function
  `esdm_es_seed_slot`. The DRNG is seeded with $T_n$ as seed and $U_n$ as
  additional input.

== ESDM Architecture <sec:architecture>

Before going into the details of the ESDM processing, the concept underlying
the ESDM shown in figure @fig:big-picture is provided here.

The entropy derived from the slow entropy sources is collected and accumulated
in the per-CPU rings of the kernel module which contain uncompressed, but only
concatenated entropy data, in the conditioning pools of the eBPF entropy
sources and in the auxiliary pool.

At the time the DRNG shall be seeded, all entropy sources are requested for
data - in parallel threads with the meson option `es_parallel_fetch`, which is
enabled per default. The kernel module post-processes the recorded time
stamps with its DRBG, the XDRBG-256 pools are extracted.

For the entropy sources, data of the size requested by the caller is generated
which is credited with at most the available entropy. For the auxiliary pool,
always the requested size of data is returned irrespective of the entropy rate
of this pool. This ensures that also data that is not credited with entropy
but injected into the ESDM is used to stir the seed for the DRNG.

The DRNG always tries to seed itself with 256 bits of entropy, or 384 bits for
the initial seeding with the SP800-90C oversampling in effect. In any case, if
the entropy sources cannot deliver that amount, the available entropy is used
and the DRNG keeps track on how much entropy it was seeded with. During boot,
the DRNG is seeded as follows:

+ The DRNG is reseeded from the entropy sources if all entropy sources
  collectively have at least 256 bits of entropy available (384 bits with the
  SP800-90C oversampling in effect). The initialization of the ESDM performs a
  forced seeding of the initial DRNG instance right away
  (`esdm_force_fully_seeded_all_drbgs`).

#par(first-line-indent: 0pt)[The ESDM also implements a forced seeding
operation, also called emergency reseeding. This is performed for every
seeding of a DRNG that is not fully seeded and for the reseed of a DRNG that
reached its maximum output without a full reseed. The forced seeding performs a continuous reseeding of the DRNG in an atomic
operation with existing entropy.
This means that a regular reseeding is triggered repeatedly as often as needed
to obtain 256 bits of entropy to reach the fully seeded level. In this case,
the entropy obtained from the entropy sources is added up. This is permissible
because the multiple reseeding operations are performed while the DRNG is
locked, i.e. the DRNG will not produce output in that time. The repetition
stops as soon as no entropy source delivers entropy any more (fewer than two
for the initial seeding with the NTG.1 seeding strategy, unless the Jitter RNG
operates in its own NTG.1 mode) - the implementation is provided with the
function
`esdm_drng_seed_es`. A reseed of a fully seeded DRNG collects the entropy
without holding the lock of the DRNG, which keeps serving requests meanwhile,
and locks it for the injection of the seed only
(`esdm_drng_reseed_seed_locked`). Figure @fig:seeding illustrates the seeding
operation of a DRNG.]

#figure(
  image("../figures/drng-seeding.svg", width: 72%),
  caption: [DRNG Seeding Operation],
) <fig:seeding>

At the time of the reseeding steps, the DRNG requests as much entropy as is
available in order to skip certain steps and reach the seeding level of 256
bits. This may imply that one or more of the aforementioned steps are skipped.

In all listed steps, the DRNG is (re)seeded with a number of random bytes from
the entropy pool that is at most the amount of entropy present in the entropy
pool. This means that when the entropy pool contains 256 or more bits of
entropy, the DRNG is seeded with that amount of entropy as well.

Before the DRNG is fully seeded, requests of random data from the blocking
interfaces are not processed.

At runtime the DRNG operates as deterministic random number generator with the
following properties:

- The maximum number of random bytes that can be generated with one DRNG
  generate operation is limited to 4096 bytes - $2^16$ bytes in a build that
  limits the output without a full reseed (see below). When longer random
  numbers are
  requested, multiple DRNG generate operations are performed. The used DRNGs
  implement an update of their state during the generation operation for
  backward secrecy.

- The DRNG is reseeded with whatever entropy is available, but at least 256
  bits – in the worst case where
  no additional entropy can be provided by the entropy sources, the DRNG is
  re-seeded with the current time only and continues its operation to try
  to reseed again after again the expiry of one of these thresholds:

  - If the last reseeding of the DRNG is more than 600 seconds
    ago#footnote[Note, this value will not empty the entropy pool even on a
    completely quiet system. Testing of the ESDM was performed on a KVM
    without fast entropy sources and with a minimal user space, where only the
    SSH daemon was running, During the testing, no operation was performed by
    a user. Yet, the system collected more than 256 bits of entropy from the
    interrupt entropy source within that time frame, satisfying the DRNG
    reseed requirement.] - the interval can be set at runtime to at most 3600
    seconds (`esdm_set_reseed_max_time`), where an interval of 0 seconds
    reseeds the DRNG before every request -, or

  - $2^20$ DRNG generate operations are performed, whatever comes first, or

  - the number of bits generated since the last reseed with full entropy
    reaches the threshold of the meson option `drng_reseed_threshold_bits`
    (disabled per default; at most 98,304 bits in a build with the meson
    option `sp80090c`, `fips140` or `ais2031_drg4` and without
    `ais2031_drg3`), or

  - the DRNG is forced to reseed before the next generation of random numbers
    with the `RNDRESEEDCRNG` IOCTL or the respective RPC and EGD interfaces
    (`esdm_drng_force_reseed`).

  The chosen values prevent high-volume requests from user space to cause
  frequent reseeding operations which drag down the performance of the
  DRNG#footnote[Considering that the maximum request size is 4096 bytes
  defined by `ESDM_DRNG_MAX_REQSIZE` (i.e. each request is segmented into 4096
  byte chunks) and at most $2^20$ requests defined by
  `ESDM_DRNG_RESEED_THRESH` can be made before a forced reseed takes place, at
  most $4096 dot 2^20 = 4,294,967,296$ bytes can be obtained from the DRNG
  without a reseed operation.].

- The per-CPU DRNG instances discussed in section @sec:numa are reseeded by
  a reseed worker thread ahead of the requests, so that a request does not
  wait for the collection of entropy: in each pass, the worker reseeds the
  DRNG instances whose reseed is due and brings up the DRNG instances that
  are not fully seeded, each seeding on a thread of its own, at most as many
  at once as there are Jitter RNG collectors (section @sec:jent). The seed
  time of a per-CPU DRNG instance is pushed out by a random offset of up to a
  tenth of the reseed interval, so that the DRNG instances do not all fall due
  at once. The worker sleeps until the next reseed falls due, at most 20
  seconds - the implementation is provided with the function
  `esdm_drng_reseed_worker`. The initial DRNG instance is reseeded by the
  worker as well as within the
  request when its reseed is due, the prediction resistance DRNG instance
  only within the request, for every output block.

- If the DRNG was not reseeded with full entropy for the last $2^30$ DRNG
  generate operations –
  i.e. the reseeding requests discussed in the previous bullets were
  unsuccessful – the DRNG reverts back to an unseeded state. This applies that
  the DRNG will not produce random numbers when accessed via the blocking
  interfaces. In this case, the DRNG behaves like during boot time, see
  section @sec:not-fully-seeded.

- If the number of bits generated since the last reseed with full entropy
  reaches the threshold of the meson option `drng_max_reseed_bits` (disabled
  per default; at most $2^17$ bits in a build with the meson option
  `sp80090c`, `fips140` or `ais2031_drg4` and without `ais2031_drg3`), the
  DRNG starts no further generate operation until it is reseeded with full
  entropy by the reseed worker - the initial DRNG instance, which stops
  already at the threshold of `drng_reseed_threshold_bits`, by the next
  request as well. Without a reseed worker, a per-CPU DRNG instance reverts
  back to an unseeded state instead.

#par(first-line-indent: 0pt)[The reseed interval is measured with
`CLOCK_MONOTONIC_COARSE`, which does not advance while the system is
suspended: the time of a suspend does not count towards the 600 seconds.]

=== Fully Seeded Level <sec:seed-levels>

The ESDM's DRNG is reseeded when the first 256 bits of entropy are
received during boot as indicated above. Reaching the 256 bits level
is defined as the DRNG is “fully” seeded, or reaching 384 bits for the
initial seeding with the SP800-90C oversampling in effect - the
implementation is provided with the function `esdm_fully_seeded`. With the AIS
20/31 NTG.1 seeding strategy (meson option `ais2031_ntg1`), the initial
seeding requires instead that two entropy sources deliver at least 240
bits of entropy each, or that the Jitter RNG operated in its own NTG.1 mode
alone delivers 240 bits of entropy.

The ESDM is operational once its initial DRNG instance is fully seeded;
random numbers are generated once in addition the self tests of its
cryptographic primitives passed. This level has the following implications:

- When reaching the fully seeded level, the user-space callers waiting for a
  fully seeded DRNG via the `getrandom` system call or /dev/random are woken
  up. Using the ESDM API of `esdm_get_random_bytes_full`, the caller is
  waiting synchronously until the fully seeded level is reached.

=== DRNG Instances <sec:numa>

To prevent bottlenecks in large systems, the DRNG will be instantiated once
for each CPU (meson option `node`, enabled per default), limited to the
number of worker threads of the meson option `threading_max_worker_threads`
(64 per default), and at runtime with `esdm_config_max_nodes_set` or the
option `--small_memory` of the ESDM server, which uses one DRNG instance. The
DRNG instance of node zero is the initial DRNG instance. The instantiations of
the DRNGs happen all at the same time when the ESDM is initialized. Next to
them, the ESDM maintains the DRNG instance operated with prediction
resistance, which is seeded for every output block it generates.

The question now arises how are the different DRNGs seeded without re-using
entropy or relying on random numbers from a yet insufficiently seeded ESDM.
The ESDM seeds the DRNGs starting with the one for node zero
– the DRNG for node zero is seeded with the approach discussed above. Once
the DRNG for node 0 is fully seeded, the ESDM will seed the DRNG of node one
when having again 256 bits of entropy available. This is followed by seeding
the DRNG of node two after having again collected 256 bits of entropy, and so
on - with the reseed worker, several DRNG instances are brought up side by
side, each from entropy collected for it. Figure
@fig:numa illustrates the seeding strategy showing that each DRNG instance is
freshly seeded with a separate seed buffer.

#figure(
  image("../figures/numa-drng.svg", width: 90%),
  caption: [DRNG Instances with seeding strategy],
) <fig:numa>

When producing random numbers, the ESDM tries to obtain the random numbers
from the DRNG of the current CPU: it probes the DRNG instances starting with
that one, skips the instances that are busy, not fully seeded or out of their
output budget, and uses the first one that is fully seeded. If no such DRNG is
found, it falls back to using the DRNG for node zero - the implementation is
provided with the function `esdm_drng_get_sleep`. A worker thread of the
RPC interfaces of the ESDM server starts the probing with a DRNG
instance of its own instead of the one of its CPU: worker $i$ with node
$1 + (i mod (N - 1))$ for $N$ DRNG instances (`esdm_config_thread_node_set`).

=== Flexible Design <sec:flexible-design>

Albeit the preceding sections look like the DRNG and the management logic are
highly interrelated, the ESDM code allows for an easy replacement of the DRNG
with another deterministic random number generator. This flexible design
allowed the implementation of the ChaCha20 DRNG if the SP800-90A DRBG is not
desired, as well as of the different crypto backends.

To implement another DRNG, all functions in `struct esdm_drng_cb` in
`esdm/esdm_crypto.h` must be implemented. These functions cover the
allocation/deallocation of the DRNG as well as its usage. Similarly, all
functions in `struct esdm_hash_cb` from `esdm/esdm_crypto.h` must be
implemented to provide the conditioning hash, and all functions in
`struct esdm_xof_cb` from `esdm/crypto/esdm_xof.h` to provide the SHAKE256 of
the XDRBG-256 pools.

The implementations can be changed at compile time. The default
implementation is the SP800-90A Hash-DRBG using a software-implementation of
the used SHA-512 message digest, together with a software implementation of
SHAKE256 for the XDRBG-256 pools.

In addition, the ESDM allows the addition of new entropy sources, also outside
of the ESDM code as external entropy source (section @sec:ext-es).

== ESDM Data Structures <sec:data-structures>

The ESDM uses the following main data structures:

- The data from the interrupt and scheduler entropy sources of the kernel
  module is recorded in per-CPU rings. The rings are written lockless since
  the currently executing CPU's ring is used by a single writer. Reading the
  rings for seeding the DRBG of the kernel module is serialized by the lock of
  the IOCTL interface of the kernel module, while a spin lock which is not
  used by the writers orders a reset of the rings against a reading of them.
  As the filling of the seed buffer is very infrequently (see above for the
  reseed periods of the DRNG), the lock is hardly contented which allows the
  conclusion that the entropy collection operates quasi-lockless.

- The eBPF entropy sources collect their data in per-CPU maps of the eBPF
  programs, which operate lock-less. Their conditioning pools as well as the
  auxiliary pools are each protected by a lock of their own.

- The cryptographic algorithm data structures hold the reference to the DRNG
  instance and the hash instance and associated meta data needed for its
  operation. Each DRNG instance is protected by a lock of its own which guards
  its state, and by a second lock which serializes its seedings, so that the
  entropy for one DRNG is collected once. The seedings of different DRNG
  instances run side by side, as the entropy sources lock themselves. The
  array of the per-CPU DRNG instances is guarded by a read-write lock, which
  is only taken for writing to release the array during shutdown. The hash
  references are not replaced at runtime, so the hash is used without a lock:
  the hash state is kept by the caller - on its stack for the builtin hash.

== Interrupt Processing - ESDM-internal Entropy Source <sec:irq-processing>

The interrupt entropy source is provided by the kernel module `esdm_es`
(`kernel/esdm_es`, built with `BUILD_ES_IRQ=1`, which is the default of its
Makefile). With the kernel patch `0002-ESDM-interrupt-entropy-source-hooks`,
the ESDM hooks a callback into the interrupt handler at the same
location where the legacy /dev/random places its callback hook
(`add_interrupt_randomness`). While the callback is registered, the legacy
/dev/random does not receive the interrupt events any more. The ESDM reads
the entropy source via the IOCTLs of the device `/dev/esdm_es` of the kernel
module (`kernel/shared/esdm_es_ioctl.h`).

The ESDM interrupt processing callback receives the number of the interrupt
from the interrupt handler, which it does not use. That interrupt processing
callback is the hot code path in the ESDM and special care is taken that it is
as short as possible and that it operates without locking.

Figure @fig:irq-processing illustrates the interrupt processing performed by
the ESDM. The figure specifies which parts of the interrupt processing execute
in IRQ context and which executes in process context. The operations executed
in interrupt context are all completely listed in this section. All steps
executed in process context are illustrated in section @sec:seeding.

The figure depicts the example when one interrupt arrives on CPU 0. If an
interrupt arrives on another CPU, the same operation is applied, but the
respective CPU-local ring is used. The rings from other CPUs in the figure
therefore are filled with the same processing steps, which, however, are not
shown.

#figure(
  image("../figures/irq-processing.svg", width: 100%),
  caption: [Interrupt Processing],
) <fig:irq-processing>

The following processing happens when an interrupt is received and the ESDM
is triggered:

+ A high-resolution time stamp is obtained using the service
  `random_get_entropy` kernel function. This integer value is divided by a GCD
  to eliminate bits that do not change. The GCD is calculated from the first
  100 time stamps; a GCD of 1,000 or more indicates a timer too coarse to
  deliver entropy, which stops the crediting of entropy. Until the GCD is
  calculated, the undivided time stamp is processed. Entropy is contained in
  the variations of the time of events and its time delta variations.

+ The health tests discussed in section @sec:health-tests are performed on
  each received time stamp. A time stamp not passing them is dropped.

+ The time stamp is stored as a 64-bit value in the operating CPU's ring. When
  the ring is full, the time stamp is dropped.

+ The number of time stamps recorded in the rings of all CPUs is translated
  into an entropy statement when the ESDM wants to know how much entropy is
  present in the entropy source.

+ When the ESDM requests data from the interrupt entropy source with the
  `ESDM_IRQ_ENT_BUF` IOCTL, the recorded time stamps are post-processed with
  the DRBG of the kernel module as specified in section @sec:dp-irq and
  depicted in figure @fig:collection-pool. This is performed in process
  context.

  #figure(
    image("../figures/collection-pool-processing.svg", width: 70%),
    caption: [Kernel Entropy Source Data Extraction],
  ) <fig:collection-pool>

+ The ESDM server implements a monitor thread that polls the interrupt ES for
  its entropy level every $2^29$ nanoseconds until all DRNGs become fully
  seeded. While the poll monitor is active, every time the interrupt ES
  entropy level reaches the entropy rate configured for the interrupt ES (the
  meson option `es_irq_entropy_rate`, 256 bits per default), a reseed is
  triggered as discussed in section @sec:seeding.

+ If all DRNG instances are fully seeded, the poll monitor stops polling the
  interrupt ES. This implies
  that only during boot time the next step is triggered. At runtime, the
  entropy sources will not trigger a reseeding of the DRNG.

#par(first-line-indent: 0pt)[The entropy collection mechanism is available
immediately after the kernel RNG reached full entropy. This shall guarantee
that the kernel RNG is fully seeded before hijacking its main entropy source.
To prevent starving the kernel RNG, the `esdm-kernel-seeder` reseeds the
kernel RNG periodically with 512 bits of data obtained from the ESDM server,
every 120 seconds per default (meson option `linux-reseed-interval`, the
systemd unit of the daemon sets 10 seconds), credited with the entropy of the
meson option `linux-reseed-entropy-count` (0 per default).]

In case the underlying system does not support a high-resolution time stamp,
the kernel module refuses to load.

=== Entropy Amount of Interrupts <sec:entropy-interrupts>

The discussion of the entropy content of scheduling events in section
@sec:entropy-sched-events applies to the interrupt-based entropy. The only
difference is the use of the compile-time entropy value of
`CONFIG_ESDM_IRQ_ENTROPY_RATE`, which is $256 dot "ESDM_ES_OSR"$ as well, and
the meson option `es_irq_entropy_rate` (256 bits per default).

=== Health Tests <sec:irq-health-tests>

The health tests documented in section @sec:health-tests are applied to the
interrupt entropy source as well. The ESDM ensures that the health tests for
the interrupt and the scheduler entropy sources are strictly separated. This
separation applies to the SP800-90B as well.

== Scheduler Events - ESDM-internal Entropy Source <sec:sched-events>

The scheduler entropy source is provided by the kernel module `esdm_es` as
well, built with `BUILD_ES_SCHED=1` (disabled per default in its Makefile).
With the kernel patch `0001-ESDM-scheduler-entropy-source-hooks`, the ESDM
hooks into the scheduling operation of the Linux kernel which is
triggered every time a task is woken up (`ttwu_stat` called by
`try_to_wake_up`). The ESDM handling of a scheduling event is depicted with
figure @fig:sched-processing.

#figure(
  image("../figures/sched-processing.svg", width: 100%),
  caption: [Scheduler-event Processing],
) <fig:sched-processing>

When a task is woken up, the ESDM callback is invoked which obtains a
high-resolution time stamp that is processed like the time stamp of an
interrupt as outlined in figure @fig:sched-pool: it is divided by the GCD,
subjected to the health tests and stored in the CPU-local ring. When the
CPU-local ring is full, the time stamp is dropped.

#figure(
  image("../figures/sched-pool-management.svg", width: 62%),
  caption: [Scheduler Event Recording],
) <fig:sched-pool>

At the time the DRNG shall be (re)seeded, the time stamps of the per-CPU rings
are post-processed with the DRBG of the scheduler entropy source as specified
in section @sec:dp-sched. This guarantees that “unused
entropy” is appropriately protected by the state of the DRBG. The
data processing concepts between the scheduler ES and the interrupt ES are
identical when comparing the figures in this section to section
@sec:irq-processing.

This entire post-processing is performed in the process context.
Therefore, the DRBG operation is not performed as part of the scheduling
operation.

As a side note, the scheduler entropy source potentially has some
relationship with the IRQ entropy source because an IRQ may trigger a
scheduler event (e.g. with the flag `TIF_NEED_RESCHED`). Therefore, both
entropy sources cannot be used at the same time and credit entropy to both.
It is permissible to use both, but only one is credited with entropy.

=== Entropy Amount of Scheduling Events <sec:entropy-sched-events>

The question now arises, how much entropy is generated with the scheduler
entropy source. The kernel module assumes $1 \/ "ESDM_ES_OSR"$ bits of
entropy per time stamp obtained for one scheduling event, i.e. one third of
a bit with the default oversampling rate of 3.

With the kernel module compile time parameter of
`CONFIG_ESDM_SCHED_ENTROPY_RATE` the number of scheduling events that must be
collected to obtain 256 bits of entropy is specified: $256 dot "ESDM_ES_OSR"$.
The ESDM requests the kernel module to credit the rate of the meson option
`es_sched_entropy_rate` (0 per default, i.e. the scheduler entropy source is
not credited with entropy unless configured), but the kernel module never
credits more entropy than its own rate.

The entropy of high-resolution time stamps is provided with the fast-moving
least significant bits of a time stamp which is supported by the quantitative
measurements of interrupt time stamps shown in chapter @sec:irq-assessment.
The ESDM records the entire 64-bit time stamp after its division by the GCD
and leaves its compression to the DRBG post-processing.

The Linux kernel allows unprivileged user space processes to monitor the
scheduling events of interrupts by reading the process listing with a certain
degree of accuracy. The ESDM uses a high-resolution time stamp that executes
with nanosecond precision on 1 GHz systems. Local attackers are expected to be
measure the occurrence of a scheduling event with a microsecond precision. The
distance between a microsecond and a nanosecond is $2^10$. Thus, when the
attacker is assumed to predict the interrupt occurrence with a microsecond
precision and the time stamp operates with nanosecond precision, 10 bits of
uncertainty remains that cannot be predicted by that attacker. Hence, only
these 10 bits can deliver entropy.

=== Health Tests <sec:health-tests>

The ESDM implements the following health tests:

- Stuck Test
- Repetition Count Test (RCT)
- Adaptive Proportion Test (APT)

#par(first-line-indent: 0pt)[Those tests are detailed in the following
sections. They are implemented in `kernel/esdm_es/esdm_health.c` for the
entropy sources of the kernel module and in
`esdm/es_ebpf/esdm_es_ebpf_health.bpf.h` for the eBPF entropy sources, both
with the cut-off values of `kernel/shared/esdm_health_cutoffs.h`. The kernel
module runs the RCT and the APT over the time stamps of all CPUs, while the
eBPF entropy sources run every test, the startup test included, for each CPU
on the time stamps of that CPU.]

Please note that these health tests are only performed for the internal
entropy sources. Other entropy sources like the entropy sources feeding the
auxiliary pool, the Jitter RNG, or the CPU-based entropy sources are not
covered by these tests as they are fully self-contained entropy sources where
the ESDM does not have access to the raw noise data and does not include a
model of the entropy source to implement appropriate health tests. The ESDM
considers both as external entropy source. Thus, the user must ensure that
either those other entropy sources implement all health tests as needed - the
ESDM operates the Jitter RNG with its health tests enforced (`JENT_FORCE_FIPS`)
with the SP800-90C oversampling in effect, in FIPS mode or with the NTG.1
seeding strategy - or the ESDM must be configured such that these entropy
sources are credited with zero bits of entropy. Not crediting any entropy to
these other entropy sources can be achieved with the following configuration
options:

- Sources feeding the auxiliary entropy pool: The interface functions to
  provide entropy data have to be invoked with the value 0 for the entropy
  rate.

- CPU-based entropy source: `es_cpu_entropy_rate=0`

- Jitter RNG: `es_jent_entropy_rate=0`

#par(first-line-indent: 0pt)[These options ensure that random data from the
entropy sources are pulled, but are not credited with any entropy.]

The kernel module performs the stuck test on every time stamp and drops stuck
time stamps. The RCT, and the APT health test as well as the SP800-90B startup
test are only performed by the kernel module when the kernel is booted with
`fips=1`. The health tests of the eBPF entropy sources are only performed in
FIPS mode or with the NTG.1 seeding strategy.

In addition, the entropy sources are only credited if a high-resolution time
stamp is found. Systems with a low-resolution time stamp will not deliver
sufficient entropy for the interrupt entropy source which implies that also
the health tests are not applicable.

#paragraph[Stuck Test][The stuck test calculates the first, second and third
discrete derivative of the time stamp to be recorded in the per-CPU
ring. Only if all three values are non-zero, the received time
delta is considered to be non-stuck. The first derivative calculated by the
stuck test verifies that two successive time stamps are not equal, i.e. are
“stuck”. The second derivative calculates that there is no linear repetitive
signal.]

The third derivative of the time stamp is considered relevant based on the
following: The entropy is delivered with the variations of the occurrence of
interrupt events, i.e. it is mathematically present in the time differences
of successive events. The time difference, however, is already the first
discrete derivative of time. Now, if the time difference delivers the actual
entropy, the stuck test shall catch that the time differences are not stuck,
i.e. the first derivative of the time difference (or the second derivative of
the absolute time stamp) shall not be zero. In addition, the stuck test shall
ensure that the time differences do not show a linear repetitive signal –
i.e. the second discrete derivative of the time difference (or the third
discrete derivative of the absolute time stamp) shall not be zero.

#paragraph[Repetition Count Test][The ESDM uses an enhanced version of the
Repetition Count Test (RCT) specified in SP800-90B @sp80090b section 4.4.1.
Instead of counting identical back-to-back values, the input to the RCT is the
counting of the stuck values during the processing of received
events. The data that is recorded is the time stamp. As the
stuck result includes the comparison of two back-to-back time stamps by
computing the discrete derivatives of the time stamp, the RCT simply
checks whether the stuck test found the time stamp stuck. If so,
the RCT counter is increased. Otherwise, the RCT counter is reset to
zero.]

The RCT is applied with $alpha = 2^(-30)$ compliant to the recommendation of
FIPS 140-2 IG 9.8. Considering the assumed entropy of $1 \/ "OSR"$ bits per
time stamp, the cut-off value is $30 dot "OSR"$ for an intermittent failure
and $60 dot "OSR"$ for a permanent failure.

During the counting operation, the ESDM always calculates the RCT cut-off
value of C. If that value reaches the allowed cut-off value, the ESDM will
trigger the health test failure discussed below. An error is logged to the
kernel log that such a health test failure occurred, by the eBPF entropy
sources to the log of the ESDM server, naming the RCT.

This test is only applied and enforced in FIPS mode (for the eBPF entropy
sources also with the NTG.1 seeding strategy).

#paragraph[Adaptive Proportion Test][Compliant to SP800-90B @sp80090b section
4.4.2 the ESDM implements the Adaptive Proportion Test (APT). Considering that
the entropy is present in the least significant bits of the time stamp, the
APT is applied only to those least significant bits. The APT is applied to the
four least significant bits.]

The APT is calculated over a window size of 512 time stamps. The cut-off value
depends on the assumed entropy of $1 \/ "OSR"$ bits per time stamp: by
assuming that each time stamp has (at least) one bit of entropy and the
APT-input data is non-binary, the cut-off value
C = 325 as defined in SP800-90B section 4.4.2 (355 for a permanent failure);
with the default oversampling rate of 3 of the kernel module it is 459 (479
for a permanent failure).

This test is only applied and enforced in FIPS mode (for the eBPF entropy
sources also with the NTG.1 seeding strategy).

#paragraph[Runtime Health Test Failures][If either the RCT, or the APT health
test fails irrespective whether during initialization or runtime, the
following actions occur:]

+ The entropy collected by the entropy source is invalidated.

+ The SP800-90B startup health test are initiated with all implications
  discussed in section @sec:health-tests. That implies that from that point
  on, new events must be observed and its entropy must be collected before
  data is provided by the entropy source.

#par(first-line-indent: 0pt)[On a permanent failure, the kernel module panics
the kernel if the module parameter `esdm_panic_on_permanent_health_failure`
is set. An eBPF entropy source is not credited with entropy any more after a
permanent failure until it is reset, and its self test fails.]

#paragraph[SP800-90B Startup Tests][The aforementioned health tests are
applied to the first 1,024 time stamps obtained from the events of the
entropy source. In case
one error is identified for either the RCT, or the APT, the collected entropy
is invalidated and the SP800-90B startup health test is restarted.]

As long as the SP800-90B startup health test is not completed, the entropy
source does not deliver data. As all ESDM random number output interfaces only
generate data once the ESDM is operational, i.e. its initial DRNG is fully
seeded (section @sec:seed-levels), none of them provides random numbers
before the DRNG was seeded from entropy sources that completed their
SP800-90B startup test or from other entropy sources.

To summarize, the following rules apply:

- SP800-90B compliant output interfaces

  - `/dev/random`
  - `/dev/urandom`
  - `getrandom(2)` system call irrespective of `GRND_INSECURE`
  - `esdm_get_random_bytes_full` API call
  - `esdm_get_random_bytes_pr` API call
  - `esdm_get_random_bytes` API call

- SP800-90B non-compliant output interfaces

  - the fallback of the CUSE daemons and of `libesdm-getrandom.so` to the
    kernel RNG while the ESDM server cannot be reached or refuses a request,
    for `/dev/urandom` and `GRND_INSECURE` also while the ESDM is not
    operational
  - `libesdm-getrandom.so` in PID 1 and in a process running the ESDM
    itself, which always use the kernel RNG

== eBPF-based Entropy Sources - ESDM-internal Entropy Sources <sec:ebpf>

The eBPF-based scheduler and interrupt entropy sources (meson options
`es_sched_ebpf` and `es_irq_ebpf`, disabled per default) collect the event
timing of the scheduler and the interrupt entropy sources on a Linux kernel
without kernel patches. They require libbpf 1.2 or later, and at runtime a
kernel with BTF information (`/sys/kernel/btf/vmlinux`) and a high-resolution
clock - otherwise the entropy source is disabled. A kernel on which the
collected raw samples could not be erased again makes the ESDM refuse to
start. The eBPF programs are loaded
during the privileged initialization of the ESDM server, which requires root
or the capabilities `CAP_BPF` and `CAP_PERFMON`. Figure @fig:ebpf illustrates
their processing.

#figure(
  image("../figures/ebpf-processing.svg", width: 100%),
  caption: [eBPF Entropy Source Processing],
) <fig:ebpf>

+ The eBPF programs are attached to the `tp_btf/sched_switch` and the
  `tp_btf/irq_handler_entry` tracepoints. They obtain the time stamp of the
  event, divide it by the GCD of the time source and apply the health tests of
  section @sec:health-tests to it.

+ The difference of the time stamp to the one of the preceding event of the
  same CPU is collected in a per-CPU batch of 64 deltas, which is handed to a
  BPF ring buffer when it is full, or when no delta was collected for 250 ms.

+ The ESDM server reads the batches from the ring buffer and inserts them
  into the XDRBG-256 conditioning pool of the entropy source as specified in
  section @sec:dp-ebpf. It stops reading once that pool holds all the entropy
  one output block can carry; batches arriving at a full ring buffer are
  dropped.

+ An extraction reseeds the XDRBG-256 with the inserted deltas and generates
  the output block.

#par(first-line-indent: 0pt)[The entropy rate of the meson options
`es_sched_ebpf_entropy_rate` and `es_irq_ebpf_entropy_rate` (0 per default)
is applied to the 64 bits of each delta and capped at $1 \/ "OSR"$ bits per
event with the oversampling rate of the meson options `es_sched_ebpf_osr` and
`es_irq_ebpf_osr` (1 per default), which also determines the cut-off values
of the health tests. The rates are to be determined with the measurement
tooling in `tests/es_ebpf_testing` before crediting the entropy sources. Of
these and the interrupt and scheduler entropy sources of the kernel module, at
most one is credited with entropy: the build refuses more than one non-zero
entropy rate, and a non-zero rate set at runtime zeroes the others. When
the entropy sources are unloaded, every collected raw sample is zeroized - the
per-CPU state of the eBPF programs and the ring buffer included.]

== Auxiliary Entropy Pool - ESDM-external Entropy Sources <sec:aux>

The ESDM also supports obtaining entropy from the following data sources and
entropy sources that are external to the ESDM. The data is injected into the
auxiliary pool.

During the reseeding operation of the DRNG, any user-space entropy provider
waiting via select(2) or poll(2) for /dev/random to become writable, or with
the function `esdm_aux_timedwait_for_need_entropy` of `libesdm_aux_client` for
a semaphore of the status shared memory segment of the ESDM server, is
triggered to provide data if the auxiliary pool holds less entropy than the
write wakeup threshold (`write_wakeup_threshold`, per default the entropy all
auxiliary pools can hold). This
data is mixed into the auxiliary pool. This approach shall ensure that the
ESDM-external entropy sources may provide entropy at least once each DRNG
reseed operation.

=== Injecting Data From User Space <sec:aux-injecting>

User space can take the following actions to inject data into the DRNG:

- When writing data into /dev/random or /dev/urandom, or using the respective
  RPC (`esdm_rpcc_write_data`) or EGD interfaces, the data is added to the
  auxiliary pool. The ESDM assumes it has zero bits of entropy.

- When using the privileged IOCTL of `RNDADDENTROPY` with /dev/random, or the
  privileged RPC API call `esdm_rpcc_rnd_add_entropy`, the
  caller can inject entropic data into the auxiliary pool and define the
  amount of entropy associated with that data. The write command of the EGD
  protocol carries an entropy claim as well, which is only honored for a
  caller with the user ID 0.

=== Auxiliary Pool <sec:aux-pool>

The auxiliary pool is maintained as a separate entropy source that eventually
is concatenated with all other entropy sources in compliance with SP800-90C.

The auxiliary pool is an XDRBG-256 as specified in section @sec:dp-aux whose
SHAKE256 is provided by the crypto backend. It is processed as follows:

+ Data is inserted by absorbing it into the SHAKE256 context of the pool: it
  becomes part of the seed of the next reseed of the XDRBG.

+ When entropy is to be extracted from the auxiliary pool, the XDRBG is
  reseeded - or instantiated with the first extraction - with the inserted
  data, and the output is generated together with the new state of the pool,
  with which the SHAKE256 context is started again for the next insertions.

+ The output is generated with the amount of data requested
  by the DRNG (e.g. either 256 or 384 bits) and returned to the caller. Note,
  the auxiliary pool output is not truncated to the amount of entropy the data
  contains because the entropy provider may add data to the auxiliary pool
  without entropy, e.g. by simply writing to /dev/random. Thus, it may be
  possible that the auxiliary pool contains zero bits of entropy but yet
  contains data that should be used to “stir” the DRNG state.

#par(first-line-indent: 0pt)[Figure @fig:aux-pool illustrates the auxiliary
pool operation for the case when user space inserts three separate buffers.]

#figure(
  image("../figures/aux-pool-processing.svg", width: 62%),
  caption: [Auxiliary Pool Processing],
) <fig:aux-pool>

In addition, the ESDM maintains an entropy estimator for the auxiliary pool
counting the received entropy. The entropy estimator is capped to a maximum
of the size of the state of the XDRBG, 512 bits, as the pool cannot maintain
more entropy. With the SP800-90C oversampling in effect, the entropy estimator
credits 64 bits less than the pool holds unless the meson option
`aux-has-full-entropy` is enabled. With several auxiliary pools (meson option
`num-aux-pools`, 1 per default), the data of one extraction is taken from one
pool, the first one holding the requested entropy, else the one holding the
most entropy. Data with entropy is inserted into one pool as well, the first
one with room for its entropy, else the one with the most room, data without
entropy into all of them.

The output of the auxiliary pool is copied into the seed buffer when
generating random numbers to seed the DRNG. As the output never reveals the
state of the pool, the seed buffer is not mixed back into the auxiliary pool.
The extraction operation is atomic with respect to the auxiliary pool. This
implies that it will always be fully completed before the next operation can
commence. This ensures that the same auxiliary pool state can only be used
once for a given seeding operation.

The entropy estimator is decreased by the amount of entropy read from the
pool. If the SHAKE256 fails during an operation, the state of the pool is
discarded and its entropy estimator set to zero.

During the initialization of the ESDM, the current time together with data of
the CPU entropy source, and a machine-specific personalization string if one
is available, are inserted into the auxiliary pool without being credited
with entropy (`esdm_es_mgr_initialize`).

== Jitter RNG - ESDM-external Entropy Source <sec:jent>

The Jitter RNG is treated as an external entropy source which is requested for
random bits at the time the DRNG shall be seeded. No data is collected ahead
of the request.

The ESDM allocates the number of Jitter RNG collectors of the meson option
`es_jent_instances` or the option `--es_jent_instances` of the ESDM server (1
to 64; per default 4 in a build with the meson option `sp80090c`, `fips140` or
`ais2031_drg4` without `ais2031_drg3`, 1 otherwise), each with a lock of its
own, so that the seedings of several DRNG instances collect side by side. The
Jitter RNG is allocated with the oversampling rate of the meson option
`es_jent_osr` (3 per default). With a Jitter RNG of version 3.7.0 or later,
its memory size and its hash loop count can be adjusted with the meson options
`es_jent_max_mem` and `es_jent_hash_loop_count`. With the meson option
`es_jent_ntg1` and a Jitter RNG of version 3.7.0 or later providing secure
memory, the Jitter RNG is operated in its own NTG.1 mode (`JENT_NTG1`): it is
then an NTG.1 conformant RNG by itself. While a collector fails, the Jitter
RNG is not credited with entropy.

=== Entropy of CPU Jitter RNG Entropy Source <sec:jent-entropy>

The CPU Jitter RNG entropy source is credited with one bit of entropy per
generated data bit per default.

The entropy value can be altered by changing the meson configuration option of
`es_jent_entropy_rate`.

=== Kernel Jitter RNG Entropy Source <sec:jent-kernel>

The ESDM can read the Jitter RNG of the Linux kernel crypto API via the
`libkcapi` library (meson option `es_jent_kernel`, disabled per default). The
kernel crypto API RNG is named with the meson option `es_jent_kernel_name`
(`jitterentropy_rng` per default) or at runtime with the option
`--es_jent_kernel_name` of the ESDM server, e.g. for a jitterentropy kernel
module registering its RNG under another name. The entropy rate is defined
with the meson option `es_jent_kernel_entropy_rate` (256 per default).

== CPU-base Entropy Source - ESDM-external Entropy Source <sec:cpu>

The CPU-based entropy source is treated as an external entropy source which is
requested for random bits at the time the DRNG shall be seeded. Depending on
the underlying CPU, only one such source is available like RDSEED on Intel x86
(or RDRAND if RDSEED is not available), the POWER CPU DARN instruction, the
seed CSR of RISC-V, the PRNO TRNG function of IBM Z or the RNDRRS register of
ARMv8.

Depending whether the CPU entropy source is documented to full entropy,
expressed by its data multiplier,
the following data collection methods are applied. This approach is
orthogonal to the amount of entropy the ESDM awards to the CPU entropy source.

- CPU entropy source provides full entropy: The CPU entropy source is queried
  for the amount of data which is stored in the temporary seed buffer.

- CPU entropy source provides less than full entropy: For this entropy source,
  the ESDM contains the information about how much data must be fetched from
  the CPU entropy source to get full entropy - 2,048 times the requested data
  for RDRAND, twice the requested data for DARN and the seed CSR of RISC-V. The
  required amount of data is
  pulled from the CPU entropy source and conditioned with the hash currently
  in use by the ESDM. The calculated message digest is truncated to the
  requested amount of data which is stored in the temporary seed buffer.

=== Entropy of CPU Entropy Source <sec:cpu-entropy>

The entropy source of the CPU is assumed to have one 32th of the generated
data size – 8 bits of entropy. The reason for that conservative estimate is
that the design and implementation of those entropy sources is not commonly
known and reviewable. The entropy value can be altered by changing the meson
configuration option of `es_cpu_entropy_rate`.

== Kernel RNG Entropy Source - ESDM-external Entropy Source <sec:krng>

The ESDM offers the use of the kernel RNG as an entropy source. The kernel RNG
derives its entropy from sampling of interrupts.

The legacy RNG is queried for random numbers using the `getrandom(2)` system
call with the flag `GRND_NONBLOCK`.

=== Entropy of Kernel RNG Entropy Source <sec:krng-entropy>

When the kernel RNG is enabled, the ESDM applies the entropy rate defined at
compile time with `es_kernel_entropy_rate` (128 per default) which is a value
between 0 and 256 bits of entropy when 256 data bits are pulled from the
legacy RNG.

If the SP800-90C oversampling is in effect, the kernel RNG entropy source's
entropy rate is set to zero. The
reason is that the legacy RNG is known to not comply with FIPS 140 rules like
SP800-90B and thus must be assumed to provide no entropy. The same applies
while the scheduler entropy source of the kernel module is credited with
entropy, because interrupts may trigger scheduling events, and after a self
test of the entropy source found a repeated output.

When the interrupt entropy source of the kernel module is present, the kernel
entropy source entropy rate is set to `ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY` (4)
bits of entropy. This is due to the fact that the presence of IRQ entropy
source takes away the kernel RNG's main entropy source. Yet, some other
entropy sources are present which may or may not deliver entropy. Thus a safe
entropy value is applied by the ESDM. While the eBPF-based interrupt entropy
source is credited, an entropy rate of the kernel RNG entropy source set at
runtime is capped to the same value.

== Linux HWRAND Entropy Source - ESDM-external Entropy Source <sec:hwrand>

The ESDM reads the Linux hardware random number generator framework via
`/dev/hwrng` (meson option `es_hwrand`, enabled per default), which provides
the data of the hardware RNG selected by the kernel, e.g. a TPM or a
virtio-rng device. The device is read by a thread of its own with a deadline
of 2 seconds, so that a stalled device does not stall the seeding. A device
failing a read is not credited with entropy and is not read by the seedings
any more; the ES monitor probes it at most every 10 seconds until it delivers
again. The entropy rate is defined with the meson option
`es_hwrand_entropy_rate` (0 per default). With an entropy rate of zero, the
data is only part of the additional input of the DRNG, and the device is
skipped when it is busy with another seeding.

== TPM 2.0 Entropy Source - ESDM-external Entropy Source <sec:tpm2>

The ESDM obtains random numbers from a TPM 2.0 with the `TPM2_GetRandom`
command sent to the TPM resource manager device of the meson option
`es_tpm2_rm_path` (`/dev/tpmrm0` per default) without using a TSS library
(meson option `es_tpm2`, enabled per default). With the meson option
`es_tpm2_stir`, a `TPM2_StirRandom` command with the current time precedes
each request. A device absent at initialization leaves the entropy source
disabled. The device is read with the same deadline and failure handling as
the HWRAND entropy source. The self test requires two reads of the TPM to
differ. The entropy rate is defined with the meson option
`es_tpm2_entropy_rate` (0 per default).

== External Entropy Source - ESDM-external Entropy Source <sec:ext-es>

Noise sources that are not part of the ESDM are served to the ESDM server by
a provider: a process of its own the server reads from over a Unix domain
socket of the type `SOCK_SEQPACKET` - the ExternalSocket entropy source (meson
option `es_ext`, enabled per default). The provider creates the socket, whose
path is configured with the option `--es_ext` of the ESDM server or the meson
option `es_ext_path`; without a path, the entropy source is inactive. The ESDM
loads no code of an external entropy source into its own process: the
provider keeps its own privileges, address space and life cycle. The ESDM
server accepts the provider only if it runs as root, or as the user given with
`--es_ext_uid` (meson option `es_ext_peer_uid`), as reported by `SO_PEERCRED`,
and connects to it again after a failure at most every 5 seconds.

The messages are encoded with protobuf (`es-ext/pb/es_ext.proto`), one message
per datagram, with the requests INFO, SELFTEST, STATUS and GET_ENTROPY. On
every connection, the ESDM asks for INFO and a passing self test before it
requests entropy. A provider is written against `esdm_es_ext.h` of
`libesdm_es_ext`: the callbacks of the entropy source as a
`struct esdm_es_ext_plugin` - an `init`, `fini`, `get_entropy`, `selftest`,
`status_json` and `entropy_rate` callback - and a `main()` handing them to
`esdm_es_ext_provider_main()`, which takes the command line of a provider
program and serves the callbacks one at a time on the socket.
`esdm-es-pkcs11` (meson option `es_pkcs11`) reads the random number generator
of a PKCS\#11 token with `C_GenerateRandom`, `esdm-es-pcsc` (meson option
`es_pcsc`) the one of a smart card with the `GET CHALLENGE` command over
PC/SC; `es-ext/example` holds a further example.

A block is credited with the entropy the provider claims for it, capped by
the entropy rate of the entropy source: the one configured with the meson
option `es_ext_entropy_rate` or the option `--es_ext_entropy_rate` of the
ESDM server, else the one the provider declares in its answer to INFO, else
0. A provider claiming more entropy than the block holds breaks the protocol
and is disconnected. A provider failing a read is not credited with entropy
until it delivers again, one failing its self test until a self test passes.
The ESDM shows the status a provider reports in its answer to STATUS as part
of its own status; the ES monitor asks for it in every round, and a provider
not answering within 500 ms is disconnected and not asked again for a minute.

== DRNG Seeding Operation <sec:seeding>

The seeding operation obtains random data from all available entropy sources.

The (re)seeding logic tries to obtain 256 bits of entropy from the entropy
sources. However, if less entropy can only be delivered, the entropy sources
are only read if at least 256 bits of entropy collectively from all entropy
sources are available, unless the reseed is forced or the ESDM is not yet fully
seeded - otherwise, the DRNG is reseeded with the time stamp below only.

For efficiency reasons, the seeding operation uses a seed buffer depicted in
figure @fig:big-picture that is the following set of blocks of 256 bits each.
With the SP800-90C oversampling in effect, the initial seeding of the DRNG is
seeded with a seed buffer that pulls 384 bits in the following blocks. Each
block is dedicated to an entropy source. As each entropy source can be disabled at
compile time, the different bullets in the following list only applies if the
corresponding entropy source is enabled. The blocks are filled in the order of
section @sec:components, in parallel threads with the meson option
`es_parallel_fetch`:

+ The blocks of the interrupt and scheduler entropy sources of the kernel
  module are filled with the output of their DRBG as depicted in figure
  @fig:collection-pool. A block receives data from the DRBG only if as much
  entropy can be pulled from the per-CPU rings as the block holds. In the
  worst case when no new events are received, no data is delivered.

+ The blocks of the eBPF entropy sources are filled with the output of their
  XDRBG-256 conditioning pools.

+ The blocks of the fast entropy sources - the Jitter RNG, the CPU, the kernel
  RNG, the HWRAND, the TPM 2.0, the kernel Jitter RNG and the external entropy
  source - are filled with the data obtained from them at the time of the
  request.

+ Finally, a block is filled with the output of the auxiliary pool.

#par(first-line-indent: 0pt)[Finally, also a time stamp (`struct timespec` of
`CLOCK_MONOTONIC`) indicating the
time of the request is mixed into the DRNG. That time stamp, however, is not
assumed to have entropy and is only there to further stir the state of the
DRNG.]

The filled seed buffer is handed to the DRNG as a seed string, together with
the additional input buffer holding the data of the entropy sources configured
with an entropy rate of zero as specified in section @sec:dp-seed-buffer.

=== DRNG May Become Not Fully Seeded <sec:not-fully-seeded>

The ESDM maintains a counter for each DRNG instance how many generate
operation are performed without performing a reseed that has full entropy. If
this counter reaches the threshold of $2^30$ generate operations, or the
number of bits generated reaches the threshold of the meson option
`drng_max_reseed_bits`, i.e. the
DRNG did not receive a seed with full entropy for that many generate
operations, the DRNG is set to not fully seeded. This setting implies that the
DRNG instance will not be used any more for generating random numbers until
the ESDM received sufficient entropy to reseed the DRNG with full entropy. A
per-CPU DRNG instance that reached the threshold of `drng_max_reseed_bits`
remains fully seeded while the reseed worker is active, but does not serve
any request until the reseed worker reseeded it; the requests are served by
another DRNG instance meanwhile. The initial DRNG instance stops serving
requests at the threshold of `drng_reseed_threshold_bits` already, which
leaves the remaining output for its reseed.

If the DRNG that becomes not fully seeded is the initial DRNG instance that
was seeded during boot time as outlined in section @sec:seed-levels, the
entire ESDM is marked as not operational. This setting blocks all blocking
interfaces just like during boot time when the ESDM is not yet fully seeded.

The ESDM automatically tries to recover from it when it received sufficient
entropy.

== Cryptographic Primitives Used By ESDM <sec:crypto>

The following subsections explain the cryptographic primitives that may be
used by the ESDM.

=== Crypto Backends <sec:backends>

The ESDM obtains its cryptographic primitives - the DRNG, the conditioning
hash and the SHAKE256 of the XDRBG-256 pools - from the crypto backend
selected with the meson option `crypto_backend` as listed in table
@tab:backends. The glue code is found in `esdm/esdm_*.c` and
`esdm/esdm_botan.cpp`, the builtin primitives in `crypto`.

#figure(
  {
    set par(justify: false, first-line-indent: 0pt)
    set text(size: 9pt)
    show table.cell: set align(left + top)
    table(
      columns: (auto, 1fr, auto, auto),
      table.header(
        [Backend], [DRNG], [Hash], [SHAKE256],
        table.hline(stroke: 0.8pt),
      ),
      [builtin (default)],
      [SP800-90A Hash DRBG with SHA-512 (`drng_hash_drbg`, default) or
        ChaCha20 DRNG (`drng_chacha20`)],
      [SHA-512 (`hash_sha512`) or \ SHA3-512 (`hash_sha3_512`)],
      [builtin],
      [OpenSSL 3.0 \ or later],
      [SP800-90A Hash DRBG with SHA-512 (default), CTR DRBG with AES-256 or
        HMAC DRBG with SHA-512 (`openssl_drng_type`)],
      [SHA3-512], [OpenSSL],
      [Botan 3.2 \ or later],
      [SP800-90A HMAC DRBG with SHA-512 (default) or ChaCha20 RNG, with fast
        key erasure with Botan 3.14 or later (`botan_drng_type`)],
      [SHA3-512], [Botan],
      [GnuTLS 3.6.7 \ or later],
      [SP800-90A CTR DRBG with AES-256 and the Block_Cipher_df derivation
        function added by the ESDM],
      [SHA-512], [nettle 3.6 \ or later],
      [leancrypto 1.6 \ or later],
      [XDRBG-256 with SHAKE256],
      [SHA3-512], [leancrypto],
    )
  },
  caption: [ESDM Crypto Backends],
) <tab:backends>

The backends based on libraries allow using assembler or even
hardware-accelerator backed cipher primitives. Such support
should relieve the CPU from processing the cryptographic operation as much as
possible.

=== DRBG <sec:drbg>

If the SP800-90A DRBG implementation is used, the default DRBG used by the
ESDM is the builtin Hash DRBG with SHA-512 (`crypto/hash_drbg.c`). Other DRBG
types are provided by the crypto backends listed in section @sec:backends.

All DRNGs are always instantiated with the same DRNG type.

The input with the seed and re-seed of the DRBG has been explained above and
does not need to be re-iterated here. Mathematically speaking, the seed and
re-seed data obtained from the entropy sources and the ESDM external sources
are mixed into the DRBG using the DRBG instantiate and reseed functions as
defined by SP800-90A, the data of the entropy sources configured with an
entropy rate of zero as additional input.

The DRBG generates output with the DRBG “generate” function that is specified
in SP800-90A. The DRBG used to generate two types of output that are
discussed in the following subsections.

#paragraph[/dev/urandom and `esdm_get_random_bytes`][Users that want to obtain
data via the /dev/urandom interface or the `esdm_get_random_bytes` API are
delivered data that is obtained from the DRNG “generate” function. I.e. the
DRNG generates the requested random numbers on demand.]

Data requests on either interface is segmented into blocks of maximum 4096
bytes, or $2^16$ bytes in a build limiting the output without a full reseed.
For each block, the DRNG “generate” function is invoked individually.
According to SP800-90A, the maximum numbers of bytes per DRBG “generate”
request is $2^19$ bits or $2^16$ bytes which is not exceeded by the ESDM.

In addition to the slicing of the requests into blocks, the ESDM maintains a
counter for the number of DRNG “generate” requests since the last reseed.
According to SP800-90A, the number of allowed requests before a forceful
reseed is $2^48$ – a number that is very high. The ESDM uses a much more
conservative threshold of $2^20$ requests as a maximum. When that threshold
is reached, the DRBG will be reseeded by using the operation documented in
section @sec:seeding before the next DRNG “generate” operation commences - a
per-CPU DRNG instance is reseeded by the reseed worker instead while it
continues to generate.

The handling of the reseed threshold as well as the capping of the amount of
random numbers generated with one DRNG “generate” operation ensures that the
DRNG is operated compliant to all constraints in SP800-90A.

#paragraph[/dev/random and `esdm_get_random_bytes_full`][The random numbers to
be generated for /dev/random as well as `esdm_get_random_bytes_full` are
defined to have a special property: it only provides data once the ESDM is
fully seeded as outlined in section @sec:seed-levels. In addition, the ESDM
must be fully initialized before random numbers are generated, including the
completion of the SP800-90B health test if entropy from internal entropy
sources is gathered.]

=== ChaCha20 DRNG <sec:chacha20>

If the SP800-90A DRBG is not desired, the ESDM can use a standalone C
implementations for ChaCha20 to provide a DRNG (meson option `drng_chacha20`
of the builtin crypto backend).

The ChaCha20 DRNG is implemented with the components discussed in the
following section. All of those components rest on a state defined by
@rfc7539, section 2.3.

The operation of the ChaCha20 DRNG can be characterized with figure
@fig:chacha20. This figure outlines the initialization of the DRNG, its
seeding using the state update operation and the invocation of one generate
operation that is requested to obtain more than 512 bits of data.

#figure(
  image("../figures/chacha20-drng.svg", width: 90%),
  caption: [ChaCha20 DRNG Operation],
) <fig:chacha20>

#paragraph[State Update Function][The state update function's purpose is to
update the state of the ChaCha20 DRNG - the implementation is provided with
the function `esdm_cc20_drng_update` in `crypto/chacha20_drng.c`. That is
achieved by]

+ XOR the key-sized part of the last output block of the generate operation
  that was not handed out with the key part of the ChaCha20 state, or,
+ if less than a key-sized part of it is left or no output block was
  generated, generating one output block of ChaCha20 and XOR its first
  key-sized part with the key part of the ChaCha20 state.

#par(first-line-indent: 0pt)[In addition, the nonce part of the state is
incremented by one to ensure the uniqueness requirement of @rfc7539 chapter
4.]

#paragraph[Seeding Operation][The seeding operation processes a seed of
arbitrary lengths. The seed is segmented into ChaCha20 key size chunks which
are sequentially processed by the following steps:]

+ The key-size seed chunk is XORed into the ChaCha20 key location of the
  state.
+ This operation is followed by invoking the state update function with a
  fresh output block.
+ Repeat the previous steps for all unprocessed key-sized seed chunks.

#par(first-line-indent: 0pt)[If the last seed chunk is smaller than the
ChaCha20 key size, only the available bytes of the seed are XORed into the key
location. This is logically equivalent to padding the right side of the seed
with zeroes until that block is equal in size to the ChaCha20 key. The
additional input is processed the same way after the seed.]

The invocation of the state update function is intended to eliminate any
potentially existing dependencies between the seed chunks.

#paragraph[Generate Operation][The random numbers from the ChaCha20 DRNG are
the data stream produced by ChaCha20, i.e. without the final XOR of the data
stream with plaintext. Thus, the DRNG generate function simply invokes the
ChaCha20 to produce the data stream as often as needed to produce the
requested number of random bytes.]

After the conclusion of the generate operation, the state update function is
invoked to ensure enhanced backward secrecy of the ChaCha20 state that was
used to generate the random numbers.

=== XDRBG-256 <sec:xdrbg>

The auxiliary pool and the conditioning pools of the eBPF entropy sources are
each an XDRBG-256 - the XDRBG over SHAKE256 with a state of 512 bits as
specified in section @sec:dp-aux. The implementation is provided with
`esdm/crypto/esdm_xdrbg.c`, the SHAKE256 is that of the crypto backend
(`struct esdm_xof_cb`). The kernel module `esdm_es` compiles the same
implementation over the SHAKE256 of the kernel, where the kernel provides it
(`CONFIG_CRYPTO_LIB_SHA3`), to post-process the time stamps of its entropy
sources. The additional input $alpha$ of at most 84 bytes
separates the different pools. One generate step produces at most 344 bytes;
a longer output is generated in several steps, each one with the state the
previous one left.

== ESDM External Interfaces <sec:interfaces>

The following ESDM interfaces are provided:

- ESDM library API: The API is documented in ‘esdm.h‘.

- ESDM server RPC API: The RPC API is documented in ‘esdm\_rpc\_client.h‘, see
  section @sec:rpc.

- EGD interface: See section @sec:egd.

- /dev/random and /dev/urandom device files: See the Linux man page
  `random(4)`. In addition, when opening the /dev/random or the /dev/urandom
  device of the CUSE daemons with the
  `O_SYNC` flag, the DRNG is managed with prediction resistance enabled. When
  using either device with `O_SYNC`, the ESDM API call of
  `esdm_get_random_bytes_pr` is used to service the request. Therefore all
  considerations outlined for this API apply to both devices with `O_SYNC` as
  well. If the ESDM server cannot be reached or answers with an error - for
  /dev/urandom also while the ESDM is not yet operational -, the CUSE daemons
  serve the request from the device file of the kernel. The privileged IOCTLs
  require the capability `CAP_SYS_ADMIN` of the caller.

- /proc/sys/kernel/random/\* interfaces: See the Linux man page random(4) and
  the description of `esdm-proc` in chapter @sec:design.

- getrandom and getentropy APIs: See Linux man pages `getrandom(2)` and
  `getentropy(3)`. The flags of `getrandom(2)` select the ESDM API call
  servicing the request:

  - `GRND_INSECURE`: `esdm_get_random_bytes`,
  - `GRND_RANDOM`: `esdm_get_random_bytes_pr`,
  - `GRND_SEED` (0x0010, a flag of the ESDM): `esdm_get_seed` to obtain the
    data of the entropy sources directly, where the ESDM flag
    `GRND_FULLY_SEEDED` (0x0020) indicates that the DRNG of the caller is
    already fully seeded,
  - otherwise: `esdm_get_random_bytes_full`.

  With `GRND_NONBLOCK`, the non-blocking variants of these calls are used.
  If the ESDM server cannot be reached or answers with an error - e.g. for
  `GRND_INSECURE` while the ESDM is not yet operational -, the `getrandom`
  system call of the kernel serves the request; a `GRND_SEED` request fails
  instead.

- OpenSSL RAND providers (meson option `openssl-rand-provider`):
  `libesdm-rng-provider.so` serves the RAND algorithms of OpenSSL from the
  ESDM over the RPC interface and honors the prediction resistance flag of
  OpenSSL with `esdm_get_random_bytes_pr`, `libesdm-rng-provider-pr.so`
  serves all requests with it, `libesdm-seed-src-provider.so` provides the
  ESDM as seed source. `libesdm-egd-provider.so` and
  `libesdm-egd-provider-pr.so` obtain the data over the EGD interface: the
  former from the socket `esdm-egd.socket`, refusing requests asking for
  prediction resistance, the latter from the socket `esdm-egd-pr.socket`.

- Kernel character devices of the kernel module `esdm_cdev`:
  `/dev/esdm_random` is served like `esdm_get_random_bytes_full`, waiting
  until the ESDM is operational, `/dev/esdm_urandom` like
  `esdm_get_random_bytes`; opened with `O_SYNC`, either one is served from
  the prediction resistance DRNG. `/proc/esdm` offers the files
  `entropy_avail`, `poolsize`, `write_wakeup_threshold`,
  `urandom_min_reseed_secs`, `status` and `status.json`. The module supports
  the IOCTLs of the random devices of the kernel. While the ESDM cannot be
  reached, nothing is served from elsewhere: the requests wait or fail.

- External entropy sources: the ESDM server reads the providers of external
  entropy sources over a Unix domain socket, see section @sec:ext-es.

- Status: See section @sec:status.

=== RPC Interface <sec:rpc>

The ESDM server provides two RPC interfaces on Unix domain sockets of the type
`SOCK_SEQPACKET`: the unprivileged one on `esdm-rpc-unpriv.socket`, which
everybody may access, and the privileged one on `esdm-rpc-priv.socket`, which
is only accessible by root and whose operations are only executed for a caller
with the user ID 0 as reported by `SO_PEERCRED`. The messages are encoded with
protobuf-c behind a header with the method index, the message length and a
request identifier (`service-rpc/service/esdm_rpc_protocol.h`), one message
per datagram.

- Unprivileged operations: obtaining random numbers (`RpcGetRandomBytes`,
  `RpcGetRandomBytesFull`, `RpcGetRandomBytesPr`), seed data (`RpcGetSeed`),
  writing data without entropy (`RpcWriteData`), the status (`RpcStatus`,
  `RpcStatusJson`, `RpcDrngStatusJson`, `RpcJentStatus`), the seeding state
  (`RpcIsFullySeeded`) and the entropy levels and settings of the Linux
  interfaces.

- Privileged operations: inserting entropy (`RpcRndAddEntropy`,
  `RpcRndAddToEntCnt`), clearing the entropy estimates (`RpcRndClearPool`),
  forcing a reseed (`RpcRndReseedCRNG`), changing the Linux interface settings,
  running the self tests (`RpcSelftest`) and, only in a build with the meson
  option `testmode` or of the build type `debug`, setting the entropy rates of
  the entropy sources (`RpcSetEsRate`).

#par(first-line-indent: 0pt)[The server never waits within a request: it
serves the random numbers with the non-blocking API calls, and the client
library waits and asks again. A prediction resistance request obtains at most
32 bytes; a caller with the user ID 0 that found the prediction resistance
DRNG busy has the next turn, the other callers are turned away for up to 3
seconds meanwhile. The privileged interface is served by one worker thread, the
unprivileged one by one worker thread per DRNG instance, each serving its
connections one request after the other in an event loop of its own
(`service-rpc/server/esdm_rpc_server.c`).]

=== EGD Interface <sec:egd>

The ESDM server optionally serves the protocol of the Entropy Gathering Daemon
on Unix domain sockets of the type `SOCK_STREAM`, accessible by all users:
`esdm-egd.socket`, enabled with the systemd socket unit
`esdm-server-egd.socket` or the option `--egd_socket` of the server
(`/run/esdm-egd.socket` per default, meson option
`esdm-server-egd-socket-path`), and `esdm-egd-pr.socket`, enabled with the
systemd socket unit `esdm-server-egd-pr.socket` or the option
`--egd_socket_pr` (`/run/esdm-egd-pr.socket` per default, meson option
`esdm-server-egd-pr-socket-path`). As the EGD protocol cannot ask for
prediction resistance per request, it is a property of the socket: the second
socket serves the reads of the EGD protocol from the prediction resistance
DRNG. Both sockets
offer the commands of the EGD protocol (`service-egd/esdm_egd_protocol.h`):

- 0x00: the available entropy in bits,
- 0x01: reading up to the requested number of bytes without blocking,
- 0x02: reading the requested number of bytes, blocking,
- 0x03: writing data with an entropy claim into the auxiliary pool - the
  claim is only honored for a caller with the user ID 0,
- 0x04: the PID of the server.

#par(first-line-indent: 0pt)[A transfer is limited to 255 bytes. The random
numbers are served from `esdm_get_random_bytes_full_noblock`, or
`esdm_get_random_bytes_pr_noblock` on the second socket; a blocking read is
completed by the event loop of the server, which never waits within a request.
What the EGD protocol cannot express, the ESDM offers with commands of its own,
0xe0 to 0xec: prediction resistant reads, a read with the semantics of
/dev/urandom (`esdm_get_random_bytes`), the state of the ESDM, the status as
text and as JSON document, reads and insertions of up to 64 KiB and, only for
a caller with the user ID 0 as reported by `SO_PEERCRED`, crediting entropy to
the auxiliary pool, clearing its entropy, reseeding the DRNGs, and setting
`write_wakeup_threshold` and `urandom_min_reseed_secs`.]

The client library `libesdm_egd_client` (`esdm_egd_client.h`) owns one
connection, serializes the requests on it and reconnects after a restart of
the server or a `fork()` of the caller. The OpenSSL providers
`libesdm-egd-provider.so` and `libesdm-egd-provider-pr.so` are based on it.
The kernel module `esdm_cdev` connects to `esdm-egd.socket` with a kernel
socket and uses the commands of the ESDM to serve `/dev/esdm_random`,
`/dev/esdm_urandom` and `/proc/esdm` together with the IOCTLs of the random
devices of the kernel.

=== ESDM Status <sec:status>

The ESDM keeps its status as JSON documents (`esdm/esdm_info.c`): the general
status (`esdm_status_json`) with the version of the library, the DRNG, the
security strength, the satisfied standards, the seeding state, the entropy
level, the state of every entropy source, the DRNG instances, the reseed
worker and the periodic self tests, and the state of a single DRNG instance
(`esdm_status_drng_json`, `esdm_status_drng_pr_json`). The text form of the
status (`esdm_status`) is rendered from the JSON document. A status that does
not fit into the buffer of the caller is answered with `-EMSGSIZE`. The status
is available via the RPC and the EGD interfaces, `esdm-tool --status` and the
files `/proc/sys/kernel/random/esdm_type` and `/proc/esdm/status`. The status
flags of the satisfied standards are “FIPS 140”, “DRG.3”, “DRG.4”,
“SP800-90C”, “NTG.1(2011)” and “NTG.1(2024)”.

The ESDM server also maintains a status shared memory segment with semaphores
that the CUSE daemons and `libesdm_aux_client` use to learn about the
operational state and the need for entropy without an RPC call.

== ESDM Self-Tests <sec:self-tests>

All cryptographic primitives are self-tested during the startup phase of the
ESDM with known-answer tests, each accompanied by negative tests - the
implementation is provided with `esdm/esdm_selftest.c`:

- the conditioning hash of the crypto backend,
- the XDRBG-256 together with its SHAKE256,
- the DRNG including a reseed.

#par(first-line-indent: 0pt)[In addition, every entropy source is asked to
test itself. The self tests are repeated every 600 seconds by a periodic
worker and can be triggered with the privileged `esdm_rpcc_selftest` RPC API
call or `esdm-tool --selftest`. No random numbers are generated and no seed
data is handed out while the
cryptographic self tests have not passed; a failure of them is final. An
entropy source failing its self test is logged and reported in the status,
and is not credited with entropy until a later self test passes.]

In FIPS mode, i.e. in a build with the meson option `fips140` if
`/proc/sys/crypto/fips_enabled` is set or the environment variable
`ESDM_SERVER_FORCE_FIPS` is present, a power-on self test is performed before
the ESDM starts (`esdm/fips.c`): an HMAC-SHA256 known-answer test and the
integrity test of the executable and of the ESDM library against the
reference value of the HMAC file next to each of them, which is created with
`esdm-tool --fips-targetfile` and `--fips-checkfile`. A missing reference
value is a failed integrity test.

== ESDM Test Interfaces <sec:test-interfaces>

When compiling the kernel module `esdm_es` with `BUILD_TESTING=1`, the
following interfaces are enabled for the entropy sources built into the module
allowing direct access to non-deterministic aspects. It is not advisable to
enable these interfaces for production systems. Yet, these interfaces are
considered to be protected against misuse by allowing only the root user to
access them. In addition, any data obtained through these interfaces is not
used by the ESDM to feed the entropy pool. Thus, even when leaving these
interfaces enabled on production systems, the impact on security is
considered to be limited. No data is provided while the debugfs is locked down
by the lockdown mode of the kernel.

- Interrupt Entropy Source:

  - The interface `/sys/kernel/debug/esdm_es/esdm_raw_hires` allows
    reading of the raw unconditioned noise data collected while the read
    operation is in progress by providing the time deltas of the events
    collected by the ESDM that otherwise are injected into the entropy pool.
    When loading the module with the module parameter
    `boot_raw_hires_test=1`, the time deltas of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_raw_hires` file after loading the module provides this data in this
    case.

  - The interface `/sys/kernel/debug/esdm_es/esdm_irq_perf` allows
    reading of the number of cycles used to process one interrupt event. This
    allows measuring the performance impact of the ESDM on the interrupt
    handler. When loading the module with the module parameter
    `boot_irq_perf=1`, the performance data of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_irq_perf` file after loading the module provides this data in this
    case.

- Scheduler Entropy Source:

  - The interface `/sys/kernel/debug/esdm_es/esdm_raw_sched_hires` allows
    reading of the raw unconditioned noise data collected while the read
    operation is in progress by providing the time deltas of the events
    collected by the ESDM that otherwise are injected into the entropy pool.
    When loading the module with the module parameter
    `boot_raw_sched_hires_test=1`, the time deltas of the first
    1,024 events recorded by the ESDM are stored. The first read of the
    `esdm_raw_sched_hires` file after loading the module provides this data in
    this case.

  - The interface `/sys/kernel/debug/esdm_es/esdm_sched_perf` allows
    reading of the number of cycles used to process one scheduler event. This
    allows measuring the performance impact of the ESDM on the scheduler. When
    loading the module with the module parameter
    `boot_sched_perf=1`, the performance data of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_sched_perf` file after loading the module provides this data in
    this case.

#par(first-line-indent: 0pt)[The helper tool `esdm-getrawentropy` is provided
to read the files and format the data for post-processing, `esdm-extractlsb`
converts the data into the input of the SP800-90B assessment tools (meson
option `validation-helpers`, `tests/validation-helpers`).]

For the eBPF entropy sources, the collector `esdm-ebpf-collect` together with
the scripts `analyze_non_iid.sh` and `analyze_restart.sh` in
`tests/es_ebpf_testing` (meson option `es_ebpf_testing`) obtains the raw time
deltas and performs the SP800-90B assessment including the restart test. The
collector refuses to run in FIPS mode, and the ESDM server itself never records
raw data.
