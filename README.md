# Entropy Source and DRNG Manager

** ... or /dev/random in user space **

![Build Status CI](https://github.com/smuellerDD/esdm/actions/workflows/test_ci.yml/badge.svg?branch=master)

The Entropy Source and DRNG Manager (ESDM) manages a set of deterministic
random number generators (DRNG) and ensures their proper seeding and reseeding.
To seed the DRNGs, a set of entropy sources are managed by the ESDM. The
cryptographic strength of the entire ESDM is always 256 bits. All entropy
processing is designed to maintain this strength.

Besides other services, it provides an API and ABI compliant drop-in
replacement for the Linux `/dev/random` and `/dev/urandom` devices as well
as the `getrandom` system call. This means it not only supports common
users requesting random numbers, but also services using the IOCTLs
documented in `random(4)` or using `select(2)` / `poll(2)` on the device files.

In addition to the Linux interface support, the ESDM provides a daemon managing
the entropy sources and DRNG instances that can be accessed with a wrapper
library. The ESDM requires only POSIX support along with `protobuf-c` and thus
is intended to be executable on different operating systems.

It is extensible as follows:

* Additional entropy sources can easily be added, existing entropy sources
  can be deselected during compile time or its entropy rate altered
  during startup time.

* The cryptographic primitives can be altered by simply providing a new
  backend for hash algorithms or DRNG algorithms. See the `drng_chacha20`
  configuration option replacing the SP800-90A DRBG with a ChaCha20-based
  DRNG, or the `hash_sha3_512` configuration option replacing the SHA2-512
  conditioning hash with SHA3-512.

* Different DRNG Seeding strategies can be defined, by modifying one location
  in the code that governs the initial and reseeding operation of the DRNGs.

The (re)seeding operation of the DRNG implements design ideas of the following
specifications:

* SP800-90B: The entropy source of the Jitter RNG provides an SP800-90B
  compliant entropy source. In addition, the Intel RDSEED instruction is
  claimed to provide an SP800-90B entropy source. Also, when using the
  scheduler-based entropy source - which is only implemented for the Linux
  kernel using the code in `addon/linux_esdm_es`, a separate SP800-90B
  entropy source is provided. In addition, when using the interrupt-based
  entropy source - which is only implemented for the Linux kernel using the
  code in `addon/linux_esdm_es`, a separate SP800-90B entropy source is
  provided. If the kernel-based jitter entropy source shall be used, please
  compile your Linux kernel with CONFIG_CRYPTO_JITTERENTROPY.

* SP800-90C: The specification provides guidelines how to combine a DRNG
  and entropy sources.

## Build

Use the Meson/Ninja build infrastructure with the following steps:

1. `meson setup build`

2. `meson compile -C build`

3. `meson install -C build`

### Dependencies

The following dependencies are required:

* protobuf-c: When enabling any code beyond the ESDM library, the protobuf-c
  support is needed. Either the package of your favorite distribution must be
  installed or obtain the sources from the
  [Protobuf-C Github website](https://github.com/protobuf-c/protobuf-c).

The following dependencies are required provided the respective functionality
is enabled during compile time:

* Jitter RNG: If the Jitter RNG entropy source is enabled as a compile time
  option, install the Jitter RNG library from your distribution or from the
  [Jitter RNG homepage](https://www.chronox.de/jent).

* kcapi library: If the kernel-based jitter source is enabled as a compile time
  option, the kcapi library is required, either from your distribution or from
  the
  [libkcapi website](http://www.chronox.de/libkcapi).

* SELinux library: If your system uses SELinux and you compile the CUSE device
  file support (compile time option), the SELinux library is needed for proper
  device file labeling. In this case, use the package from your distribution.

* FUSE 3 library: If the CUSE daemons shall be compiled and are enabled as a
  compile time option, the FUSE 3 library is required either from your
  distribution or from the
  [libfuse Github website](https://github.com/libfuse/libfuse/).

* Botan >= 3.0: If the Botan backend for cryptographic operations shall be used
  and is enabled as a compile time option get Botan either from your distribution
  or from the
  [botan Github website](https://github.com/randombit/botan).

* OpenSSL >= 3.0: If the OpenSSL backend for cryptographic operations shall be
  used and is enabled as a compile time option, or if the OpenSSL ESDM seed
  source shall be compiled when the compile time option is enabled, obtain OpenSSL either from your distribution or from the
  [OpenSSL website](https://www.openssl.org/source/).

* leancrypto: If the leancrypto backend for cryptographic operations shall be
  enabled during compile time, obtain leancrypto from the
  [leancrypto](https://leancrypto.org) website.

Beyond those dependencies, only POSIX support is required.

### Installing via the Arch User Repository

If you are using [Arch Linux](https://www.archlinux.org/) or any of
its derivatives, you can use your favorite
[AUR Helper](https://wiki.archlinux.org/index.php/AUR_helpers) and install:

| **Version** | **Maintainer** | **Package**  |
| :--------- | :------------- | :----------- |
| the latest changes in the default branch (master currently) | Piotr Górski   | [esdm-git](https://aur.archlinux.org/packages/esdm-git) <sup>AUR</sup> |

### Using ESDM in NixOS

If you are using [NixOS](https://nixos.org/), enable ESDM as follows:

```
services.esdm.enable = true;
```

Please consult the current NixOS module for more finegrained settings.
At the time of writing this, it was located in:

```nix
nixpkgs/nixos/modules/services/security/esdm.nix
```

If you'd like to use the ESDM kernel seeder, /dev/(u)random and proc handler
enable:

```nix
services.esdm.enableLinuxCompatServices = true;
```

### Building an RPM

The ESDM code distribution contains an RPM SPEC file which can be used to
generate RPMs from it. This SPEC file is tested using the [OpenSUSE Build Service](https://build.opensuse.org/project/show/home:smuellerDD).

### Using ESDM from Rust

A small helper crate for ESDM usage together with Rust's rand crate can
be obtained from [ESDM Crate](https://crates.io/crates/rand-esdm).
Please find current usage instructions in the crate's documentation.

### Configuration

The ESDM build system supports various configuration options which are
listed and documented when invoking `meson configure build`.

The options can be altered with `meson configure build -D<option>=<value>`
where `<value>` is either `enabled` or `disabled`, or `true` or `false` as
documented.

Besides different entropy sources, multiple cryptographic backends can be
configured. Please note, that backends based on libraries like OpenSSL or
Botan typically provide higher DRBG performance than the builtin backend.

### Scheduler-based Entropy Source

The ESDM provides a new, currently unique entropy source: the scheduler-based
entropy source. It requires additional kernel support which is provided
in the directory `addon/linux_esdm_es/`. Please see the `README.md` there
how to enable the support in the kernel.

In any case, it is harmless to enable the ESDM user space support for the
scheduler entropy source. It will try to find the kernel interface of the
aforementioned extension. If it does not find it, it will print a message
during the startup of the `esdm-server` and then deactivate itself.

### eBPF-based Scheduler and Interrupt Entropy Sources

As an alternative to the kernel-patch based scheduler and interrupt entropy
sources above, the ESDM provides eBPF-based variants (`es_sched_ebpf` and
`es_irq_ebpf`) that collect the same event timing on a stock Linux kernel:
eBPF programs attached to the stable `sched_switch`, `irq_handler_entry`
and `softirq_entry` tracepoints record the event time stamps, execute the
SP800-90B health tests (RCT and APT) on the raw data and deposit the time
between successive events of a CPU. The spacing of the events is where the
entropy is, and it is what the SP800-90B assessment of the raw samples
measures, so what the server credits is what was assessed.

The deltas are collected in per-CPU buffers and handed to a BPF ring
buffer once a buffer is full - or, for a CPU that falls quiet with a
partially filled one, after an idle deadline, so that nothing collected
lingers unaccounted. The `esdm-server` reads them from there when it wants
entropy and conditions them into a per-source entropy pool with the
configured hash; it stops reading once that pool holds all the entropy one
output block can carry, and an extraction fetches what its block still
costs. Events collected while nobody reads fill the buffers up and are then
dropped - nothing needs them, and what is already collected is no worse.

Only events the health tests vouch for are collected, so no health state
travels with them. What the programs report back - the deltas each CPU
handed over and its SP800-90B health state - lives in a per-CPU map the
server reads directly, which is also how it knows how much entropy is
still to be had without fetching it first.

Requirements: a kernel with BTF support (`CONFIG_DEBUG_INFO_BTF`, standard
on the common distributions; kernel 5.15 or later on x86_64, 6.1 or later
on arm64), libbpf >= 1.2, and `clang` plus `bpftool` at build time. The
programs are loaded during the privileged initialization phase of the
`esdm-server`. Like all timing entropy sources, at most one of `es_irq`,
`es_sched`, `es_irq_ebpf` and `es_sched_ebpf` may be credited with a
non-zero entropy rate.

The default entropy rate of both sources is 0 (uncredited): determine the
appropriate rate for a deployment environment with the measurement tooling
in `addon/es_ebpf_testing/` before crediting the sources. See
`doc/esdm_es_ebpf.md` for the design description.

## Testing

The ESDM code repository uses `meson` to provide an extensive test harness
to verify the correctness of the implementation of ESDM. To execute the
testing, use `meson test -C build` after the setup step outlined in [Build].

Note, some tests require to be executed as root. For example to validate the
correctness of the device file implementations of `/dev/random` or
`/dev/urandom`, the root privilege is required to create those devices.
If the testing is not executed as root, a few tests will be marked as skipped
due to this issue.

In addition, some tests require the library to be compiled with the option
`testmode` to enable interfaces to test internal operations. DO NOT ENABLE
THIS MODE FOR PRODUCTION CODE! This mode per default is disabled and can
be enabled with the command `meson configure build -Dtestmode=enabled`.

## Usage

The ESDM consists of the following components:

* `libesdm.so`: The ESDM provides a library with the core of the ESDM. The
  DRNG and entropy source managers together with all entropy sources and
  cryptograpphic algorithm implementations are implemented with this library.
  This library is wrapped by the `esdm-server` listed below. The API for using
  the library is exported by and documented with `esdm.h`.

  The library is provided in case a user wants to employ the ESDM in his
  projects instead of the `esdm-server`. Yet, the `esdm-server` provides a
  wrapping daemon to the ESDM library that is intended to be commonly used.

  In addition, the ESDM can be configured with the options specified in
  `esdm_config.h`. This would need to be performed by the consuming application.
  When using the tools below, this library can be ignored.

* `esdm-server`: The ESDM server provides the RPC server that encapsulates
  the ESDM with its random number generator and the entropy source management.
  When starting the server, a Unix domain socket is created that allows clients
  to request services including random numbers.

  The ESDM server can either be started manually or with the provided (and
  installed) systemd unit file. When using systemd, start the server with
  `systemctl start esdm-server`.

  A wrapper library to access the ESDM server RPC interface is provided with
  `libesdm_rpc_client.so`. Its API is specified and documented with
  `esdm_rpc_client.h`.

  The `esdm-server` is the backend to all of the following ESDM components.

  NOTE: The Unix domain sockets of the `esdm-server` are only visible in the
  respective mount namespace. If you have multiple mount namespaces, you need
  to start the daemon in each mount namespace or make the files otherwise
  available if its services shall be available there.

* `esdm-cuse-random`: The ESDM CUSE daemon creates a device file that behaves
  identically to /dev/random. It must be started as root. Reading, writing and
  IOCTLs are implemented in an ABI-compatible way.

  The ESDM CUSE daemon can either be started manually or with the provided (and
  installed) systemd unit file. When using systemd, start the server with
  `systemctl start esdm-cuse-random`. Although the daemon creates a
  /dev/random device, the actual visible operation is atomic (a bind mount) for
  both creation and destruction of the new device file which implies that the
  daemon can be started and stopped at any time during runtime of the Linux OS.

  NOTE: The bind mount is only visible in the respective mount namespace. If
  you have multiple mount namespaces, you need to start this daemon in each
  mount namespace or make the file otherwise available if its service shall be
  available there.

* `esdm-cuse-urandom`: Same as `esdm-cuse-random` but behaving like
  /dev/urandom.

* `esdm-proc`: This FUSE file system implements all files found on a Linux
  system under `/proc/sys/kernel/random` but pointing to the ESDM server. This
  process is required to ensure that all interfaces are provided by ESDM. For
  details about the provided files, see the `random(4)` man page. Note,
  the kernel exports the `/proc/sys/kernel/random` information also as
  `sysctl(8)`. This interface is not covered by `esdm-proc`.

  NOTE: If you run the `esdm-proc` tool on a system with SELinux in enforcing
  mode using the targeted policy, you need to create a new policy. A template
  is provided in the `addons/esdm-proc-selinux` directory. Compile the policy
  with the provided `esdm_proc.sh` script. For details, see
  `addons/esdm-proc-selinux/README.md`.

* `libesdm-getrandom.so`: The library provides a wrapper to the `getrandom` and
  `getentropy` libc library calls. To use the library for other consumers, use
  one of the following  considerations:

	- Use LD_PRELOAD="/path/to/libesdm-getrandom.so" with the intended
	  application.

        - Create / update `/etc/ld.so.preload` to add the entry
          `/usr/local/lib64/libesdm-getrandom.so` (or the respective path to
          the `libesdm-getrandom.so` on the system). This is to be followed
          by the execution of `ldconfig`.

	- Compile the application or library with the following options:

		- `LDFLAGS += -Wl,--wrap=getrandom,--wrap=getentropy`

		- `LDFLAGS += -lesdm-getrandom`

* `openssl-provider`: A random provider for OpenSSL 3.0 and greater is included.
  Load `libesdm-rng-provider.so` if all random numbers should originate in ESDM
  or `esdm-seed-src-provider.so` if ESDM should only be used as a source of seeds.
  Both reach the ESDM over its RPC interface and tag their algorithms with the
  property `provider=esdm`.

  `libesdm-egd-provider.so` is an alternative to `libesdm-rng-provider.so` that
  obtains its random numbers over the EGD interface instead (see
  README.usage.md). It needs nothing but that one socket - no RPC client, no
  shared memory - which makes it usable where the RPC interface cannot be
  reached. Its algorithms carry the property `provider=esdm-egd`, so it can be
  loaded next to the RPC based ones, and the socket it uses is named with the
  `egd_socket` key of its `openssl.cnf` section. Note that the EGD protocol
  cannot express prediction resistance: a request explicitly asking for it is
  refused rather than served with ordinary random data.

  `libesdm-egd-provider-pr.so` is the prediction resistance counterpart. Since
  the protocol cannot select the generator per request, that is a property of
  the socket - the ESDM serves a second EGD socket from
  `esdm_get_random_bytes_pr()` - so this variant simply defaults to that socket
  and accepts prediction resistance requests. Its algorithms carry
  `provider=esdm-egd-pr`.

* `libesdm_egd_client`: A small client library for the ESDM's EGD interface,
  used by the EGD OpenSSL provider and usable on its own (`esdm_egd_client.h`).
  It owns a single connection, serializes the command stream on it, bounds every
  wait, and reconnects transparently when the daemon was restarted or the client
  is used after a `fork()`.

* `esdm-server-signal-helper`: This small tool is used to support proper
  quiescing of the ESDM server when the system suspends or sleeps. When invoking
  this tool with the `--suspend --pid <ESDM-Server-PID-file>` it notifies the
  ESDM server to prepare for suspending/sleeping. Conversely when the tool is
  used with the option `--resume` it informs the ESDM server about the system
  wakeup. The associated systemd unit files of `esdm-server-suspend.service`
  and `esdm-server-resume.service` obtain the suspend/resume trigger.

* `esdm-kernel-seeder`: Can be used to periodically seed the Linux kernel from
  ESDM. Configure its interval and entropy rate via the respective meson options
  (`linux-reseed-interval` and `linux-reseed-entropy-count`).

* `esdm-tool`: This tool can be used to test ESDM and interact with it without
  building an own tool with the rpc_client library or using the CUSE devices.
  With the help of esdm-tool `esdm-wait-unti-fully-seeded.service` is implemented.
  Add this service as a dependency of your early system start if you'd like to
  guarantee, that all services started in succession can expect ESDM to return
  fast.

IMPORTANT NOTE: The RPC interfaces between the components are present to ensure
there is a proper security domain separation. The RPC protocol is not considered
to constitute a stable API that should be used to program against.

## Documentation

See the documentation in the `doc/` directory.

# Author

Stephan Mueller <smueller@chronox.de>
