Changes 1.2.4
* Add an optional EGD (Entropy Gathering Daemon) protocol interface to the
esdm-server, enabled by starting esdm-server-egd.socket or with
--egd_socket <path>, which serves legacy entropy consumers such as libgcrypt's
rndegd backend or OpenSSL's RAND_egd()

* Add libesdm_egd_client, a client library for the EGD interface, and
libesdm-egd-provider.so, an OpenSSL 3 RAND provider based on it: both need
nothing but the one EGD socket and therefore work where the RPC interface
cannot be reached, OpenSSH's sandboxed pre-authentication child included

* Add a second EGD socket serving the prediction resistance generator
(esdm-server-egd-pr.socket, --egd_socket_pr) together with the matching
libesdm-egd-provider-pr.so - the EGD protocol cannot ask for prediction
resistance per request, so it is a property of the socket

* Add the kernel module esdm_cdev (kernel/esdm_cdev): /dev/esdm_random,
/dev/esdm_urandom and /proc/esdm served from the ESDM over its EGD socket, with
the ioctls of the kernel's random devices - the counterpart of the CUSE
frontend in the kernel, leaving the kernel's own devices untouched; nothing is
served from elsewhere while the ESDM is not reachable. esdm-cdev-check holds
its checks, installed with the build option esdm-cdev-check

* EGD interface: commands of the ESDM's own, 0xe0 to 0xec of
esdm_egd_protocol.h, for what the EGD protocol cannot express: prediction
resistant reads, a read with the semantics of /dev/urandom, the state, the
status, reads and insertions of up to 64 KiB, and for a privileged peer the
pool and reseed operations

* Entropy pools: each auxiliary pool and the conditioning pool of the eBPF entropy sources is an XDRBG-256 - the XDRBG over SHAKE256 with a state of 512 bits, the one the kernel module esdm_es conditions with - instead of a pair of conditioning hashes; whatever is inserted is the seed of the next reseed and an extraction reseeds and generates; the SHAKE256 is that of the crypto backend (nettle >= 3.6 for the GnuTLS backend, Botan >= 3.2), the crypto self test covers it with a known-answer test of the XDRBG, and esdm_get_digestsize() reports the size of the state; after an XOF failure the eBPF pool takes the seed of a new instantiation instead of leaving the source without one

* Botan backend: with Botan 3.14.0 or later, the ChaCha20 DRNG
(botan_drng_type=chacha20) runs with fast key erasure, which gives its state
backtracking resistance (AIS 20/31 DRG.3); its self test uses the known answers
of the fast key erasure in Botan's own test suite

* Kernel module esdm_es: moved from addon/linux_esdm_es to kernel/esdm_es and
built from the source tree, sharing the IOCTL interface, the seed sizes and the
health test cutoffs with the ESDM instead of carrying copies. It needs Linux
6.1 or later, supports 7.2 and 7.3, and post-processes with the XDRBG-256 over
the SHAKE256 of the kernel where the kernel has its SHA-3 library, which Linux
7.2 and later require

* Kernel module esdm_es: the requested entropy and the entropy rate belong to
the descriptor of /dev/esdm_es they are set on, a requested size that is no seed
size is refused, and the state is reported as JSON only - ESDM_IRQ_STATUS and
ESDM_SCHED_STATUS are gone

* fix: RNDADDTOENTCNT: credits add up in a build oversampling the auxiliary pool,
where the count less the oversampling was read and set back; esdm_pool_add_entropy()
credits under the pool lock

* Split the build option ais2031 into ais2031_ntg1 (NTG.1 seeding strategy) and
ais2031_drg4 (DRG.4.10 reseeding limits), which can now be selected independently

* NTG.1 seeding strategy: seed from the jitter RNG alone when it is operated in
its own NTG.1 mode (es_jent_ntg1 with jitterentropy >= 3.7.0), as it is NTG.1
conformant without a second entropy source

* Add eBPF-based scheduler and interrupt entropy sources (es_sched_ebpf,
es_irq_ebpf): no kernel patches required, in-program SP800-90B health tests,
zeroization of every collected raw sample when the sources are unloaded - the
in-program collection buffers and the ring buffer holding the events included -
raw entropy measurement tooling including the SP800-90B restart test in
tests/es_ebpf_testing

* Add external entropy sources: provider processes written against libesdm_es_ext (esdm_es_ext.h) serve them over a Unix domain socket in protobuf, read by the ExternalSocket ES (esdm-server --es_ext); the ES monitor asks the provider for its status on every round, one not answering within 500 ms not again for a minute

* Entropy sources: no entropy is buffered ahead of a request, the auxiliary pool aside - the Jitter RNG block buffer is gone with es_jent_entropy_blocks, esdm-server --jent_block_disable and esdm_config_es_jent_async_enabled{,_set}()

* Jitter RNG ES: es_jent_instances collectors (meson option, esdm-server --es_jent_instances 1 to 64, default 4 in a build reseeding often - sp80090c, fips140, ais2031_drg4 - and 1 otherwise) serve the seedings of the DRNGs side by side, each behind a lock of its own - in an SP800-90C build four of them raise the output under load from some 35000 to 90000 requests of 32 bytes per second on ten CPUs; with jitterentropy >= 3.8.0 the known answer tests of its conditioning component run through jent_selftest() bound to every collector, and a collector that failed them serves nothing

* Kernel Jitter RNG ES: the kernel crypto API RNG it reads is configurable (meson option es_jent_kernel_name, esdm-server --es_jent_kernel_name, jitterentropy_rng by default), e.g. for a jitterentropy kernel module registering its RNG under another name; the status names the RNG in use

* Add TPM2 entropy source

* Add PKCS11 entropy source as esdm-es-pkcs11, and esdm-es-pcsc reading PC/SC smart cards - both external ES providers

* SP800-90C compliance: all ES with zero entropy are inserted into DRBG as "additional info" or "personalization string" (compliance to section 2.6)

* Reseed the DRNGs proactively: an asynchronous worker reseeds a DRNG whose interval elapsed whether or not data was ever requested from it, brings up instances that never reached the fully seeded level, spreads the seed times over a random offset and sleeps until the next reseed falls due; the status reports the worker, its passes and the time left before each reseed

* fix: An RPC client decoded a response whose header it had just rejected, handing the caller a payload reaching past the receive buffer - for the random calls, data generated for an earlier request (found by the new fuzz harnesses)

* fix: An interrupted RPC call left its answer on the connection, where it was handed out as the reply to the next call and every call after it; the connection is now dropped when a call abandons its answer (found by the new fuzz harnesses)

* fix: The OpenSSL RAND providers stored a new context lock over the old one when locking was enabled twice, leaking it and leaving the users of the shared context locking different things (found by the new fuzz harnesses)

* Add fuzz harnesses for the RPC requests, responses and wire codec, the server as a client reaches it, both sides of the EGD interface and the library API (build option 'fuzzing', see tests/fuzz/README.md); beyond crashes they check what the code promised, and their seeds are replayed by the ordinary test suite

* Add a fuzz harness per shipped OpenSSL RAND provider module (build option 'openssl-rand-provider'), each loading its provider the way libcrypto does and holding it to the contract of <openssl/core_dispatch.h>

* Add a stress test of the RPC request path under concurrent load, every request carrying an ID the answer has to carry back

* FIPS 140 integrity test: a missing HMAC file is now a failed integrity test rather than a pass; the reference values are written at installation time with esdm-tool (see README.usage.md)

* FIPS 140 integrity test: attest the ESDM library as well, not only the executable

* Run the self tests of the hash and the DRNG implementation every 10 minutes, and hand out random bits only while their outcome, reported in the status, is that they passed

* Add a self test to every entropy source and run them in the same pass as the crypto ones, at start up and on the interval; a failing source is logged and reported but does not stop the ESDM, as it stops being credited on its own

* Run the self tests on demand over the privileged RPC socket (esdm_rpcc_selftest, esdm-tool --selftest), answered with the state of both test groups and how many entropy sources were tested and failed

* DRBG self tests: use CAVP records that reseed, so instantiate, reseed and generate are all covered as SP800-90A section 11.3 and FIPS 140-3 IG 10.3.A require

* Self tests: accompany every known answer test with two negative tests, so that neither a comparison that cannot fail nor an implementation ignoring its input passes as a self test

* esdm-tool: add --max-reseed-secs SECS to set the maximum interval between two DRNG reseeds

* Status report: add one section per DRNG instance - seeding state, reseed counters, seed generation and the time of the last seeding - to the status text and to the JSON document ("drngs" array), carrying the initial and the prediction resistance instance; an instance is identified by type and node now, so the "id" member is gone

* Status reports are no longer truncated silently: a report that does not fit into the buffer is answered with -EMSGSIZE, a JSON document empty and a text report as far as it got, so esdm_status() returns a value now

* Status: the ESDM and its entropy sources report their state as JSON only; the status text - of esdm_status() and so of the RPC, EGD, CUSE and shared memory status - is rendered from that document, its labels derived from the member names; in the JSON, the CPU source reports a hash for compressing data of null when there is none, and the eBPF sources report a permanent health test failure as permanent_failure rather than in the failure count; an entropy source is headed by its name and ID

* RPC latency: each RPC worker serves its requests from a DRNG instance of its own instead of the one of the CPU it runs on; a reseed collects its entropy without holding the DRNG, which keeps serving meanwhile; the global entropy pool lock is gone - the entropy sources lock themselves and the seedings of different DRNGs run side by side, the reseed worker starting the reseed or bring-up of each DRNG as it falls due, on a thread of its own, as far as Jitter RNG collectors are free; a caller that may not wait seeds a DRNG itself only while a Jitter RNG collector is free and leaves the seeding to the reseed worker otherwise; a client reads the answer with a blocking socket and timeouts, a request taking two system calls instead of four, and when waiting for data polls again after 1 ms, backing off to 16 ms, instead of after one second (measured by tests/rpc_client/rpc_latency_bench, meson test --benchmark)

* Add an RPC call to obtain the status of a single DRNG instance as JSON, addressed by the node it serves or by asking for the prediction resistance instance

* esdm-tool: add --drng-status [=NODE|pr] and --drng-status-json [=NODE|pr] to print one DRNG instance or, without an argument, all of them as a JSON array

* Logging: color the severities only on a terminal and without NO_COLOR set, so
log files, pipes and the test logs carry no escape sequences

* esdm-tool: add --set-es-rate ES=BITS (esdm_rpcc_set_es_rate) to set the
entropy rate of one or all entropy sources - honored by a server built in test
mode or with buildtype=debug only, for tests that take the entropy away from
the ESDM

* fix: RPC server: a failing start-up exits with an error instead of hanging; the namespace jail covers every thread; the selftest RPC needs root; privileged prediction resistance requests take precedence

* fix: RPC client: a request without answer fails with -ETIMEDOUT after a few seconds so callers reach their fallback; a lost connection is reconnected; waiting for the seeding no longer pins a connection or blocks fork(); a forked child no longer shuts down the parent's connections; esdm_rpcc_get_random_bytes_full_timeout() keeps its deadline with interrupt data; the scratch buffers are per-thread heap memory instead of 130 KB of static TLS; esdm_rpcc_get_random_bytes() returns short or -EAGAIN instead of spinning while the DRNGs of the ESDM wait for their reseed; a refused connect fails at once unless a server served the process within 10 s, instead of after 2.4 s of retries on a socket file a stopped server left behind; requests whose effect adds up (rnd_add_entropy, rnd_add_to_ent_cnt, rnd_clear_pool, rnd_reseed_crng, selftest, write_data) are not sent again when their answer is missing

* Add esdm_rpcc_get_random_bytes_full_noblock() and esdm_rpcc_get_random_bytes_pr_noblock(): one request, -EAGAIN instead of waiting

* fix: EGD server: input sent before a hangup is processed. EGD client: a symlinked socket path no longer reconnects on every call, a vanished daemon no longer raises SIGPIPE, a descriptor number the application closed and reused is no longer closed by the reconnect, the free or the fork handler; a non-blocking read finding the DRNGs of an operational ESDM waiting for their reseed is answered once one landed, for up to 1 s, instead of empty, which esdm_cdev takes for not operational; the status no longer waits for an es-ext provider in the middle of a request

* fix: DRNG manager: max_wo_reseed and max_wo_reseed_bits are enforced before every chunk, a DRNG may return short, the initial DRNG stops at its reseed threshold so that the ESDM stays operational, and the non-waiting getters answer -EAGAIN while every DRNG waits for its reseed; the prediction resistance DRNG is seeded with fresh entropy right before every chunk only and is fully seeded at s + 64 bits; the operational state follows the successfully seeded initial DRNG only; the non-blocking getters never wait for the entropy pool, esdm_get_random_bytes_pr_noblock() returns -EAGAIN instead of 0; without a reseed worker the node DRNGs reseed inline instead of never; a DRNG out of its output adds up collections for its reseed, so a single source credited below a full seed per collection works in SP800-90C and DRG.4 builds

* fix: esdm-server: --username takes its argument instead of falling back to "nobody"; the systemd unit no longer hides FIPS mode from the server (ProcSubset=pid) and allows AF_ALG where the kernel Jitter RNG source is built

* fix: libesdm: esdm_init() after esdm_fini() fails with -ESHUTDOWN; raising max_nodes after init is safe; the status SHM and semaphores are torn down after the threads are joined; the reseed worker no longer misses a wakeup; pool threads are cancelled deferred after a grace period


* fix: hwrng and TPM 2.0 entropy sources: the device is read by a thread of its own with a deadline of 2 s, so a stalled device no longer hangs seeding, start-up, shutdown or the status; a failing device is probed by the ES monitor only

* fix: entropy sources: failed self tests of the CPU, kernel RNG, kernel Jitter RNG and TPM 2.0 sources are sticky, a stalled CPU RNG is credited with nothing until it delivers again instead of failing the self test, and a source credited with nothing after a failed read is read by the next seedings whatever entropy is available, as nothing else would read it, the TPM 2.0 self test requires two reads to differ; the Jitter RNG claims no entropy while it fails and reports its status without holding off its collections; RISC-V: the seed CSR is probed instead of raising SIGILL; es-ext provider: a later unprivileged client can no longer take the ESDM's slot

* TPM 2.0 and /dev/hwrng entropy sources: credited with no entropy by default (es_tpm2_entropy_rate and es_hwrand_entropy_rate 0), and an uncredited device busy with another seeding is skipped rather than waited for - the TPM serialized every seeding, which capped the output of an SP800-90C build at some 180 reseeds per second

* DRNG manager: the reseed worker stays on duty with a reseed interval of zero seconds, and the reseed_pending member of the DRNG status is gone with the handshake behind it. ES manager: the ES monitors run one after the other in the monitor thread

* DRNG manager: in a build capping the output without a full reseed (sp80090c, fips140, ais2031_drg4), a request starting below the 2^17 bit limit is completed rather than cut at it, as SP800-90C 5.2.3 and AIS 20/31 DRG.4.10 allow, and the DRNGs generate up to 2^19 bits per request at once - a large request needs one reseed rather than one per 16 KiB; a node DRNG spent by such a request is skipped and reseeded by the worker at once instead of handing the next request to the initial DRNG

* fix: eBPF entropy sources and esdm_es: the RCT and APT fail at their cutoffs, one sample earlier, and APT windows start with their base sample; eBPF: a health failure discards the partial batch, events of an uncredited source are stirred into the pool, a failed insertion drops the credit

* fix: esdm_es: ioctls no longer hold the global lock while accessing user memory; a permanent health failure panics from an irq_work; a failing health test resets the source once per window; BUILD_TESTING creates the debugfs files of the built sources only. esdm_cdev: poll() no longer runs the watcher back to back, timeout_ms bounds a whole transfer

* fix: CUSE: O_DSYNC no longer selects prediction resistance; privileged ioctls require CAP_SYS_ADMIN of the caller; the privileges are always dropped; /proc content is generated per open, uuid was always empty

* fix: getrandom shim: GRND_NONBLOCK returns EAGAIN before full seeding, refused flags set errno, PID 1 and processes embedding libesdm use the system call, a request of no bytes reports the readiness of the ESDM instead of passing to the kernel; kernel seeder: a stop interrupts waiting RPCs, its unit starts as Type=exec without systemd support; server-signal-helper signals a server holding the PID file lock only

* fix: crypto: the leancrypto backend reports failed leancrypto self tests and refuses unseeded output (leancrypto >= 1.6.0 required) and absorbs the full additional input; the OpenSSL backend passes the additional input on every reseed and keeps no copy of a seed; SHA-3 init and the XDRBG zeroization wipe absorbed data; the GnuTLS backend requires GnuTLS >= 3.6.7, whose DRBG context layout it relies on

* fix: build: -Dfips140=true applies the SP800-90C adjustments it claims - oversampled entropy sources, the output cap without a full reseed - as -Dsp80090c does

* Timeouts, ages and reseed intervals use CLOCK_MONOTONIC_COARSE, saving a clock source read per request - a hypervisor trap in VMs without a vDSO capable clock source

Changes 1.2.3
* Fix handling of non-blocking server response

* Reduce chunk size for the PR IPC interface to 32 bytes for more responsive
server

* CPU ES: Fix RDSEED to RDRAND fallback

* Allow PR DRNG to be used as RBG3(RS) in SP800-90C mode

* Fix SP800-90C instantiate for OpenSSL backend

Changes 1.2.2
* Add TPM 2.0 entropy source

* Reworked threading concept towards multi-connection workers for less memory usage

* Add jitterentropy status RPC call and expose in esdm-tool

* Kernel seeder: add systemd notify support, improve startup speed, double inserted entropy amount

* RPC: set non-blocking sockets, add timeout to non-blocking writes, simplify per-connection buffers, improved performance

* More robust signal handling, overflow checks and argument validation

* RPM SPEC file fixes for openSUSE

* add PPC DARN instruction availability check

* fix crasher in CUSE poller thread

* fix compilation with systemd=disabled

* esdm-server: Fix handling of SIGUSR1 sent by suspend/resume helper (they caused the server to terminate)

* Add backtracking resistance to internal state/output of aux pool

* Automatically add device specific personalization string based on product uuid from DMI, when available

* Assure 256 bit security level on all Intel CPUs

* Fixes for esdm_es and switch to 64 bit timestamps and usage of time deltas

* Support for Linux kernel 6.18 in esdm_es

* Added support for NTG.1 compliant jitterentropy-library 3.7.0

* remove minimally seeded stage

* remove placeholder for atomic DRNG

Changes 1.2.1
* Reduce lock contention and increase throughput (thanks to Markus Theil)

* Add helper tool to externalize the C API to command line (thanks to Markus Theil)

* Update OpenSSL backend (thanks to Markus Theil)

* Update Botan backend (thanks to Markus Theil)

* Update systemd for SLES / Tumbleweed to prevent shutdown hangs

* Establish AIS20/31 DRG.4 compliance (thanks to Markus Theil)

* Place Linux RNG seeder into its own application to avoid chicken-egg problem inside the ESDM (thanks to Markus Theil)

* NTG.1 updates to comply with AIS 20/31 v3.0

* Linux kernel ES: Add cryptographic post-processing with state for esdm_es (SP800-90A DRBG).
  Only use high resolution time code path from now on. All known current CPUs
  support this and allow for storage of fixed with timestamps. Timestamps
  are now stored per CPU and directly take part in a combined seed of multiple
  per-CPU buffers via a scather gather list. Clear state when suspending or
  rebooting.

* Don't expose testing interface of esdm_es when in lockdown mode.

* Add NIST test vectors for Botan HMAC-DRBG(SHA-512).

* Fix: RDRAND feature detection.

* Fix: performance with many worker threads on many core systems.

* Added improved systemd support (notify, socket activation). Switch default
  path to /run in order to prevent systemd deprecation notices. Small refactoring
  of systemd service generation to unify socket and non-socket activation paths.

* Fix: FIPS 140 init works now, added checksum generation to esdm-tool for better
  scripting.

* Add explicit OSR to esdm_es. Expose different ES' via Makefile options.

Changes 1.2.0
* fix: to prevent a DoS against the RPC channel, limit the slow operations of esdm_get_random_bytes_pr and esdm_get_seed to allow only one call in flight. If another call comes in while one process is ongoing, return -EAGAIN to free the RPC channel.

* fix: handle rogue libesdm-aux clients more gracefully - if a client received a notification to supply entropy, but it fails to send anything, the ESDM will not send a notification again. This issue is alleviated by checking the need_entropy common variable

* switch from CLOCK_REALTIME to CLOCK_MONOTONIC for wait operations

* add esdm.spec file for generating an RPM

Changes 1.1.1:
* fix: properly use the mutex absolute time argument, timedlock handling and mutex destruction in the ESDM RPC client lib

* fix: race condition in worker thread execution

Changes 1.1.0:
* fix: name of leancrypto DRNG

* fix: getentropy returns 0 on success

* enhancement: only establish connection to server once and when needed

* fix: SHM in CUSE must be attached RD/WR

* enhancement: add esdm_aux_client library

Changes 1.0.2:
* hardening: enable -fzero-call-used-regs=used-gpr

* editorial: rename logging* symbols to esdm_logging* - this is purely internal, but considering some of these symbols are externally visible, libesdm_rpc_client pollutes the namespace of consumers

* enhancement: significant performance increase of RPC communication

* fix: Poll writer woke up as status variable was not properly initialized

* fix: proper shut down sequence of ESDM daemons

Changes 1.0.1:
* enhancement/fix: add support for multiple ESDM RPC client connection initializations

* fix: If a process select/poll on a CUSE file, the system now goes properly to sleep

* fix: If there is high load on the CUSE daemons - make sure they properly shut down on reboot

Changes 1.0.0:
* fix (re)initialization of ESDM to set correct entropy level

* IRQ/Sched ES: add support to retry accessing the kernel with -i and -s flags

* enhancement: Jitter RNG ES generates data asynchronously

* enhancement: add kernel Jitter RNG ES

* enhancement: add leancrypto, OpenSSL and Botan crypto provider backends

* enhancement: add OpenSSL, Botan seed provider (leancrypto ESDM seed provider is found in leancrypto source code)

* fix: ESDM server - systemd unit executes server in current mount namespace

* editorial: apply clang-format

* fix: CUSE daemons may hang during shutdown due to busy mounts

* fix: resynchronize CUSE daemons and ESDM server upon ESDM server restart

* enhancement: ESDM server status splits up FIPS 140 and SP800-90C compliance

* rename compile time option "oversample_es" to "sp80090c" which is now disabled
  by default considering that with its enabling, the oversampling is applied
  unconditionally during startup

Changes 0.6.0:
* Move ESDM apps into separate namespaces to limit their privilege even further (e.g. no possibility to create network connections)

* Add German AIS 20/31 (draft 2022) NTG.1 compliance support

* the blocking property of an interface is implemented in the client - the
  server reports -EAGAIN for a blocking behavior

* add "emergency seeding" when entropy sources cannot collectively deliver
  256 bits of entropy, pull data repeatedly until 256 bits are received

* export esdm_rpc_client.h with all depending header files to allow external
  clients to be developed

* update IRQ/Scheduler ES health test to match LRNG

* bug fix: correctly calculate memory offsets

* enhancement: Sched/IRQ ES code in ESDM can handle if kernel-parts have
  different data structure size for sending entropy to user space

* IRQ/Sched ES: Switch to /dev/esdm_es character devices a user space interfaces

Changes 0.5.0:
* Linux kernel entropy feeder is now always enabled

* Add Linux /dev/hwrng entropy source

* FIPS IG 7.19/D.K / BSI NTG.1: use a new DRNG instance executed with PR

* Handle communication errors between client and server gracefully

* ES monitor now runs for lifetime of the ESDM

* add interface to access entropy sources - esdm_get_seed including making it accessible via getrandom(2)

* fix of deadlocks during shutdown

Changes 0.4.0:
* Start CUSE daemons independently from ESDM server

* add support for invoking DRNG with prediction resistance when opening
  /dev/random with O_SYNC or using the esdm_get_random_bytes_pr API.
  This reestablishes the NTG.1 property as well as well as supports
  using the DRBG as a conditioning component pursuent to SP800-90C and
  FIPS 140 IG 7.19 / D.K.

* initialize the DRNG immediately with 256 bits (disregarding 32/128 bits)

* add interrupt entropy source

* modify collection in scheduler ES: maintain a hash state per CPU as a per-CPU entropy pool

* add proper interrupt/signal handling code to the ESDM RPC client library

* privilege level change in CUSE is now limited to caller only

* add support to allow ld.so.preload to be used to refer to libesdm-getrandom.so for a system-wide replacement of getrandom/getentropy system call.

Changes 0.3.0:
* Replace protobuf-c-rpc with built-in RPC mechanism reducing amount of mallocs,
  performing proper zeroization and being fully thread-aware

* Testing: disable /dev/random fallbacks for verifying RPC operation

* RNDGETENTCNT returns the seed state of the auxiliary entropy pool only. This
  makes it 100% ABI compliant to random.c

* Add ChaCha20 DRNG to regular code base

* Add SHA-3 conditioning hash to regular code base

* Add /proc/sys/kernel/random files handler along with SELinux policy, tested
  with:
	- rng-tools
	- jitterentropy-rngd
	- haveged

Changes 0.2.0:
* Initial public version
