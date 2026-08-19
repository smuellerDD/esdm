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
addon/es_ebpf_testing

* Centralize asynchronous buffer management to collect entropy from slow entropy sources

* Add TPM2 entropy source

* Add PKCS11 entropy source

* SP800-90C compliance: all ES with zero entropy are inserted into DRBG as "additional info" or "personalization string" (compliance to section 2.6)

* Reseed the DRNGs proactively: an asynchronous worker reseeds a DRNG whose interval elapsed whether or not data was ever requested from it, brings up instances that never reached the fully seeded level, spreads the seed times over a random offset and sleeps until the next reseed falls due; the status reports the worker, its passes and the time left before each reseed

* fix: An RPC client decoded a response whose header it had just rejected, handing the caller a payload reaching past the receive buffer - for the random calls, data generated for an earlier request (found by the new fuzz harnesses)

* fix: An interrupted RPC call left its answer on the connection, where it was handed out as the reply to the next call and every call after it; the connection is now dropped when a call abandons its answer (found by the new fuzz harnesses)

* fix: The OpenSSL RAND providers stored a new context lock over the old one when locking was enabled twice, leaking it and leaving the users of the shared context locking different things (found by the new fuzz harnesses)

* Add fuzz harnesses for the RPC requests, responses and wire codec, the server as a client reaches it, both sides of the EGD interface and the library API (build option 'fuzzing', see tests/fuzz/README.md); beyond crashes they check what the code promised, and their seeds are replayed by the ordinary test suite

* Add a stress test of the RPC request path under concurrent load, every request carrying an ID the answer has to carry back

* FIPS 140 integrity test: a missing HMAC file is now a failed integrity test rather than a pass; the reference values are written at installation time with esdm-tool (see README.usage.md)

* FIPS 140 integrity test: attest every component of the module - the ESDM library, the Jitter RNG and the crypto library of the selected backend - and not only the executable

* Run the self tests of the hash and the DRNG implementation every 10 minutes, and hand out random bits only while their outcome, reported in the status, is that they passed

* Add a self test to every entropy source and run them in the same pass as the crypto ones, at start up and on the interval; a failing source is logged and reported but does not stop the ESDM, as it stops being credited on its own

* Run the self tests on demand over the privileged RPC socket (esdm_rpcc_selftest, esdm-tool --selftest), answered with the state of both test groups and how many entropy sources were tested and failed

* DRBG self tests: use CAVP records that reseed, so instantiate, reseed and generate are all covered as SP800-90A section 11.3 and FIPS 140-3 IG 10.3.A require

* Self tests: accompany every known answer test with two negative tests, so that neither a comparison that cannot fail nor an implementation ignoring its input passes as a self test

* esdm-tool: add --max-reseed-secs SECS to set the maximum interval between two DRNG reseeds

* Status report: add one section per DRNG instance - seeding state, reseed counters, seed generation and the time of the last seeding - to the status text and to the JSON document ("drngs" array), carrying the initial and the prediction resistance instance; an instance is identified by type and node now, so the "id" member is gone

* Status reports are no longer truncated silently: a report that does not fit into the buffer is answered with -EMSGSIZE, a JSON document empty and a text report as far as it got, so esdm_status() returns a value now

* Add an RPC call to obtain the status of a single DRNG instance as JSON, addressed by the node it serves or by asking for the prediction resistance instance

* esdm-tool: add --drng-status [=NODE|pr] and --drng-status-json [=NODE|pr] to print one DRNG instance or, without an argument, all of them as a JSON array

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
