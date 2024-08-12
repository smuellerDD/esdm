Changes 1.1.2-prerelease:
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
