# User Guidance

This document contains some hints about special cases that should be considered
when using the ESDM.

## CUSE Daemon Restart and Select/Poll

Assume you have a daemon that has a select(2) or a poll(2) on either
`/dev/random` or `/dev/urandom` where the device file is served by the ESDM
CUSE helper (i.e. `esdm-cuse-random` or `esdm-cuse-urandom`).

Now, you need to restart the ESDM CUSE daemon. The following happens:

1. The user daemon sleeps in select(2) or poll(2).

2. The ESDM CUSE daemon terminates.

3. The user daemon is woken up by the ESDM CUSE daemon termination, i.e. the
   select(2)/poll(2) returns without an error.

4. The user daemon now tries, for example, to inject entropy using the `ioctl`
   of `RNDADDENTROPY`. This now *fails* with the error code `ENOTCONN`. Now,
   it is possible that the user daemon tries to close and re-open the file
   descriptor for the device file. Yet, since the ESDM CUSE daemon is
   either stopped or in the process of restarting, the user daemon now *may*
   open the "real" device file from the kernel. Thus, when the user daemon
   waits with select(2)/poll(2), it is not interfacing with the ESDM any more.

This situation can be remedied if such user daemon has a `systemd` unit file
which declares a dependency on the `esdm-cuse-random` and/or `esdm-cuse-urandom`
`systemd` units. This implies that by stopping or restarting the ESDM CUSE
daemons, the user daemon is equally stopped/restarted.

## CUSE Daemon Connection Duration

It is possible that when requesting data from `/dev/random` or `/dev/urandom`
that are provided by the CUSE daemons, a wait time that is longer than with
the Linux kernel device files is visible. For example, it is possible that
wait times of 200ms may be observed.

If guaranteed lower wait times are required, then the following approach
can be taken. However, that approach implies that the priority of the CUSE
daemons increase such that they have precedence over other applications. Also,
the change in the reconnection timeout implies that it is more likely that
a reconnection is performed which in itself requires some overhead.

The following subsections outlined the possible options which partially or
all can be applied.

### Lower Connection Timeout

The timeout for the conenction to the ESDM server can be lowered by setting
the configuration option `client-timeout-exponent` is set to a value of,
for example, 22 which implies that after 4ms wait time the connection is
closed and reopened.

### Increase Scheduling Priority of ESDM Daemons

The following options can be added to the `systemd` unit files of
`esdm-cuse-random.service`, `esdm-cuse-urandom.service`, and/or
`esdm-server.service` which increase the scheduling priorities of those
daemons compared to other applications:

```
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=99
Nice=-20
```
## FIPS 140 Compliance

To ensure FIPS 140 compliance, enable the compile time option `fips140`.
In addition, the FIPS 140 mode must be enabled by either:

* Setting the environment variable `ESDM_SERVER_FORCE_FIPS`, or

* Booting the Linux kernel with the kernel command line option `fips=1`

This requires an HMAC file next to every component of the module. They hold the
reference values of the pre-operational integrity test, and the server refuses
to start without them - a missing reference value is a failed integrity test,
not a prompt to compute one over whatever is on disk.

The components are:

* the `esdm-server` executable,

* the ESDM library it loads, `libesdm.so.1`,

* the Jitter RNG, `libjitterentropy.so.3`, where the build uses it as an
  entropy source, and

* the library providing the cryptography where that is not the built-in
  implementation: `libcrypto.so` (OpenSSL), `libgnutls.so` together with
  `libnettle.so`, `libbotan-3.so` or `libleancrypto.so`.

The last two are attested wherever they are loaded from; the server names any
component whose reference value is missing, so starting it once tells you which
files still need one. Write them when the module is installed, over the files as
they were built:

```
esdm-tool --fips-targetfile /usr/bin/esdm-server \
          --fips-checkfile /usr/bin/.esdm-server.hmac
esdm-tool --fips-targetfile /usr/lib64/libesdm.so.1 \
          --fips-checkfile /usr/lib64/.libesdm.so.1.hmac
esdm-tool --fips-targetfile /usr/lib64/libjitterentropy.so.3 \
          --fips-checkfile /usr/lib64/.libjitterentropy.so.3.hmac
```

Use the library path the loader resolves - the SONAME (`libesdm.so.1`), not the
versioned file behind it - as that is the name the integrity test looks up. The
reference value has to sit in the same directory as the file it covers, so a
library in a read-only location has to receive it from whoever installs that
location. `esdm-tool` never overwrites an existing HMAC file, so remove the old
one when a component is updated.

## SP800-90C Compliance

When enabling the compile time option of either `fips140` or `sp80090c`,
the ESDM server operates compliant to SP800-90C right away when using the
interfaces that are documented to block until sufficient initial entropy
is present.

## AIS 20/31 (2024) Compliance

When enabling the compile time option of `ais2031_ntg1`, the ESDM server
operates NTG.1 compliant to AIS 20/31 (2024, version 3.0) right away when using
the interfaces that are documented to block until sufficient initial entropy
is present. Two entropy sources have to deliver 240 bits of entropy each before
a DRNG is considered fully seeded.

If the jitter RNG is operated in its own NTG.1 mode - the compile time option
`es_jent_ntg1` together with jitterentropy 3.7.0 or later providing secure
memory - then it is an NTG.1 conformant RNG by itself. In that case a second
entropy source adds nothing to the NTG.1 property and the ESDM server seeds
from the jitter RNG alone, once it delivered its 240 bits of entropy. The
requirement is bound to the jitter RNG: another entropy source delivering the
same amount of entropy does not replace it.

The compile time option of `ais2031_drg4` is independent of it and caps the
request size based reseeding limits to the values required by DRG.4.10 of the
same standard, i.e. a reseed is attempted after 2**16 output bits and the fully
seeded state is lost after 2**17 output bits without a successful reseed.

## AIS 20/31 (2011) Compliance

The ESDM server operates NTG.1 compliant to AIS 20/31 (2011 version)
right away when using one of the following interfaces:

* `esdm_get_random_bytes_pr` ESDM library interface,

* `esdm_rpcc_get_random_bytes_pr` ESDM RPC interface,

* open the CUSE daemon provided `/dev/random` or `/dev/urandom` with the flag
  `O_SYNC`

* request random numbers from the getrandom(2) system call ESDM replacement
  with the flag `GRND_RANDOM`

## SystemD-based Startup

To start up the different ESDM components with systemd, execute the following
commands:

1. Start server: `systemctl start esdm-server`

2. Enable server: `systemctl enable esdm-server`

3. Enable the suspend helper: `systemctl enable esdm-server-suspend`

4. Enable the resume helper: `systemctl enable esdm-server-resume`

5. Start the different clients: `systemctl start esdm-linux-compat.target`

6. Enable the different clients: `systemctl enable esdm-linux-compat.target`

7. Optional (if the esdm_es_irq kernel patch is applied and thus the kernel
   random number generator must be seeded from user space):
   `systemctl start esdm-kernel-seeder`

8. Optional (if step 7 identified that it needs to be started):
   `systemctl enable esdm-kernel-seeder`

Note, a pitfall may be the use of BtrFS where `/usr/local` is a separate
subvolume. The `esdm-server` wants to be invoked very early in the boot cycle
at a time the `/usr/local` is not yet mounted which leads to the situation that
the `esdm-server` is not started during boot. Thus, the `esdm-server` should
not be deployed on a BtrFS subvolumes.

In order to support systemd by default, the IPC path is set to `/run` as a preset.
If your system uses e.g. `/var/run` and no systemd, set instead:

```
   -Desdm-server-rpc-path-unprivileged=/var/run
   -Desdm-server-rpc-path-privileged=/var/run
```

In order to use systemd socket activation with esdm, compile esdm with `-Dsystemd=enabled` (default).

## EGD Compatibility Interface

The `esdm-server` can additionally serve the protocol of the Entropy Gathering
Daemon (EGD, `egd.pl` and its re-implementations like `prngd`). It allows
consumers which only know how to obtain entropy from an EGD - such as
libgcrypt built with `--enable-random=egd` or OpenSSL's `RAND_egd()` - to be
served by the ESDM without any modification.

The interface is disabled by default. It is enabled in either of two ways:

* With systemd, by starting the socket unit that carries it - this is the
  recommended way, as the unit defines the path and the access mode of the
  socket:

```
   systemctl enable --now esdm-server-egd.socket
   systemctl restart esdm-server
```

  The `esdm-server.service` is only ordered after that socket unit and does not
  require it, so the EGD interface stays off until the socket unit is started.
  Because the descriptor is handed over when the server starts, an already
  running `esdm-server` has to be restarted once after enabling the socket.
  The socket path is set at build time with
  `-Desdm-server-egd-socket-path=/run/esdm-egd.socket`.

* Without systemd, by naming the Unix domain socket on the command line:

```
   esdm-server --egd_socket /run/esdm-egd.socket
```

The socket carries access rights for all users - taken from the `SocketMode=`
of the socket unit, or set to 0666 for a socket bound by the server itself,
just like the unprivileged RPC socket. The operations reachable through it are
unprivileged as well:

* Obtaining random numbers is equivalent to what the unprivileged RPC
  interface offers.

* Data written by a caller with the EGD "write entropy" command is inserted
  into the auxiliary pool. The entropy claim the protocol allows the caller to
  attach to that data is only honored for a privileged (UID 0) caller - the
  data of an unprivileged caller is inserted without any entropy credit. This
  mirrors the rule of the RPC interface, where inserting data with an entropy
  claim is reserved for the privileged interface.

Note that the EGD protocol transfers data in the clear over the socket and
caps every single transfer at 255 bytes. It exists for compatibility with
legacy consumers - new applications should use the ESDM RPC interface, the
device files or `getrandom(2)`.

Point the consumers at the socket, e.g. for libgcrypt at build time with
`--with-egd-socket=/run/esdm-egd.socket` or at runtime with
`gcry_control(GCRYCTL_SET_RNDEGD_SOCKET, "/run/esdm-egd.socket")`.

### Own consumers of the EGD interface

Two components of the ESDM use the interface themselves, and both are useful
where the RPC interface cannot be reached - a chroot that can be given exactly
one socket, for instance:

* `libesdm_egd_client` (`esdm_egd_client.h`) is a small client library for the
  protocol. A client owns one connection, serializes the requests on it, bounds
  every wait, and reconnects on its own after a restart of the daemon or a
  `fork()` of the calling process.

* `libesdm-egd-provider.so` is an OpenSSL 3 RAND provider built on it. Unlike
  `libesdm-rng-provider.so` it needs no RPC client, and it tags its algorithms
  with `provider=esdm-egd` so both can be loaded side by side. Its counterpart
  `libesdm-egd-provider-pr.so` is served by the prediction resistance socket
  described below and tags its algorithms `provider=esdm-egd-pr`:

```
   [provider_sect]
   esdm_egd = esdm_egd_sect

   [esdm_egd_sect]
   activate = 1
   module = /usr/local/lib64/libesdm-egd-provider.so
   egd_socket = /run/esdm-egd.socket

   [random_sect]
   random = CTR-DRBG
   properties = provider=esdm-egd
   seed = SEED-SRC
   seed_properties = provider=esdm-egd
```

  Without the `egd_socket` key the socket is taken from the `ESDM_EGD_SOCKET`
  environment variable and, failing that, from the path the respective provider
  was built with.

### Prediction resistance

The EGD protocol has no notion of prediction resistance and therefore no way to
ask for it per request. It is a property of the socket instead: a second socket
answers every request from `esdm_get_random_bytes_pr()` rather than from
`esdm_get_random_bytes_full()`. Enable it with

```
   systemctl enable --now esdm-server-egd-pr.socket
```

or with `esdm-server --egd_socket_pr <path>`; its path is set at build time with
`-Desdm-server-egd-pr-socket-path=`. The two sockets are independent and either
can be enabled on its own.

Consequently the ordinary provider refuses a request that explicitly asks for
prediction resistance, rather than quietly serving it ordinary random data,
while `libesdm-egd-provider-pr.so` - which talks to the prediction resistance
socket - accepts it. Note that this generator hands out no more than the
entropy sources just produced, so answers take as long as collecting that
entropy does.

### Sandboxed consumers

The EGD interface reaches consumers that confine themselves after startup.
OpenSSH is the reference case: sshd hands the pre-authentication protocol,
including the key exchange, to a privilege separated child that re-execs itself
and is then confined by a seccomp filter which permits little more than `read`,
`write`, `poll`, `close` and `getpid` - `socket` and `connect` are answered with
`SECCOMP_RET_KILL`, as are `sendto` and `recvfrom`.

Pointing sshd at the EGD provider works because the client establishes its
connection when it is allocated, which happens while OpenSSL loads the provider
and therefore before the child confines itself, and because everything it does
afterwards stays within those permitted calls. Setting `OPENSSL_CONF` on the
`sshd` and `sshd-keygen` units is all it takes:

```
   systemd.services.sshd.environment.OPENSSL_CONF = "/etc/ssl/openssl-esdm-egd.cnf";
   systemd.services.sshd-keygen.environment.OPENSSL_CONF = "/etc/ssl/openssl-esdm-egd.cnf";
```

The corresponding check is `nix build .#checks.<system>.egd_openssh`.

The one thing such a consumer cannot do is reconnect: a process that has already
confined itself, or that forks after connecting, cannot open a new connection.
The client therefore reports a failure there rather than recovering from it,
whereas an unconfined consumer sees a restarted ESDM transparently.

## Additional Hardening Measures

The ESDM already executes with different execution domains and without any
privileges. Yet, the following measures may be taken to additionally harden
the setup:

* Create a separate unprivileged user ID only for the ESDM daemons. Then
start all ESDM daemons such that they switch to this user instead of the user
"nobody". The ESDM-specific user shall not be used by anyone else. This
special user first ensures that ESDM cannot access other "nobody" processes.
Vice versa, other "nobody" processes cannot access the ESDM resources, notably
the processes themselves (via ptrace(2)) as well as the IPC mechanisms used
for synchronization between the ESDM daemons (semaphore / shared memory
segment).
