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

This requires the `fipscheck` HMAC file to be in place.

## SP800-90C Compliance

When enabling the compile time option of either `fips140` or `sp80090c`,
the ESDM server operates compliant to SP800-90C right away when using the
interfaces that are documented to block until sufficient initial entropy
is present.

## AIS 20/31 (2024) Compliance

When enabling the compile time option of `ais2031`, the ESDM server
operates NTG.1 compliant to AIS 20/31 (2024, version 3.0) right away when using
the interfaces that are documented to block until sufficient initial entropy
is present.

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

5. Enable the different clients: `systemctl enable esdm-linux-compat.target`

Note, a pitfall may be the use of BtrFS where `/usr/local` is a separate
subvolume. The `esdm-server` wants to be invoked very early in the boot cycle
at a time the `/usr/local` is not yet mounted which leads to the situation that
the `esdm-server` is not started during boot. Thus, the `esdm-server` should
not be deployed on a BtrFS subvolumes.

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
