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

## AIS 20/31 (2022) Compliance

When enabling the compile time option either `ais2031`, the ESDM server
operates NTG.1 compliant to AIS 20/31 (2022 draft version) right away when using
the interfaces that are documented to block until sufficient initial entropy
is present.

## AIS 20/31 (2011) Compliance

The ESDM server operates NTG.1 compliant to AIS 20/31 (2022 draft version)
right away when using one of the following interfaces:

* `esdm_get_random_bytes_pr` ESDM library interface,

* `esdm_rpcc_get_random_bytes_pr` ESDM RPC interface,

* open the CUSE daemon provided `/dev/random` or `/dev/urandom` with the flag
  `O_SYNC`

* request random numbers from the getrandom(2) system call ESDM replacement
  with the flag `GRND_RANDOM`
