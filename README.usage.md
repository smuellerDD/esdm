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
