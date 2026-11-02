# Scheduler-based Entropy Source

The code in this directory provides the scheduler-based as well as the
interrupt-based entropy source for the Linux kernel. Porting of the code to
other kernels is considered to be feasible.

The root cause of the entropy that is used by the entropy source is the timing
of scheduling events as well as interrupt events. Every time the scheduler
wakes up a task, the high-resolution time stamp of that wakeup is used as raw
entropy data - the hook of the scheduler patch sits in `ttwu_stat()`, which
`try_to_wake_up()` calls for every wakeup, not in the context switch.
Similarly, every time an interrupt is received, its high-resolution time stamp
is used as raw entropy.

Yet, if both entropy sources are enabled at the same time, the interrupt-based
entropy source is always credited with zero bits of entropy, because both
entropy sources show a dependency because a scheduling event may also cause
an interrupt event at the same time.

Each entropy source collects the time stamps in a per-CPU ring of events.
When the ESDM asks for entropy, the events collected so far are taken from the
rings and seed an internal DRBG of the entropy source, whose output is the
seed handed to the ESDM. The rings hold the events only until then: a full
ring drops further events until the next request takes them, and a reset of
the entropy source - for a health test failure, a reboot, a power management
transition, a fork of the virtual machine or on request of the ESDM - discards
them. What the DRBG
absorbed stays in its state and goes into all of its later output, and the
DRBG provides the backtracking resistance.
Attackers of the entropy source must always attack the entropy source with
some code that will be scheduled. Therefore, attackers automatically alter
the raw entropy data compared to an undisturbed system. Therefore, attackers
have to overcome another challenge to defeat the entropy source compared to
others.

This code implements a fully SP800-90B compliant entropy source with health
tests applied in FIPS mode. In addition, it applies the SP800-90C oversampling
strategy for the conditioning component.

The entropy source is particularly lightweight in the performance critical
part of the task wakeup and of the interrupt handling. It adds very minimal
processing delay of a couple of cycles.

Both entropy sources need a high-resolution timer: without one, the module
does not load. A timer found too coarse once the module runs - by the greatest
common divisor of its time stamps - stops the crediting of entropy.

## Installation

To use the entropy source, the following kernel patches must be applied
- `0001-ESDM-scheduler-entropy-source-hooks*.patch`
- `0002-ESDM-interrupt-entropy-source-hooks*.patch`
- `0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM*.patch`
  (only for kernels without the SHA-3 library, i.e. without
  `CONFIG_CRYPTO_LIB_SHA3`, up to Linux 7.1: the module uses the kernel's
  HMAC_DRBG there; with the SHA-3 library it uses the XDRBG-256 of the ESDM
  over the kernel's SHAKE256, which Linux 7.2 and later require, e.g. by
  `CONFIG_CRYPTO_SHA3`)
and the Linux kernel compiled. Use the patch suffixed with the highest kernel
version not newer than the target kernel (hooks: `_6.1`, `_6.6`, `_6.12`,
`_6.18`, `_7.3`, the `_6.18` hooks apply up to 7.2; DRBG: `_6.6` for 6.1 to
6.11, `_6.12` for 6.12, `_6.18` for 6.13 to 7.1). Linux 6.1 is the oldest
supported kernel; `kernelPatches.nix` holds the exact mapping. The patches
export their symbols GPL-only in the `ESDM` symbol namespace.
This patch adds a small framework that allows a kernel
module to be inserted into the kernel at runtime that will provide the
entropy source implementation.

Both entropy sources must be compiled by invoking `make` in this directory of
the ESDM source tree: the module shares code with the ESDM, which it takes from
the tree - the IOCTL interface of `/dev/esdm_es` and the cutoffs of the health
tests in `kernel/shared`, and the XDRBG-256 of `esdm/crypto/esdm_xdrbg.c`.
Specific options can be set in the corresponding `Makefile` allowing
selectively disabling either entropy source. This generates a kernel module
`esdm_es.ko` that can now be inserted into the kernel at any time.

## Usage

It is strongly advised to insert the kernel mode as early as possible into the
boot cycle of the operating system. For example, the kernel module can be
loaded in the initramfs-phase of the boot process. The reason for this is
that the boot process creates many processes which will create a lot of
entropy.

The scheduler-based entropy source is intended to be used by the ESDM. Ensure
that the kernel module is loaded before the `esdm-server` is started to
ensure the ESDM uses this entropy source.

# Author

Stephan Müller <smueller@chronox.de>
