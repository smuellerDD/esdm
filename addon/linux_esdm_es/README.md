# Scheduler-based Entropy Source

The code in this directory provides the scheduler-based entropy source for
the Linux kernel. Porting of the code to other kernels is considered to
be feasible.

The root cause of the entropy that is used by the entropy source is the timing
of scheduling events. Every time the scheduler performs a context switch,
the high-resolution time stamp of that context switch is used as raw entropy
data.

This entropy source maintains a per-CPU entropy pool using SHA-512 which
is constantly updated with the raw entropy data. All raw entropy data is
always maintained in the entropy pool for the lifetime of this entropy source.
This implies that the entropy pools are operated with backtracking resistance.
Attackers of the entropy source must always attack the entropy source with
some code that will be scheduled. Therefore, attackers automatically alter
the raw entropy data compared to an undisturbed system. Therefore, attackers
have to overcome another challenge to defeat the entropy source compared to
others.

This code implements a fully SP800-90B compliant entropy source with health
tests applied in FIPS mode. In addition, it applies the SP800-90C oversampling
strategy for the conditioning component.

The entropy source is particularly lightweight in the performance critical
part of the context switching. It adds very minimal processing delay of a
couple of cycles.

## Installation

To use the entropy source, the kernel patch
`0001-ESDM-scheduler-entropy-source-hooks*.patch` must be applied and the Linux
kernel compiled. This patch adds a small framework that allows a kernel
module to be inserted into the kernel at runtime that will provide the
entropy source implementation.

The scheduler-based entropy source must be compiled by invoking `make`. This
generates a kernel module `esdm_es.ko` that can now be inserted into the
kernel at any time.

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
