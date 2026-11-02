/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * IOCTL interface of /dev/esdm_es
 *
 * The ABI between the kernel module esdm_es (kernel/esdm_es) and the
 * interrupt and scheduler entropy sources of the ESDM (esdm/esdm_es_irq.c,
 * esdm/esdm_es_sched.c), included by both.
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_IOCTL_H
#define _ESDM_ES_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define ESDMIO 0xE0

/*
 * The entropy buffer read by ESDM_IRQ_ENT_BUF / ESDM_SCHED_ENT_BUF holds the
 * seed size the module is built for, and its size is part of the IOCTL
 * number: the ESDM asks for the size with ESDM_*_ENT_BUF_SIZE and reads with
 * the IOCTL of the entropy buffer of that size, ESDM_*_ENT_BUF_IOCTL(type).
 */

/* IRQ ES: return available entropy */
#define ESDM_IRQ_AVAIL_ENTROPY _IOR(ESDMIO, 0x00, __u32)

/* IRQ ES: return size of entropy buffer struct and ES number */
#define ESDM_IRQ_ENT_BUF_SIZE _IOR(ESDMIO, 0x01, __u32[2])

/* IRQ ES: read entropy value into the entropy buffer @type */
#define ESDM_IRQ_ENT_BUF_IOCTL(type) _IOR(ESDMIO, 0x02, type)

/*
 * IRQ ES: configure the entropy source with two 32-bit words:
 *
 * 1. A bit field of
 *	ESDM_ES_MGR_RESET_BIT: reset the entropy source, discarding the events
 *	  it collected so far.
 *	ESDM_ES_MGR_REQ_BITS_MASK: the entropy in bits a read of the entropy
 *	  buffer asks for - 0 leaves it unchanged, any other value has to be
 *	  one of the seed sizes of esdm_seed_sizes.h:
 *	  ESDM_DRNG_SECURITY_STRENGTH_BITS, with ESDM_OVERSAMPLE_ES_BITS added
 *	  or not, or ESDM_DRNG_INIT_SEED_SIZE_BITS. The mask holds 511 at most.
 *	The other bits are ignored.
 * 2. The entropy rate: the number of events credited with 256 bits of
 *    entropy - 0 leaves it unchanged. The module keeps it from going below
 *    the rate it was loaded with, so it never credits more entropy than that;
 *    0xffffffff credits none.
 *
 * A requested entropy that is none of the seed sizes fails with -EINVAL
 * before anything is carried out, the reset included.
 *
 * The requested entropy and the entropy rate belong to the file descriptor
 * they are set on, which starts out with ESDM_DRNG_INIT_SEED_SIZE_BITS and the
 * rate the module was loaded with. The available entropy, the entropy buffer
 * and the status read on a descriptor follow its settings, whatever those of
 * other descriptors are. The events collected are shared by all descriptors:
 * what one of them reads is gone for the others, and the reset discards them
 * for every descriptor.
 */
#define ESDM_IRQ_CONF _IOW(ESDMIO, 0x03, __u32[2])

/* IRQ ES: read status information */
#define ESDM_IRQ_STATUS _IOR(ESDMIO, 0x04, char[250])

/* SCHED ES: return available entropy */
#define ESDM_SCHED_AVAIL_ENTROPY _IOR(ESDMIO, 0x05, __u32)

/* SCHED ES: return size of entropy buffer struct and ES number */
#define ESDM_SCHED_ENT_BUF_SIZE _IOR(ESDMIO, 0x06, __u32[2])

/* SCHED ES: read entropy value into the entropy buffer @type */
#define ESDM_SCHED_ENT_BUF_IOCTL(type) _IOR(ESDMIO, 0x07, type)

/*
 * SCHED ES: configure entropy source with the same protocol as
 * ESDM_IRQ_CONF
 */
#define ESDM_SCHED_CONF _IOW(ESDMIO, 0x08, __u32[2])

/* SCHED ES: read status information */
#define ESDM_SCHED_STATUS _IOR(ESDMIO, 0x09, char[250])

/*
 * IRQ / SCHED ES: read status information as a JSON object
 *
 * The returned document carries the same properties as the plain status text
 * of ESDM_IRQ_STATUS / ESDM_SCHED_STATUS with the labels turned into JSON
 * member names, so that the ESDM server can embed it in its JSON status
 * document without parsing text.
 */
#define ESDM_IRQ_STATUS_JSON _IOR(ESDMIO, 0x0a, char[500])
#define ESDM_SCHED_STATUS_JSON _IOR(ESDMIO, 0x0b, char[500])

/* Size of the buffer the JSON status IOCTLs report into */
#define ESDM_STATUS_JSON_BUFLEN 500

/* The bits of the first word of ESDM_IRQ_CONF / ESDM_SCHED_CONF */
/* low 9 bits - can request 511 bits of entropy at most */
#define ESDM_ES_MGR_REQ_BITS_MASK 0x1ff
#define ESDM_ES_MGR_RESET_BIT 0x80000000

#endif /* _ESDM_ES_IOCTL_H */
