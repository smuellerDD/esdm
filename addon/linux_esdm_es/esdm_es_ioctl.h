/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_IOCTL_H
#define _ESDM_ES_IOCTL_H

#include <linux/ioctl.h>

#include "esdm_es_mgr_cb.h"

#define ESDMIO	0xE0
/* IRQ ES: return available entropy */
#define ESDM_IRQ_AVAIL_ENTROPY		_IOR(ESDMIO, 0x00, u32 )

/* IRQ ES: return size of entropy buffer struct and ES number */
#define ESDM_IRQ_ENT_BUF_SIZE		_IOR(ESDMIO, 0x01, u32 [2] )

/* IRQ ES: read entropy value */
#define ESDM_IRQ_ENT_BUF		_IOR(ESDMIO, 0x02, struct entropy_buf )

/*
 * IRQ ES: configure entropy source with the following protocol
 *
 * 1. When writing 2 * sizeof(u32): the first 4 bits are interpreted as a bit
 *    field with:
 * 	ESDM_ES_MGR_RESET_BIT set -> reset entropy source
 * 	ESDM_ES_MGR_REQ_BITS_MASK: amount of requested entropy in bits
 *    The second 4 bits are interpreted as entropy rate.
 *
 * Any other value is treated as an error.
 */
#define ESDM_IRQ_CONF			_IOW(ESDMIO, 0x03, u32 [2] )

/* IRQ ES: read status information */
#define ESDM_IRQ_STATUS			_IOR(ESDMIO, 0x04, char [250] )

/* SCHED ES: return available entropy */
#define ESDM_SCHED_AVAIL_ENTROPY	_IOR(ESDMIO, 0x05, u32 )

/* SCHED ES: return size of entropy buffer struct and ES number */
#define ESDM_SCHED_ENT_BUF_SIZE		_IOR(ESDMIO, 0x06, u32 [2] )

/* SCHED ES: read entropy value */
#define ESDM_SCHED_ENT_BUF		_IOR(ESDMIO, 0x07, struct entropy_buf )

/*
 * SCHED ES: configure entropy source with the following protocol
 *
 * 1. When writing 2 * sizeof(u32): the first 4 bits are interpreted as a bit
 *    field with:
 * 	ESDM_ES_MGR_RESET_BIT set -> reset entropy source
 * 	ESDM_ES_MGR_REQ_BITS_MASK: amount of requested entropy in bits
 *    The second 4 bits are interpreted as entropy rate.
 *
 * Any other value is treated as an error.
 */
#define ESDM_SCHED_CONF			_IOW(ESDMIO, 0x08, u32 [2] )

/* SCHED ES: read status information */
#define ESDM_SCHED_STATUS		_IOR(ESDMIO, 0x09, char [250] )

#endif /* _ESDM_ES_IOCTL_H */
