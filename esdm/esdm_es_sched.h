/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _ESDM_ES_SCHED_H
#define _ESDM_ES_SCHED_H

#include <linux/ioctl.h>
#include <sys/types.h>

#include "config.h"
#include "esdm_es_mgr_cb.h"

#ifdef ESDM_ES_SCHED

#define ESDMIO	0xE0

/* SCHED ES: return available entropy */
#define ESDM_SCHED_AVAIL_ENTROPY	_IOR(ESDMIO, 0x05, uint32_t )

/* SCHED ES: return size of entropy buffer struct and ES number */
#define ESDM_SCHED_ENT_BUF_SIZE		_IOR(ESDMIO, 0x06, uint32_t [2] )

/* SCHED ES: read size sizeof(eb): entropy value */
#define ESDM_SCHED_ENT_BUF		_IOR(ESDMIO, 0x07, struct entropy_es )

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
#define ESDM_SCHED_CONF			_IOW(ESDMIO, 0x08, uint32_t [2] )

/* SCHED ES: read status information */
#define ESDM_SCHED_STATUS		_IOR(ESDMIO, 0x09, char [250] )

extern struct esdm_es_cb esdm_es_sched;

bool esdm_sched_enabled(void);

#else /* ESDM_ES_SCHED */

static inline bool esdm_sched_enabled(void)
{
	return false;
}

#endif /* ESDM_ES_SCHED */

#endif /* _ESDM_ES_SCHED_H */
