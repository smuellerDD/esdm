/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef _ESDM_ES_IRQ_H
#define _ESDM_ES_IRQ_H

#include <linux/ioctl.h>
#include <sys/types.h>

#include "config.h"
#include "esdm_es_mgr_cb.h"

/*
 * The presence of the interrupt entropy source implies that the main
 * entropy source of the kernel random.c is being taken away. Yet, we may
 * have some entropy. Thus, we apply a safe assumption that we could get
 * at least the given amount of bits of entropy from the kernel RNG.
 */
#define ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY 4

#ifdef ESDM_ES_IRQ

#define ESDMIO 0xE0

/* IOCTLs to interact with the kernel ESDM ES */

/* IRQ ES: return available entropy */
#define ESDM_IRQ_AVAIL_ENTROPY _IOR(ESDMIO, 0x00, uint32_t)

/* IRQ ES: return size of entropy buffer struct and ES number */
#define ESDM_IRQ_ENT_BUF_SIZE _IOR(ESDMIO, 0x01, uint32_t[2])

/* IRQ ES: read size sizeof(eb): entropy value */
#define ESDM_IRQ_ENT_BUF _IOR(ESDMIO, 0x02, struct entropy_es)
#define ESDM_IRQ_ENT_BUF_LARGE _IOR(ESDMIO, 0x02, struct entropy_es_large)
#define ESDM_IRQ_ENT_BUF_SMALL _IOR(ESDMIO, 0x02, struct entropy_es_small)

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
#define ESDM_IRQ_CONF _IOW(ESDMIO, 0x03, uint32_t[2])

/* IRQ ES: read status information */
#define ESDM_IRQ_STATUS _IOR(ESDMIO, 0x04, char[250])

bool esdm_irq_enabled(void);
extern struct esdm_es_cb esdm_es_irq;

#else /* ESDM_ES_IRQ */

static inline bool esdm_irq_enabled(void)
{
	return false;
}

#endif /* ESDM_ES_IRQ */

#endif /* _ESDM_ES_IRQ_H */
