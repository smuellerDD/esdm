/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <sys/types.h>

#include "config.h"
#include "esdm_es_ioctl.h"
#include "esdm_es_mgr_cb.h"

/*
 * The presence of the interrupt entropy source implies that the main
 * entropy source of the kernel random.c is being taken away. Yet, we may
 * have some entropy. Thus, we apply a safe assumption that we could get
 * at least the given amount of bits of entropy from the kernel RNG.
 */
#define ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY 4

#ifdef ESDM_ES_IRQ

/* IOCTLs to interact with the kernel ESDM ES, see esdm_es_ioctl.h */

/* IRQ ES: read the entropy buffer of the size of the seed the module uses */
#define ESDM_IRQ_ENT_BUF ESDM_IRQ_ENT_BUF_IOCTL(struct entropy_es)
#define ESDM_IRQ_ENT_BUF_LARGE ESDM_IRQ_ENT_BUF_IOCTL(struct entropy_es_large)
#define ESDM_IRQ_ENT_BUF_SMALL ESDM_IRQ_ENT_BUF_IOCTL(struct entropy_es_small)

bool esdm_irq_enabled(void);
extern struct esdm_es_cb esdm_es_irq;

#else /* ESDM_ES_IRQ */

static inline bool esdm_irq_enabled(void)
{
	return false;
}

#endif /* ESDM_ES_IRQ */

#endif /* _ESDM_ES_IRQ_H */
