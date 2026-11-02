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

#ifndef _ESDM_ES_SCHED_H
#define _ESDM_ES_SCHED_H

#include <sys/types.h>

#include "config.h"
#include "esdm_es_ioctl.h"
#include "esdm_es_mgr_cb.h"

#ifdef ESDM_ES_SCHED

/* IOCTLs to interact with the kernel ESDM ES, see esdm_es_ioctl.h */

/* SCHED ES: read the entropy buffer of the size of the seed the module uses */
#define ESDM_SCHED_ENT_BUF ESDM_SCHED_ENT_BUF_IOCTL(struct entropy_es)
#define ESDM_SCHED_ENT_BUF_LARGE                                               \
	ESDM_SCHED_ENT_BUF_IOCTL(struct entropy_es_large)
#define ESDM_SCHED_ENT_BUF_SMALL                                               \
	ESDM_SCHED_ENT_BUF_IOCTL(struct entropy_es_small)

extern struct esdm_es_cb esdm_es_sched;

bool esdm_sched_enabled(void);

#else /* ESDM_ES_SCHED */

static inline bool esdm_sched_enabled(void)
{
	return false;
}

#endif /* ESDM_ES_SCHED */

#endif /* _ESDM_ES_SCHED_H */
