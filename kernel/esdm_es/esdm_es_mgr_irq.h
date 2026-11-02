/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 */

#ifndef _ESDM_ES_MGR_IRQ_H
#define _ESDM_ES_MGR_IRQ_H

#include "esdm_es_mgr_cb.h"

#ifdef ESDM_ES_IRQ

void esdm_es_mgr_irq_conf_init(struct esdm_es_conf *conf);
int esdm_es_mgr_irq_ioctl(unsigned int cmd, unsigned long arg,
			  struct esdm_es_conf *conf);
void esdm_es_mgr_irq_reset(void);
int __init esdm_es_mgr_irq_init(void);
void esdm_es_mgr_irq_exit(void);

#else /* ESDM_ES_IRQ */

static inline void esdm_es_mgr_irq_conf_init(struct esdm_es_conf *conf)
{
}

static inline int esdm_es_mgr_irq_ioctl(unsigned int cmd, unsigned long arg,
					struct esdm_es_conf *conf)
{
	return -ENOIOCTLCMD;
}

static inline void esdm_es_mgr_irq_reset(void)
{
}
static inline int __init esdm_es_mgr_irq_init(void)
{
	return 0;
}
static inline void esdm_es_mgr_irq_exit(void)
{
}

#endif /* ESDM_ES_IRQ */

#endif /* _ESDM_ES_MGR_IRQ_H */
