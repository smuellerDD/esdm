/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 */

#ifndef _ESDM_ES_MGR_SCHED_H
#define _ESDM_ES_MGR_SCHED_H

#include "esdm_es_mgr_cb.h"

#ifdef ESDM_ES_SCHED

void esdm_es_mgr_sched_conf_init(struct esdm_es_conf *conf);
int esdm_es_mgr_sched_ioctl(unsigned int cmd, unsigned long arg,
			    struct esdm_es_conf *conf);
void esdm_es_mgr_sched_reset(void);
int __init esdm_es_mgr_sched_init(void);
void esdm_es_mgr_sched_exit(void);

#else /* ESDM_ES_SCHED */

static inline void esdm_es_mgr_sched_conf_init(struct esdm_es_conf *conf)
{
}

static inline int esdm_es_mgr_sched_ioctl(unsigned int cmd, unsigned long arg,
					  struct esdm_es_conf *conf)
{
	return -ENOIOCTLCMD;
}

static inline void esdm_es_mgr_sched_reset(void)
{
}
static inline int __init esdm_es_mgr_sched_init(void)
{
	return 0;
}
static inline void esdm_es_mgr_sched_exit(void)
{
}

#endif /* ESDM_ES_SCHED */

#endif /* _ESDM_ES_MGR_SCHED_H */
