/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 *
 */

#ifndef _ESDM_ES_MGR_SCHED_H
#define _ESDM_ES_MGR_SCHED_H

#ifdef ESDM_ES_SCHED

void esdm_es_mgr_sched_reset(void);
int __init esdm_es_mgr_sched_init(struct dentry *root);
void esdm_es_mgr_sched_exit(void);

#else /* ESDM_ES_SCHED */

static inline void esdm_es_mgr_sched_reset(void) { }

static inline int __init esdm_es_mgr_sched_init(struct dentry *root)
{
	return 0;
};

static inline void esdm_es_mgr_sched_exit(void) { }

#endif /* ESDM_ES_SCHED */

#endif /* _ESDM_ES_MGR_SCHED_H */
