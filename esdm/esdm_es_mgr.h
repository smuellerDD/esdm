/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_MGR_H
#define _ESDM_ES_MGR_H

#include "bool.h"
#include "esdm_es_mgr_cb.h"

/*************************** General ESDM parameter ***************************/

#define ESDM_DRNG_BLOCKSIZE 64		/* Maximum of DRNG block sizes */

/* Helper to concatenate a macro with an integer type */
#define ESDM_PASTER(x, y) x ## y
#define ESDM_UINT32_C(x) ESDM_PASTER(x, U)

/************************* Entropy sources management *************************/

extern struct esdm_es_cb *esdm_es[];

#define for_each_esdm_es(ctr)		\
	for ((ctr) = 0; (ctr) < esdm_ext_es_last; (ctr)++)

bool esdm_state_min_seeded(void);
void esdm_debug_report_seedlevel(const char *name);

extern uint32_t esdm_write_wakeup_bits;
void esdm_set_entropy_thresh(uint32_t new);
void esdm_reset_state(void);

int esdm_pool_trylock(void);
void esdm_pool_lock(void);
void esdm_pool_unlock(void);
void esdm_pool_all_nodes_seeded(bool set);
bool esdm_pool_all_nodes_seeded_get(void);

bool esdm_fully_seeded(bool fully_seeded, uint32_t collected_entropy,
		       struct entropy_buf *eb);
uint32_t esdm_entropy_rate_eb(struct entropy_buf *eb);
void esdm_unset_fully_seeded(struct esdm_drng *drng);
void esdm_fill_seed_buffer(struct entropy_buf *eb, uint32_t requested_bits,
			   bool force);
void esdm_init_ops(struct entropy_buf *eb);

int esdm_es_mgr_reinitialize(void);
int esdm_es_mgr_initialize(void);
int esdm_es_mgr_monitor_initialize(void(*priv_init_completion)(void));
void esdm_es_mgr_finalize(void);

#endif /* _ESDM_ES_MGR_H */
