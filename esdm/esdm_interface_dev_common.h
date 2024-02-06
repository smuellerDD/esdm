/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_INTERFACE_DEV_COMMON_H
#define _ESDM_INTERFACE_DEV_COMMON_H

#include "config.h"

/******************* Upstream functions hooked into the ESDM ******************/
extern struct thread_wait_queue esdm_write_wait;

void esdm_writer_wakeup(void);

/************ Downstream functions used by interface implementations **********/
bool esdm_need_entropy(void);

#endif /* _ESDM_INTERFACE_DEV_COMMON_H */
