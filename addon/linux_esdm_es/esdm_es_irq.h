/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_IRQ_H
#define _ESDM_ES_IRQ_H

#include "esdm_es_mgr_cb.h"

int __init esdm_es_irq_module_init(void);

extern struct esdm_es_cb esdm_es_irq;

void __init esdm_irq_es_init(bool highres_timer);
void esdm_es_irq_module_exit(void);

#endif /* _ESDM_ES_IRQ_H */
