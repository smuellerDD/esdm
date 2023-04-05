// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM entropy source manager and external interface
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/module.h>

#include "esdm_es_mgr.h"
#include "esdm_es_mgr_cb.h"
#include "esdm_es_mgr_irq.h"
#include "esdm_es_mgr_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_testing.h"

/* Only panic the kernel on permanent health failure if this variable is true */
static bool esdm_panic_on_permanent_health_failure = false;
module_param(esdm_panic_on_permanent_health_failure, bool, 0444);
MODULE_PARM_DESC(esdm_panic_on_permanent_health_failure, "Panic on reaching permanent health failure - only required if ESDM is part of a FIPS 140-3 module\n");

static struct dentry *esdm_es_mgr_debugfs_root = NULL;

/********************************** Helper ***********************************/

bool esdm_enforce_panic_on_permanent_health_failure(void)
{
	return esdm_panic_on_permanent_health_failure;
}

void esdm_reset_state(enum esdm_internal_es es)
{
	if (es == esdm_int_es_irq)
		esdm_es_mgr_irq_reset();
	if (es == esdm_int_es_sched)
		esdm_es_mgr_sched_reset();
        pr_debug("reset ESDM ES %u\n", es);
}

/* Module init: allocate memory, register the debugfs files */
static int esdm_es_mgr_debugfs_init(void)
{
	esdm_es_mgr_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	return 0;
}

static int __init esdm_es_mgr_init(void)
{
	int ret = esdm_init_time_source();

	if (ret)
		goto out;

	ret = esdm_es_mgr_debugfs_init();
	if (ret)
		goto out;

	ret = esdm_es_mgr_irq_init(esdm_es_mgr_debugfs_root);
	if (ret)
		goto outfs;

	ret = esdm_es_mgr_sched_init(esdm_es_mgr_debugfs_root);
	if (ret)
		goto outfs;

	ret = esdm_test_init(esdm_es_mgr_debugfs_root);
	if (ret)
		goto outfs;

	return 0;

outfs:
	debugfs_remove_recursive(esdm_es_mgr_debugfs_root);
out:
	esdm_es_mgr_irq_exit();
	esdm_es_mgr_sched_exit();
	return ret;
}

static void __exit esdm_es_mgr_exit(void)
{
	debugfs_remove_recursive(esdm_es_mgr_debugfs_root);
	esdm_es_mgr_sched_exit();
	esdm_es_mgr_irq_exit();
}

module_init(esdm_es_mgr_init);
module_exit(esdm_es_mgr_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("ESDM entropy source manager");
