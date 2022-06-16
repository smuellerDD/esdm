// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM entropy source manager and external interface
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/module.h>

#include "esdm_es_mgr_cb.h"
#include "esdm_es_mgr_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_testing.h"

static struct dentry *esdm_es_mgr_debugfs_root = NULL;

void esdm_reset_state(void)
{
        esdm_es_mgr_sched_reset();
        pr_debug("reset ESDM\n");
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

	ret = esdm_es_mgr_sched_init(esdm_es_mgr_debugfs_root);
	if (ret)
		goto outfs;

	ret = esdm_raw_init(esdm_es_mgr_debugfs_root);
	if (ret)
		goto outfs;

	return 0;

outfs:
	debugfs_remove_recursive(esdm_es_mgr_debugfs_root);
out:
	esdm_es_mgr_sched_exit();
	return ret;
}

static void __exit esdm_es_mgr_exit(void)
{
	debugfs_remove_recursive(esdm_es_mgr_debugfs_root);
	esdm_es_mgr_sched_exit();
}

module_init(esdm_es_mgr_init);
module_exit(esdm_es_mgr_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("ESDM entropy source manager");
