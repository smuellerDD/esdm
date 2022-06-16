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
#include "esdm_es_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_testing.h"

/* The entries must be in the same order as defined by enum esdm_internal_es */
struct esdm_es_cb *esdm_es[] = {
	&esdm_es_sched,
};

/*
 * This data structure holds the dentry's of the debugfs files establishing
 * the interface to user space.
 */
struct esdm_es_mgr_debugfs {
	struct dentry *esdm_es_mgr_debugfs_root; /* root dentry */
	struct dentry *esdm_es_mgr_debugfs_ent; /* .../entropy */
	struct dentry *esdm_es_mgr_debugfs_stat; /* .../status */
};

static struct esdm_es_mgr_debugfs esdm_es_mgr_debugfs;
static u32 esdm_requested_bits = ESDM_DRNG_INIT_SEED_SIZE_BITS;

void esdm_reset_state(void)
{
        u32 i;

        for (i = 0; i < esdm_int_es_last; i++) {
		if (esdm_es[i]->reset)
			esdm_es[i]->reset();
        }
        pr_debug("reset ESDM\n");
}

/* Available entropy in the entire ESDM considering all entropy sources */
static u32 esdm_avail_entropy_sched(u32 requested_bits)
{
	return esdm_es[esdm_int_es_sched]->curr_entropy(requested_bits);
}


static ssize_t esdm_es_mgr_sched_stat_read(struct file *file, char __user *buf,
					   size_t nbytes, loff_t *ppos)
{
	char status[250];
	int ret;

	memset(status, 0, sizeof(status));
	esdm_es[esdm_int_es_sched]->state(status, sizeof(status));
	ret = simple_read_from_buffer(buf, nbytes, ppos, status,
				      sizeof(status));

	return ret;
}

static ssize_t esdm_es_mgr_sched_ent_read(struct file *file, char __user *buf,
					  size_t nbytes, loff_t *ppos)
{
	struct entropy_buf eb __aligned(ESDM_KCAPI_ALIGN);
	int ret;

	if (nbytes == sizeof(u32)) {
		/* Return entropy level */
		u32 entropy = esdm_avail_entropy_sched(esdm_requested_bits);

		return simple_read_from_buffer(buf, nbytes, ppos, &entropy,
					       sizeof(entropy));
	} else if (nbytes == 2 * sizeof(u32)) {
		/* Return size of buffer */
		u32 retbuf[2];

		retbuf[0] = sizeof(eb);
		retbuf[1] = esdm_int_es_sched;

		return simple_read_from_buffer(buf, nbytes, ppos, retbuf,
					       sizeof(retbuf));

	} else if (nbytes != sizeof(eb))
		return -EINVAL;

	memset(&eb, 0, sizeof(eb));
	esdm_es[esdm_int_es_sched]->get_ent(&eb, esdm_requested_bits);

	ret = simple_read_from_buffer(buf, nbytes, ppos, (void *)&eb,
				      sizeof(eb));

	memzero_explicit(&eb, sizeof(eb));
	return ret;
}

/* low 9 bits - can set 512 bits of entropy max */
#define ESDM_ES_MGR_REQ_BITS_MASK	0x1ff
#define ESDM_ES_MGR_RESET_BIT		0x10000

static ssize_t esdm_es_mgr_sched_ent_write(struct file *file,
					   const char __user *buf,
					   size_t nbytes, loff_t *ppos)
{
	u32 tmp, requested_bits;
	ssize_t ret;

	if (nbytes != sizeof(esdm_requested_bits))
		return -EINVAL;

	ret = simple_write_to_buffer(&tmp, sizeof(tmp), ppos, buf, nbytes);
	if (ret < 0)
		return ret;
	if (ret != sizeof(tmp))
		return -EFAULT;

	if (tmp & ESDM_ES_MGR_RESET_BIT)
		esdm_es[esdm_int_es_sched]->reset();

	requested_bits = tmp & ESDM_ES_MGR_REQ_BITS_MASK;
	if (requested_bits == 0)
		return ret;

	if (requested_bits != ESDM_DRNG_INIT_SEED_SIZE_BITS &&
	    requested_bits != ESDM_DRNG_SECURITY_STRENGTH_BITS)
		return -EINVAL;

	esdm_requested_bits = requested_bits;
	return ret;
}

/* Module init: allocate memory, register the debugfs files */
static int esdm_es_mgr_debugfs_init(void)
{
	esdm_es_mgr_debugfs.esdm_es_mgr_debugfs_root =
		debugfs_create_dir(KBUILD_MODNAME, NULL);
	return 0;
}

static struct file_operations esdm_es_mgr_sched_ent_fops = {
	.owner = THIS_MODULE,
	.read = esdm_es_mgr_sched_ent_read,
	.write = esdm_es_mgr_sched_ent_write,
	.llseek = default_llseek,
};

static struct file_operations esdm_es_mgr_sched_stat_fops = {
	.owner = THIS_MODULE,
	.read = esdm_es_mgr_sched_stat_read,
};

static int esdm_es_mgr_debugfs_init_ent(void)
{
	esdm_es_mgr_debugfs.esdm_es_mgr_debugfs_ent =
	debugfs_create_file("entropy_sched", 0600,
			    esdm_es_mgr_debugfs.esdm_es_mgr_debugfs_root,
			    NULL, &esdm_es_mgr_sched_ent_fops);

	esdm_es_mgr_debugfs.esdm_es_mgr_debugfs_stat =
	debugfs_create_file("status_sched", 0600,
			    esdm_es_mgr_debugfs.esdm_es_mgr_debugfs_root,
			    NULL, &esdm_es_mgr_sched_stat_fops);

	return 0;
}

static int __init esdm_es_mgr_init(void)
{
	int ret = esdm_es_sched_module_init();

	if (ret)
		return ret;

	ret = esdm_init_time_source();
	if (ret)
		goto out;

	ret = esdm_es_mgr_debugfs_init();
	if (ret)
		goto out;

	ret = esdm_es_mgr_debugfs_init_ent();
	if (ret)
		goto outfs;

	ret = esdm_raw_init(esdm_es_mgr_debugfs.esdm_es_mgr_debugfs_root);
	if (ret)
		goto outfs;

	return 0;

outfs:
	debugfs_remove_recursive(esdm_es_mgr_debugfs.esdm_es_mgr_debugfs_root);
out:
	esdm_es_sched_module_exit();
	return ret;
}

static void __exit esdm_es_mgr_exit(void)
{
	debugfs_remove_recursive(esdm_es_mgr_debugfs.esdm_es_mgr_debugfs_root);
	esdm_es_sched_module_exit();
}

module_init(esdm_es_mgr_init);
module_exit(esdm_es_mgr_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("ESDM entropy source manager");

