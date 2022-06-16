// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM entropy source manager and external interface
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/module.h>

#include "esdm_definitions.h"
#include "esdm_es_mgr_sched.h"
#include "esdm_es_sched.h"


static struct dentry *esdm_es_mgr_debugfs_sched_ent; /* .../entropy */
static struct dentry *esdm_es_mgr_debugfs_sched_stat; /* .../status */

static u32 esdm_requested_bits = ESDM_DRNG_INIT_SEED_SIZE_BITS;

/* Available entropy in the entire ESDM considering all entropy sources */
static u32 esdm_avail_entropy_sched(u32 requested_bits)
{
	return esdm_es_sched.curr_entropy(requested_bits);
}

static ssize_t esdm_es_mgr_sched_stat_read(struct file *file, char __user *buf,
					   size_t nbytes, loff_t *ppos)
{
	char status[250];
	int ret;

	memset(status, 0, sizeof(status));
	esdm_es_sched.state(status, sizeof(status));
	ret = simple_read_from_buffer(buf, nbytes, ppos, status,
				      sizeof(status));

	return ret;
}

/*
 * The following protocol is applied depending on the read size:
 *
 * 1. read size sizeof(u32): return available entropy
 * 2. read size 2*sizeof(u32): return size of entropy buffer struct and
 *    entropy source number
 * 3. read size sizeof(eb): entropy value
 */
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
	esdm_es_sched.get_ent(&eb, esdm_requested_bits);

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
		esdm_es_mgr_sched_reset();

	requested_bits = tmp & ESDM_ES_MGR_REQ_BITS_MASK;
	if (requested_bits == 0)
		return ret;

	if (requested_bits != ESDM_DRNG_INIT_SEED_SIZE_BITS &&
	    requested_bits != ESDM_DRNG_SECURITY_STRENGTH_BITS)
		return -EINVAL;

	esdm_requested_bits = requested_bits;
	return ret;
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

void esdm_es_mgr_sched_reset(void)
{
	esdm_es_sched.reset();
}

int __init esdm_es_mgr_sched_init(struct dentry *root)
{
	int ret = esdm_es_sched_module_init();

	if (ret)
		return ret;

	esdm_es_mgr_debugfs_sched_ent =
		debugfs_create_file("entropy_sched", 0600, root,
				    NULL, &esdm_es_mgr_sched_ent_fops);

	esdm_es_mgr_debugfs_sched_stat =
		debugfs_create_file("status_sched", 0600, root,
				    NULL, &esdm_es_mgr_sched_stat_fops);

	return 0;
}

void esdm_es_mgr_sched_exit(void)
{
	esdm_es_sched_module_exit();
}
