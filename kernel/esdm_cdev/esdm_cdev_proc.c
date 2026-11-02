// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM character device frontend - /proc/esdm
 *
 * The ESDM's values of the files of the kernel's /proc/sys/kernel/random, as
 * the CUSE frontend's esdm-proc emulates them, plus the status of the ESDM.
 * boot_id and uuid are the kernel's alone, which has them:
 *
 *  entropy_avail		entropy of the ESDM's auxiliary pool in bits
 *  poolsize			size of that pool in bits
 *  write_wakeup_threshold	writable with CAP_SYS_ADMIN
 *  urandom_min_reseed_secs	writable with CAP_SYS_ADMIN
 *  status			the status report of the ESDM
 *  status.json			the status of the ESDM as JSON document
 *
 * Generated anew whenever a file is read from its start, as the kernel's
 * files are. While the ESDM cannot be reached, their reads fail as the reads
 * of /dev/esdm_urandom do.
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>

#include "esdm_cdev.h"

struct esdm_cdev_proc_file {
	const char *name;
	umode_t mode;
	int (*show)(struct seq_file *m, void *v);
	/* The command setting the value of a writable file */
	u8 set_cmd;
	/* The field of the state a file shows, see ESDM_EGD_STATE_* */
	unsigned int field;
	/* Status: as JSON document? */
	bool json;
};

static struct proc_dir_entry *esdm_cdev_proc_dir;

static int esdm_cdev_show_state(struct seq_file *m, void *v)
{
	const struct esdm_cdev_proc_file *file = m->private;
	u32 state[ESDM_EGD_STATE_NUM_FIELDS];
	int ret = esdm_cdev_egd_get_state(state);

	if (ret)
		return ret;

	seq_printf(m, "%u\n", state[file->field]);

	return 0;
}

static int esdm_cdev_show_status(struct seq_file *m, void *v)
{
	const struct esdm_cdev_proc_file *file = m->private;
	char *report;
	size_t len;
	int ret = esdm_cdev_egd_status(file->json, &report, &len);

	if (ret)
		return ret;

	seq_write(m, report, len);
	kvfree(report);

	return 0;
}

static const struct esdm_cdev_proc_file esdm_cdev_proc_files[] = {
	{
		.name = "entropy_avail",
		.mode = 0444,
		.show = esdm_cdev_show_state,
		.field = ESDM_EGD_STATE_ENT_CNT,
	},
	{
		.name = "poolsize",
		.mode = 0444,
		.show = esdm_cdev_show_state,
		.field = ESDM_EGD_STATE_POOLSIZE,
	},
	{
		.name = "write_wakeup_threshold",
		.mode = 0644,
		.show = esdm_cdev_show_state,
		.set_cmd = ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP,
		.field = ESDM_EGD_STATE_WRITE_WAKEUP,
	},
	{
		.name = "urandom_min_reseed_secs",
		.mode = 0644,
		.show = esdm_cdev_show_state,
		.set_cmd = ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS,
		.field = ESDM_EGD_STATE_MIN_RESEED_SECS,
	},
	{
		.name = "status",
		.mode = 0444,
		.show = esdm_cdev_show_status,
	},
	{
		.name = "status.json",
		.mode = 0444,
		.show = esdm_cdev_show_status,
		.json = true,
	},
};

static int esdm_cdev_proc_open(struct inode *inode, struct file *filp)
{
	const struct esdm_cdev_proc_file *file = pde_data(inode);

	/*
	 * A status report fits the seq_file buffer from the start: one that
	 * overflowed it would be asked for anew, with a larger one.
	 */
	return single_open_size(filp, file->show, (void *)file,
				file->show == esdm_cdev_show_status ?
					ESDM_EGD_MAX_STATUS + 1 :
					PAGE_SIZE);
}

/*
 * Set the value of write_wakeup_threshold or urandom_min_reseed_secs. The
 * kernel's files are root's to write; here the ESDM carries out what the
 * module sends as root, so the writer needs CAP_SYS_ADMIN, as for the
 * privileged ioctls. The value is parsed like the kernel's proc_dointvec():
 * a number, with a newline after it.
 */
static ssize_t esdm_cdev_proc_write(struct file *filp, const char __user *ubuf,
				    size_t count, loff_t *ppos)
{
	const struct esdm_cdev_proc_file *file = pde_data(file_inode(filp));
	u32 val;
	int ret;

	if (!file->set_cmd)
		return -EIO;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtou32_from_user(ubuf, count, 0, &val);
	if (ret)
		return ret;
	/* The value has to fit the 32 bit interface, as for esdm-proc */
	if (val == U32_MAX)
		return -ERANGE;

	ret = esdm_cdev_egd_priv(file->set_cmd, true, val);
	if (ret)
		return ret;

	return (ssize_t)count;
}

static const struct proc_ops esdm_cdev_proc_ops = {
	.proc_open = esdm_cdev_proc_open,
	.proc_read = seq_read,
	.proc_write = esdm_cdev_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int esdm_cdev_proc_init(void)
{
	unsigned int i;

	esdm_cdev_proc_dir = proc_mkdir("esdm", NULL);
	if (!esdm_cdev_proc_dir)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(esdm_cdev_proc_files); i++) {
		const struct esdm_cdev_proc_file *file =
			&esdm_cdev_proc_files[i];

		if (!proc_create_data(file->name, file->mode,
				      esdm_cdev_proc_dir, &esdm_cdev_proc_ops,
				      (void *)file)) {
			proc_remove(esdm_cdev_proc_dir);
			esdm_cdev_proc_dir = NULL;
			return -ENOMEM;
		}
	}

	return 0;
}

/* Waits for the files being opened, read or written */
void esdm_cdev_proc_fini(void)
{
	proc_remove(esdm_cdev_proc_dir);
	esdm_cdev_proc_dir = NULL;
}
