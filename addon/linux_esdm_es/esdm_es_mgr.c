// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM entropy source manager and external interface
 *
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/version.h>

#include "esdm_es_ioctl.h"
#include "esdm_es_mgr.h"
#include "esdm_es_mgr_cb.h"
#include "esdm_es_mgr_irq.h"
#include "esdm_es_mgr_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_drbg_kcapi.h"
#include "esdm_testing.h"

/* Only panic the kernel on permanent health failure if this variable is true */
static bool esdm_panic_on_permanent_health_failure = false;
module_param(esdm_panic_on_permanent_health_failure, bool, 0444);
MODULE_PARM_DESC(
	esdm_panic_on_permanent_health_failure,
	"Panic on reaching permanent health failure - only required if ESDM is part of a FIPS 140-3 module\n");

static int esdm_major = 0;
module_param(esdm_major, int, 0);
MODULE_PARM_DESC(esdm_major, "ESDM major device number");
#define ESDM_MAX_MINORS 2

static struct class *esdm_es_class;
static struct cdev esdm_cdev;
static DEFINE_MUTEX(esdm_cdev_lock);

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

/* Module init: allocate memory, register the device file */
static int esdm_cdev_open(struct inode *inode, struct file *file)
{
	unsigned m = iminor(inode);
	/* optionally set file->private_data here */

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (m >= ESDM_MAX_MINORS)
		return -EINVAL;
	return nonseekable_open(inode, file);
}

static int esdm_cdev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long esdm_cdev_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	int ret = -ENODEV;

	/*
	 * All IOCTLs are allowed without restriction. However, the device
	 * node can only be opened with CAP_SYS_ADMIN. This allows the
	 * restriction of the access to the IOCTLs to root, but the calling
	 * service can drop its privileges after opening the device.
	 */

	mutex_lock(&esdm_cdev_lock);

	switch (cmd) {
	case ESDM_IRQ_AVAIL_ENTROPY:
	case ESDM_IRQ_ENT_BUF_SIZE:
	case ESDM_IRQ_ENT_BUF:
	case ESDM_IRQ_CONF:
	case ESDM_IRQ_STATUS:
		ret = esdm_es_mgr_irq_ioctl(cmd, arg);
		break;
	case ESDM_SCHED_AVAIL_ENTROPY:
	case ESDM_SCHED_ENT_BUF_SIZE:
	case ESDM_SCHED_ENT_BUF:
	case ESDM_SCHED_CONF:
	case ESDM_SCHED_STATUS:
		ret = esdm_es_mgr_sched_ioctl(cmd, arg);
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	mutex_unlock(&esdm_cdev_lock);
	return ret;
}

static const struct file_operations esdm_cdev_fops = {
	.owner = THIS_MODULE,
	.open = esdm_cdev_open,
	.release = esdm_cdev_release,
	.unlocked_ioctl = esdm_cdev_ioctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
	.llseek = no_llseek,
#endif
};

static int __init esdm_es_mgr_dev_init(void)
{
	dev_t dev;
	struct device *device;
	int ret;

	/* make creation of all devices atomic */
	mutex_lock(&esdm_cdev_lock);

	esdm_es_class = class_create(
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
		THIS_MODULE,
#endif
		KBUILD_MODNAME);
	if (IS_ERR(esdm_es_class)) {
		mutex_unlock(&esdm_cdev_lock);
		return PTR_ERR(esdm_es_class);
	}

	if (esdm_major) {
		dev = MKDEV(esdm_major, 0);
		ret = register_chrdev_region(dev, ESDM_MAX_MINORS,
					     KBUILD_MODNAME);
	} else {
		ret = alloc_chrdev_region(&dev, 0, ESDM_MAX_MINORS,
					  KBUILD_MODNAME);
		esdm_major = MAJOR(dev);
	}

	if (ret < 0) {
		pr_warn("ESDM cdev class allocation failed\n");
		goto err;
	}

	cdev_init(&esdm_cdev, &esdm_cdev_fops);
	ret = cdev_add(&esdm_cdev, dev, ESDM_MAX_MINORS);
	if (ret < 0) {
		pr_warn("ESDM cdev creation failed\n");
		goto err_cdev;
	}

	device = device_create(esdm_es_class, NULL, dev, NULL, KBUILD_MODNAME);
	if (IS_ERR(device)) {
		pr_warn("ESDM cdev /sys allocation failed\n");
		ret = PTR_ERR(device);
		goto err_cdev;
	}

	mutex_unlock(&esdm_cdev_lock);

	pr_info("ESDM user space interface available (major number %u)\n",
		esdm_major);

	return 0;

err_cdev:
	cdev_del(&esdm_cdev);
	unregister_chrdev_region(MKDEV(esdm_major, 0), ESDM_MAX_MINORS);
err:
	class_destroy(esdm_es_class);
	mutex_unlock(&esdm_cdev_lock);
	return ret;
}

static void __exit esdm_es_mgr_dev_fini(void)
{
	mutex_lock(&esdm_cdev_lock);

	device_destroy(esdm_es_class, MKDEV(esdm_major, 0));

	cdev_del(&esdm_cdev);

	unregister_chrdev_region(MKDEV(esdm_major, 0), ESDM_MAX_MINORS);
	class_destroy(esdm_es_class);

	mutex_unlock(&esdm_cdev_lock);

	pr_info("ESDM user space interface unavailable\n");
}

static int __init esdm_es_mgr_init(void)
{
	int ret = esdm_init_time_source();
	if (ret) {
		pr_warn("esdm_init_time_source() failed\n");
		goto out;
	}

	ret = esdm_drbg_selftest();
	if (ret) {
		pr_warn("esdm_drbg_selftest() failed\n");
		goto out;
	}

	ret = esdm_es_mgr_irq_init();
	if (ret) {
		pr_warn("esdm_es_mgr_irq_init() failed\n");
		goto out;
	}

	ret = esdm_es_mgr_sched_init();
	if (ret) {
		pr_warn("esdm_es_mgr_sched_init() failed\n");
		goto out;
	}

	ret = esdm_test_init();
	if (ret) {
		pr_warn("esdm_test_init() failed\n");
		goto out;
	}

	ret = esdm_es_mgr_dev_init();
	if (ret) {
		pr_warn("esdm_es_mgr_dev_init() failed\n");
		goto out;
	}

	return 0;

out:
	esdm_es_mgr_irq_exit();
	esdm_es_mgr_sched_exit();
	return ret;
}

static void __exit esdm_es_mgr_exit(void)
{
	esdm_es_mgr_dev_fini();
	esdm_test_exit();
	esdm_es_mgr_sched_exit();
	esdm_es_mgr_irq_exit();
}

module_init(esdm_es_mgr_init);
module_exit(esdm_es_mgr_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("ESDM entropy source manager");
