// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM entropy source manager and external interface
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/random.h>
#include <linux/suspend.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "esdm_es_ioctl.h"
#include "esdm_es_mgr.h"
#include "esdm_es_mgr_cb.h"
#include "esdm_es_mgr_irq.h"
#include "esdm_es_mgr_sched.h"
#include "esdm_es_timer_common.h"
#include "esdm_health.h"
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

/*
 * No printk here: the health tests reset from the hot path, where the
 * deferred health-test messages already report it.
 */
void esdm_reset_state(enum esdm_internal_es es)
{
	if (es == esdm_int_es_irq)
		esdm_es_mgr_irq_reset();
	if (es == esdm_int_es_sched)
		esdm_es_mgr_sched_reset();
}

/*
 * The configuration of the entropy sources a descriptor of the device holds,
 * its file->private_data. The requested entropy and the entropy rate belong to
 * the ESDM that sets them: one ESDM crediting a source with nothing - as the
 * ESDM does with the scheduler ES by default - must not have the source deliver
 * nothing to another ESDM crediting it, nor have it credited for another one
 * that does not. The events the sources collected are one pool all the same,
 * which every descriptor reads from and a reset clears for all of them.
 */
struct esdm_es_file {
	struct esdm_es_conf irq;
	struct esdm_es_conf sched;
};

/* Module init: allocate memory, register the device file */
static int esdm_cdev_open(struct inode *inode, struct file *file)
{
	struct esdm_es_file *f;
	unsigned m = iminor(inode);
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (m >= ESDM_MAX_MINORS)
		return -EINVAL;

	ret = nonseekable_open(inode, file);
	if (ret)
		return ret;

	/* Last, as a failing open is not released */
	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	esdm_es_mgr_irq_conf_init(&f->irq);
	esdm_es_mgr_sched_conf_init(&f->sched);
	file->private_data = f;

	return 0;
}

static int esdm_cdev_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	file->private_data = NULL;
	return 0;
}

static long esdm_cdev_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	struct esdm_es_file __maybe_unused *f = filp->private_data;
	int ret = -ENODEV;

	/*
	 * All IOCTLs are allowed without restriction. However, the device
	 * node can only be opened with CAP_SYS_ADMIN. This allows the
	 * restriction of the access to the IOCTLs to root, but the calling
	 * service can drop its privileges after opening the device.
	 *
	 * The lock serializes the IOCTLs on the entropy sources, the
	 * configuration of the descriptor among them.
	 */

	mutex_lock(&esdm_cdev_lock);

	switch (cmd) {
#ifdef ESDM_ES_IRQ
	case ESDM_IRQ_AVAIL_ENTROPY:
	case ESDM_IRQ_ENT_BUF_SIZE:
	case ESDM_IRQ_ENT_BUF:
	case ESDM_IRQ_CONF:
	case ESDM_IRQ_STATUS_JSON:
		ret = esdm_es_mgr_irq_ioctl(cmd, arg, &f->irq);
		break;
#endif /* ESDM_ES_IRQ */
#ifdef ESDM_ES_SCHED
	case ESDM_SCHED_AVAIL_ENTROPY:
	case ESDM_SCHED_ENT_BUF_SIZE:
	case ESDM_SCHED_ENT_BUF:
	case ESDM_SCHED_CONF:
	case ESDM_SCHED_STATUS_JSON:
		ret = esdm_es_mgr_sched_ioctl(cmd, arg, &f->sched);
		break;
#endif /* ESDM_ES_SCHED */
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
	/*
	 * All IOCTL arguments point to u32 values, char arrays or struct
	 * entropy_buf (u8 array and u32), which have the same layout for
	 * 32-bit tasks, so only the pointer needs converting.
	 */
	.compat_ioctl = compat_ptr_ioctl,
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

static int esdm_es_mgr_reboot_notifier(struct notifier_block *nb,
				       unsigned long action, void *data)
{
	pr_warn("Reset ESDM ES' because of reboot/halt\n");

	esdm_es_mgr_irq_reset();
	esdm_es_mgr_sched_reset();

	return NOTIFY_OK;
}

static struct notifier_block esdm_es_mgr_notifier_reboot = {
	.notifier_call = esdm_es_mgr_reboot_notifier,
	.priority = 0,
};

/*
 * IS_ENABLED(), as the =m of distribution kernels leaves CONFIG_VMGENID
 * undefined: the notifier chain belongs to the built-in random.c, which
 * declares and exports it for VMGENID=m as well.
 */
#if IS_ENABLED(CONFIG_VMGENID)
static int esdm_es_mgr_vmgenid_notifier(struct notifier_block *nb,
					unsigned long action, void *data)
{
	pr_warn("Reset ESDM ES' because of vmgenid change!\n");

	esdm_es_mgr_irq_reset();
	esdm_es_mgr_sched_reset();

	return NOTIFY_OK;
}

static struct notifier_block esdm_es_mgr_notifier_vmgenid = {
	.notifier_call = esdm_es_mgr_vmgenid_notifier,
	.priority = 0,
};
#endif

static int esdm_es_mgr_power_notifier(struct notifier_block *nb,
				      unsigned long action, void *data)
{
	pr_warn("Reset ESDM ES' because of power management change!\n");

	esdm_es_mgr_irq_reset();
	esdm_es_mgr_sched_reset();

	return NOTIFY_OK;
}

static struct notifier_block esdm_es_mgr_notifier_power = {
	.notifier_call = esdm_es_mgr_power_notifier,
	.priority = 0,
};

/*
 * Every step that failed undid its own part, so the error path undoes the
 * steps before it only: an entropy source that was never set up is not torn
 * down, which would log its unloading.
 */
static int __init esdm_es_mgr_init(void)
{
	int ret = esdm_init_time_source();
	if (ret) {
		pr_warn("esdm_init_time_source() failed\n");
		goto out_time;
	}

	ret = esdm_drbg_selftest();
	if (ret) {
		pr_warn("esdm_drbg_selftest() failed\n");
		goto out_time;
	}

	ret = esdm_es_mgr_irq_init();
	if (ret) {
		pr_warn("esdm_es_mgr_irq_init() failed\n");
		goto out_time;
	}

	ret = esdm_es_mgr_sched_init();
	if (ret) {
		pr_warn("esdm_es_mgr_sched_init() failed\n");
		goto out_irq;
	}

	ret = esdm_test_init();
	if (ret) {
		pr_warn("esdm_test_init() failed\n");
		goto out_sched;
	}

	ret = esdm_es_mgr_dev_init();
	if (ret) {
		pr_warn("esdm_es_mgr_dev_init() failed\n");
		goto out_test;
	}

	register_reboot_notifier(&esdm_es_mgr_notifier_reboot);
#if IS_ENABLED(CONFIG_VMGENID)
	register_random_vmfork_notifier(&esdm_es_mgr_notifier_vmgenid);
#endif
	register_pm_notifier(&esdm_es_mgr_notifier_power);
	return 0;

out_test:
	esdm_test_exit();
out_sched:
	esdm_es_mgr_sched_exit();
out_irq:
	esdm_es_mgr_irq_exit();
out_time:
	/* as in esdm_es_mgr_exit(), drain messages the hooks queued */
	esdm_health_exit();
	esdm_time_source_exit();
	return ret;
}

static void __exit esdm_es_mgr_exit(void)
{
	unregister_reboot_notifier(&esdm_es_mgr_notifier_reboot);
#if IS_ENABLED(CONFIG_VMGENID)
	unregister_random_vmfork_notifier(&esdm_es_mgr_notifier_vmgenid);
#endif
	unregister_pm_notifier(&esdm_es_mgr_notifier_power);

	esdm_es_mgr_dev_fini();
	esdm_test_exit();
	esdm_es_mgr_sched_exit();
	esdm_es_mgr_irq_exit();

	/*
	 * The scheduler and IRQ hooks are unregistered above, so no further
	 * deferred health-test or GCD messages can be queued. Drain any still
	 * pending before the module text is freed.
	 */
	esdm_health_exit();
	esdm_time_source_exit();
}

module_init(esdm_es_mgr_init);
module_exit(esdm_es_mgr_exit);

MODULE_LICENSE("Dual BSD/GPL");
/* The kernel patches export into ESDM, a string literal since 6.13 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("ESDM");
#else
MODULE_IMPORT_NS(ESDM);
#endif
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("ESDM entropy source manager");
