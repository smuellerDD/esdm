// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM testing interfaces to obtain raw entropy
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <asm/errno.h>

#include "esdm_testing.h"

#if defined(CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY) ||                            \
	defined(CONFIG_ESDM_SCHED_PERF)
#define ESDM_TESTING_USE_BUSYLOOP
#endif

#define ESDM_TESTING_RINGBUFFER_SIZE 1024
#define ESDM_TESTING_RINGBUFFER_MASK (ESDM_TESTING_RINGBUFFER_SIZE - 1)

struct esdm_testing {
	u64 esdm_testing_rb[ESDM_TESTING_RINGBUFFER_SIZE];
	u32 rb_reader;
	atomic_t rb_writer;
	atomic_t esdm_testing_enabled;
	/*
	 * raw_spinlock_t (not spinlock_t): esdm_testing_store() is reached from
	 * the scheduler hook (esdm_sched_randomness) with rq->lock held, i.e. a
	 * genuinely atomic context. On PREEMPT_RT a spinlock_t becomes a sleeping
	 * rtmutex, which must not be acquired there; a raw spinlock never sleeps.
	 */
	raw_spinlock_t lock;
	wait_queue_head_t read_wait;
	/*
	 * Serializes the readers: each one resets the ring and enables the
	 * collection when it starts and disables it again when it ends, which
	 * would otherwise pull the ring away under a concurrent reader and
	 * leave it waiting for data that is no longer collected.
	 */
	struct mutex reader_lock;
};

/*************************** Generic Data Handling ****************************/

/*
 * boot variable:
 * 0 ==> No boot test, gathering of runtime data allowed
 * 1 ==> Boot test enabled and ready for collecting data, gathering runtime
 *	 data is disabled
 * 2 ==> Boot test completed and disabled, gathering of runtime data is
 *	 disabled
 */

static void esdm_testing_reset(struct esdm_testing *data)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&data->lock, flags);
	data->rb_reader = 0;
	atomic_set(&data->rb_writer, 0);
	raw_spin_unlock_irqrestore(&data->lock, flags);
}

/* Returns whether the reader may hand out data */
static bool esdm_testing_init(struct esdm_testing *data, u32 boot)
{
	/*
	 * should the testing interface be present by accident in a production build
	 * with lockdown mode enabled later on (not in early boot), do not store values!
	 *
	 * Neither hand out those of a boot time test: its parameter is writable
	 * at runtime, so the test may have been started after lockdown was
	 * enabled. The store cannot check lockdown, it runs in atomic context.
	 *
	 * This is only defense in depth, as lockdown would probably already deny
	 * access without this based on the access rights.
	 */
	if (security_locked_down(LOCKDOWN_DEBUGFS)) {
		pr_warn("Skipping data collection due to enabled lockdown mode\n");
		return false;
	}

	/*
	 * The boot time testing implies we have a running test. If the
	 * caller wants to clear it, he has to unset the boot_test flag
	 * at runtime via sysfs to enable regular runtime testing
	 */
	if (boot)
		return true;

	esdm_testing_reset(data);
	atomic_set(&data->esdm_testing_enabled, 1);
	pr_warn("Enabling data collection\n");

	return true;
}

static void esdm_testing_fini(struct esdm_testing *data, u32 boot)
{
	/* If we have boot data, we do not reset yet to allow data to be read */
	if (boot)
		return;

	atomic_set(&data->esdm_testing_enabled, 0);
	esdm_testing_reset(data);
	pr_warn("Disabling data collection\n");
}

static bool esdm_testing_store(struct esdm_testing *data, u64 value, u32 *boot)
{
	unsigned long flags;

	if (!atomic_read(&data->esdm_testing_enabled) && (*boot != 1))
		return false;

	raw_spin_lock_irqsave(&data->lock, flags);

	/*
	 * Disable entropy testing for boot time testing after ring buffer
	 * is filled. No printk: this runs from the hooks with the raw lock
	 * held, and a console wake-up would re-enter the hook on this CPU.
	 */
	if (*boot && ((u32)atomic_read(&data->rb_writer)) >=
			     ESDM_TESTING_RINGBUFFER_SIZE) {
		*boot = 2;
		raw_spin_unlock_irqrestore(&data->lock, flags);
		return false;
	}

	data->esdm_testing_rb[((u32)atomic_read(&data->rb_writer)) &
			      ESDM_TESTING_RINGBUFFER_MASK] = value;
	atomic_inc(&data->rb_writer);

	raw_spin_unlock_irqrestore(&data->lock, flags);

#ifndef ESDM_TESTING_USE_BUSYLOOP
	if (wq_has_sleeper(&data->read_wait))
		wake_up_interruptible(&data->read_wait);
#endif

	return true;
}

static bool esdm_testing_have_data(struct esdm_testing *data)
{
	return ((((u32)atomic_read(&data->rb_writer)) &
		 ESDM_TESTING_RINGBUFFER_MASK) !=
		(data->rb_reader & ESDM_TESTING_RINGBUFFER_MASK));
}

static int esdm_testing_reader(struct esdm_testing *data, u32 *boot, u8 *outbuf,
			       u32 outbuflen)
{
	unsigned long flags;
	int collected_data = 0;

	if (mutex_lock_interruptible(&data->reader_lock))
		return -ERESTARTSYS;

	if (!esdm_testing_init(data, *boot))
		goto out;

	while (outbuflen) {
		u32 writer = (u32)atomic_read(&data->rb_writer);

		raw_spin_lock_irqsave(&data->lock, flags);

		/* We have no data or reached the writer. */
		if (!writer || (writer == data->rb_reader)) {
			raw_spin_unlock_irqrestore(&data->lock, flags);

			/*
			 * Now we gathered all boot data, enable regular data
			 * collection.
			 */
			if (*boot) {
				*boot = 0;
				goto out;
			}

			/* not enabled under lockdown, nothing will arrive */
			if (!atomic_read(&data->esdm_testing_enabled))
				goto out;

#ifdef ESDM_TESTING_USE_BUSYLOOP
			/*
			 * The store does not wake up readers in this
			 * configuration, so poll - but stay killable and give
			 * the CPU away, the data may be long in coming, e.g.
			 * before the hooks are registered.
			 */
			while (!esdm_testing_have_data(data) &&
			       !signal_pending(current)) {
				cond_resched();
				cpu_relax();
			}
#else
			wait_event_interruptible(data->read_wait,
						 esdm_testing_have_data(data));
#endif
			/* hand out what was read before the signal */
			if (signal_pending(current)) {
				if (!collected_data)
					collected_data = -ERESTARTSYS;
				goto out;
			}

			continue;
		}

		/* We copy out word-wise */
		if (outbuflen < sizeof(u64)) {
			raw_spin_unlock_irqrestore(&data->lock, flags);
			goto out;
		}

		/*
		 * Mask the reader index like the writer does (line storing into
		 * esdm_testing_rb) and like have_data(). rb_reader is a monotonic
		 * counter that is never wrapped, so indexing it unmasked walks
		 * past the ESDM_TESTING_RINGBUFFER_SIZE-element array once it
		 * exceeds the ring size, reading adjacent kernel memory into the
		 * buffer that is then copied to userspace.
		 */
		memcpy(outbuf,
		       &data->esdm_testing_rb[data->rb_reader &
					      ESDM_TESTING_RINGBUFFER_MASK],
		       sizeof(u64));
		data->rb_reader++;

		raw_spin_unlock_irqrestore(&data->lock, flags);

		outbuf += sizeof(u64);
		outbuflen -= sizeof(u64);
		collected_data += sizeof(u64);
	}

out:
	esdm_testing_fini(data, *boot);
	mutex_unlock(&data->reader_lock);
	return collected_data;
}

static int esdm_testing_extract_user(struct file *file, char __user *buf,
				     size_t nbytes, loff_t *ppos,
				     int (*reader)(u8 *outbuf, u32 outbuflen))
{
	u8 *tmp, *tmp_aligned;
	int ret = 0, large_request = (nbytes > 256);

	if (!nbytes)
		return 0;

	/*
	 * The intention of this interface is for collecting at least
	 * 1000 samples due to the SP800-90B requirements. So, we make no
	 * effort in avoiding allocating more memory that actually needed
	 * by the user. Hence, we allocate sufficient memory to always hold
	 * that amount of data.
	 */
	tmp = kvzalloc(ESDM_TESTING_RINGBUFFER_SIZE + sizeof(u64), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp_aligned = PTR_ALIGN(tmp, sizeof(u64));

	while (nbytes) {
		int i;

		if (large_request && need_resched()) {
			if (signal_pending(current)) {
				if (ret == 0)
					ret = -ERESTARTSYS;
				break;
			}
			schedule();
		}

		i = min_t(int, nbytes, ESDM_TESTING_RINGBUFFER_SIZE);
		i = reader(tmp_aligned, i);
		if (i <= 0) {
			/* earlier chunks are already in the user buffer */
			if (i < 0 && !ret)
				ret = i;
			break;
		}
		if (copy_to_user(buf, tmp_aligned, i)) {
			ret = -EFAULT;
			break;
		}

		nbytes -= i;
		buf += i;
		ret += i;
	}

	kvfree_sensitive(tmp, ESDM_TESTING_RINGBUFFER_SIZE + sizeof(u64));

	if (ret > 0)
		*ppos += ret;

	return ret;
}

/************* Raw High-Resolution IRQ Timer Entropy Data Handling ************/

#ifdef CONFIG_ESDM_RAW_HIRES_ENTROPY

static u32 boot_raw_hires_test = 0;
module_param(boot_raw_hires_test, uint, 0644);
MODULE_PARM_DESC(
	boot_raw_hires_test,
	"Enable gathering boot time high resolution timer entropy of the first IRQ entropy events");

static struct esdm_testing esdm_raw_hires = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock = __RAW_SPIN_LOCK_UNLOCKED(esdm_raw_hires.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(esdm_raw_hires.read_wait),
	.reader_lock = __MUTEX_INITIALIZER(esdm_raw_hires.reader_lock)
};

bool esdm_raw_hires_entropy_store(u64 value)
{
	return esdm_testing_store(&esdm_raw_hires, value, &boot_raw_hires_test);
}

static int esdm_raw_hires_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_raw_hires, &boot_raw_hires_test,
				   outbuf, outbuflen);
}

static ssize_t esdm_raw_hires_read(struct file *file, char __user *to,
				   size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_raw_hires_entropy_reader);
}

static const struct file_operations esdm_raw_hires_fops = {
	.owner = THIS_MODULE,
	.read = esdm_raw_hires_read,
};

#endif /* CONFIG_ESDM_RAW_HIRES_ENTROPY */

/******************** Interrupt Performance Data Handling *********************/

#ifdef CONFIG_ESDM_IRQ_PERF

static u32 boot_irq_perf = 0;
module_param(boot_irq_perf, uint, 0644);
MODULE_PARM_DESC(
	boot_irq_perf,
	"Enable gathering interrupt-based entropy source performance data");

static struct esdm_testing esdm_irq_perf = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock = __RAW_SPIN_LOCK_UNLOCKED(esdm_irq_perf.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(esdm_irq_perf.read_wait),
	.reader_lock = __MUTEX_INITIALIZER(esdm_irq_perf.reader_lock)
};

bool esdm_irq_perf_time(u64 start)
{
	return esdm_testing_store(&esdm_irq_perf, random_get_entropy() - start,
				  &boot_irq_perf);
}

static int esdm_irq_perf_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_irq_perf, &boot_irq_perf, outbuf,
				   outbuflen);
}

static ssize_t esdm_irq_perf_read(struct file *file, char __user *to,
				  size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_irq_perf_reader);
}

static const struct file_operations esdm_irq_perf_fops = {
	.owner = THIS_MODULE,
	.read = esdm_irq_perf_read,
};

#endif /* CONFIG_ESDM_IRQ_PERF */

/****** Raw High-Resolution Scheduler-based Timer Entropy Data Handling *******/

#ifdef CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY

static u32 boot_raw_sched_hires_test = 0;
module_param(boot_raw_sched_hires_test, uint, 0644);
MODULE_PARM_DESC(
	boot_raw_sched_hires_test,
	"Enable gathering boot time high resolution timer entropy of the first Scheduler-based entropy events");

static struct esdm_testing esdm_raw_sched_hires = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock = __RAW_SPIN_LOCK_UNLOCKED(esdm_raw_sched_hires.lock),
	.read_wait =
		__WAIT_QUEUE_HEAD_INITIALIZER(esdm_raw_sched_hires.read_wait),
	.reader_lock = __MUTEX_INITIALIZER(esdm_raw_sched_hires.reader_lock)
};

bool esdm_raw_sched_hires_entropy_store(u64 value)
{
	return esdm_testing_store(&esdm_raw_sched_hires, value,
				  &boot_raw_sched_hires_test);
}

static int esdm_raw_sched_hires_entropy_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_raw_sched_hires,
				   &boot_raw_sched_hires_test, outbuf,
				   outbuflen);
}

static ssize_t esdm_raw_sched_hires_read(struct file *file, char __user *to,
					 size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_raw_sched_hires_entropy_reader);
}

static const struct file_operations esdm_raw_sched_hires_fops = {
	.owner = THIS_MODULE,
	.read = esdm_raw_sched_hires_read,
};

#endif /* CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY */

/******************** Scheduler Performance Data Handling *********************/

#ifdef CONFIG_ESDM_SCHED_PERF

static u32 boot_sched_perf = 0;
module_param(boot_sched_perf, uint, 0644);
MODULE_PARM_DESC(
	boot_sched_perf,
	"Enable gathering scheduler-based entropy source performance data");

static struct esdm_testing esdm_sched_perf = {
	.rb_reader = 0,
	.rb_writer = ATOMIC_INIT(0),
	.lock = __RAW_SPIN_LOCK_UNLOCKED(esdm_sched_perf.lock),
	.read_wait = __WAIT_QUEUE_HEAD_INITIALIZER(esdm_sched_perf.read_wait),
	.reader_lock = __MUTEX_INITIALIZER(esdm_sched_perf.reader_lock)
};

bool esdm_sched_perf_time(u64 start)
{
	return esdm_testing_store(&esdm_sched_perf,
				  random_get_entropy() - start,
				  &boot_sched_perf);
}

static int esdm_sched_perf_reader(u8 *outbuf, u32 outbuflen)
{
	return esdm_testing_reader(&esdm_sched_perf, &boot_sched_perf, outbuf,
				   outbuflen);
}

static ssize_t esdm_sched_perf_read(struct file *file, char __user *to,
				    size_t count, loff_t *ppos)
{
	return esdm_testing_extract_user(file, to, count, ppos,
					 esdm_sched_perf_reader);
}

static const struct file_operations esdm_sched_perf_fops = {
	.owner = THIS_MODULE,
	.read = esdm_sched_perf_read,
};

#endif /* CONFIG_ESDM_SCHED_PERF */

/**************************************************************************
 * Debugfs interface
 **************************************************************************/

static struct dentry *esdm_raw_debugfs_root = NULL;

int __init esdm_test_init(void)
{
	/*
	 * should the testing interface be present by accident in a production build
	 * with lockdown mode enabled early, do not create debugfs access!
	 *
	 * This is only defense in depth, as lockdown would probably already deny
	 * access without this based on the access rights.
	 */
	if (security_locked_down(LOCKDOWN_DEBUGFS)) {
		pr_info("ESDM is skipping debugfs creation due to lockdown mode: %s\n",
			KBUILD_MODNAME);
		return 0;
	}

	/*
	 * debugfs_create_dir() reports failure via ERR_PTR, never NULL. The
	 * testing interface is optional: a kernel without debugfs or with it
	 * disabled (debugfs=off) must not cost ESDM its entropy sources, so
	 * only skip the interface, as for lockdown above.
	 */
	esdm_raw_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(esdm_raw_debugfs_root)) {
		pr_warn("ESDM testing debugfs creation failed, interface disabled: %s (%ld)\n",
			KBUILD_MODNAME, PTR_ERR(esdm_raw_debugfs_root));
		esdm_raw_debugfs_root = NULL;
		return 0;
	}

	pr_info("ESDM testing debugfs created: %s\n", KBUILD_MODNAME);

#ifdef CONFIG_ESDM_RAW_HIRES_ENTROPY
	debugfs_create_file_unsafe("esdm_raw_hires", 0400,
				   esdm_raw_debugfs_root, NULL,
				   &esdm_raw_hires_fops);
#endif

#ifdef CONFIG_ESDM_IRQ_PERF
	debugfs_create_file_unsafe("esdm_irq_perf", 0400, esdm_raw_debugfs_root,
				   NULL, &esdm_irq_perf_fops);
#endif

#ifdef CONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY
	debugfs_create_file_unsafe("esdm_raw_sched_hires", 0400,
				   esdm_raw_debugfs_root, NULL,
				   &esdm_raw_sched_hires_fops);
#endif

#ifdef CONFIG_ESDM_SCHED_PERF
	debugfs_create_file_unsafe("esdm_sched_perf", 0400,
				   esdm_raw_debugfs_root, NULL,
				   &esdm_sched_perf_fops);
#endif

	return 0;
}

/* not __exit, the module init error path calls it too */
void esdm_test_exit(void)
{
	if (esdm_raw_debugfs_root) {
		debugfs_remove_recursive(esdm_raw_debugfs_root);
		esdm_raw_debugfs_root = NULL;
	} else {
		pr_info("ESDM debugfs root was never created (lockdown or debugfs unavailable): %s\n",
			KBUILD_MODNAME);
	}
}
