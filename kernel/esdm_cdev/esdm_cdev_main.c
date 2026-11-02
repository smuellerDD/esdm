// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM character device frontend
 *
 * /dev/esdm_random and /dev/esdm_urandom serve the random numbers of the ESDM
 * running in user space with the semantics of the kernel's /dev/random and
 * /dev/urandom, as the CUSE frontend of the ESDM does from user space:
 *
 *  - /dev/esdm_random waits until the ESDM is operational - its DRNG fully
 *    seeded - and then reads from it. O_NONBLOCK gets -EAGAIN instead, and
 *    poll() reports it readable once the ESDM is operational.
 *  - /dev/esdm_urandom reads from the ESDM's DRNG without waiting for all of
 *    them to be fully seeded - but for the ESDM to be operational, before
 *    which it hands out nothing.
 *  - Opened with O_SYNC, either reads from the prediction resistance DRNG,
 *    which hands out no more than its entropy sources just delivered. Without
 *    O_NONBLOCK, the read waits for the rest. O_DSYNC alone does not.
 *  - Data written to either is mixed into the ESDM's auxiliary pool without
 *    being credited with entropy.
 *  - The ioctls of the kernel's devices: RNDGETENTCNT for everybody, the ones
 *    changing the entropy accounting only for a caller with CAP_SYS_ADMIN.
 *
 * While the ESDM cannot be reached, /dev/esdm_random waits for it as for one
 * not operational, everything else fails, see esdm_cdev_ioctl(). Nothing is
 * served by the kernel's RNG instead, so what a reader gets came from the
 * ESDM. The kernel's /dev/random and /dev/urandom are left as they are, and
 * there for that.
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "esdm_cdev.h"

/*
 * Whether the ESDM is operational, as far as the module knows - see the
 * watcher below. Not authoritative - the reads find out anew - but what the
 * waits and poll() go by.
 */
static atomic_t esdm_cdev_operational = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(esdm_cdev_wait);

/* Readers waiting for the ESDM to turn operational */
static atomic_t esdm_cdev_waiters = ATOMIC_INIT(0);
/* A poller waits for it since it was last operational */
static atomic_t esdm_cdev_pollers = ATOMIC_INIT(0);

/* Poll interval of the watcher, and its longest one while unreachable */
#define ESDM_CDEV_WATCH_MS 100
#define ESDM_CDEV_WATCH_MAX_MS 1000

/* Prediction resistant reads ask again after this long for the rest */
#define ESDM_CDEV_PR_RETRY_MS 50

static void esdm_cdev_watch(struct work_struct *work);
static DECLARE_DELAYED_WORK(esdm_cdev_watch_work, esdm_cdev_watch);
static unsigned int esdm_cdev_watch_ms = ESDM_CDEV_WATCH_MS;
static bool esdm_cdev_stopping;

static void esdm_cdev_set_operational(bool operational)
{
	if (atomic_xchg(&esdm_cdev_operational, operational) == operational ||
	    !operational)
		return;

	atomic_set(&esdm_cdev_pollers, 0);
	wake_up_interruptible_all(&esdm_cdev_wait);
}

static void esdm_cdev_watch_kick(void)
{
	if (!READ_ONCE(esdm_cdev_stopping))
		mod_delayed_work(esdm_cdev_wq, &esdm_cdev_watch_work, 0);
}

/*
 * The watcher: asks the ESDM for its state while somebody waits for it to turn
 * operational, and wakes the waiters once it is.
 *
 * Polling rather than a request that waits in the ESDM: such a request would
 * hold a connection of the pool for as long as the ESDM takes, and the ESDM
 * offers no notification over the EGD socket.
 */
static void esdm_cdev_watch(struct work_struct *work)
{
	u32 state[ESDM_EGD_STATE_NUM_FIELDS];
	int ret = esdm_cdev_egd_get_state(state);

	/* An ESDM that cannot be reached is asked less often */
	esdm_cdev_watch_ms = ret ? min(esdm_cdev_watch_ms * 2,
				       ESDM_CDEV_WATCH_MAX_MS) :
				   ESDM_CDEV_WATCH_MS;
	esdm_cdev_set_operational(!ret && (state[ESDM_EGD_STATE_FLAGS] &
					   ESDM_EGD_STATE_FLAG_OPERATIONAL));

	if (atomic_read(&esdm_cdev_operational))
		return;

	if ((atomic_read(&esdm_cdev_waiters) ||
	     atomic_read(&esdm_cdev_pollers)) &&
	    !READ_ONCE(esdm_cdev_stopping))
		queue_delayed_work(esdm_cdev_wq, &esdm_cdev_watch_work,
				   msecs_to_jiffies(esdm_cdev_watch_ms));
}

/*
 * Wait for the ESDM to turn operational after a read found it not, or could
 * not reach it. Returns 0 once it is, or -ERESTARTSYS.
 */
static int esdm_cdev_wait_operational(void)
{
	int ret;

	esdm_cdev_set_operational(false);

	atomic_inc(&esdm_cdev_waiters);
	esdm_cdev_watch_kick();
	ret = wait_event_interruptible(esdm_cdev_wait,
				       atomic_read(&esdm_cdev_operational));
	atomic_dec(&esdm_cdev_waiters);

	return ret;
}

/********************************* Devices ***********************************/

static struct miscdevice esdm_cdev_urandom_dev;

static ssize_t esdm_cdev_read(struct file *file, char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	bool urandom = file->private_data == &esdm_cdev_urandom_dev;
	bool nonblock = file->f_flags & O_NONBLOCK;
	/*
	 * O_SYNC is __O_SYNC | O_DSYNC, so a test of O_SYNC would take O_DSYNC
	 * alone for it. The kernel tells them apart by __O_SYNC, too.
	 */
	bool pr = file->f_flags & __O_SYNC;
	u8 read = pr ? ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK :
		       (urandom ? ESDM_EGD_CMD_ESDM_READ_UNSEEDED :
				  ESDM_EGD_CMD_READ_NONBLOCK);
	/* As large as the read needs, up to one request to the ESDM */
	size_t done = 0, room = min_t(size_t, count, ESDM_EGD_MAX_BULK);
	ssize_t ret = 0;
	u8 *block;

	if (!count)
		return 0;

	block = kvmalloc(room, GFP_KERNEL);
	if (!block)
		return -ENOMEM;

	while (done < count) {
		int got;

		/*
		 * A signal ends the read, as it ends the waits for the ESDM's
		 * answers. The kernel's devices finish the first page of a
		 * read regardless, they wait for nothing then.
		 */
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		cond_resched();

		got = esdm_cdev_egd_read(read, block,
					 min_t(size_t, count - done, room));

		/*
		 * The ESDM cannot be reached: /dev/esdm_urandom fails,
		 * /dev/esdm_random waits for it as for one not operational.
		 */
		if (got < 0 && (urandom || got == -ERESTARTSYS)) {
			ret = got;
			break;
		}
		got = max(got, 0);

		/*
		 * The ESDM's answer tells its state: it hands out nothing from
		 * its DRNG before it is operational. An answer short of all is
		 * no failure: the DRNG serving it reached the most it may
		 * generate without a full reseed on the way - in a build for
		 * SP800-90C every 16 KiB -, and the rest is asked for again.
		 */
		if (!pr)
			esdm_cdev_set_operational(got);

		if (!got) {
			/* Not operational, or no prediction resistant data */
			if (nonblock) {
				ret = -EAGAIN;
				break;
			}

			if (pr) {
				long tmo = msecs_to_jiffies(ESDM_CDEV_PR_RETRY_MS);

				if (schedule_timeout_interruptible(tmo)) {
					ret = -ERESTARTSYS;
					break;
				}
				continue;
			}

			ret = esdm_cdev_wait_operational();
			if (ret)
				break;
			continue;
		}

		if (copy_to_user(ubuf + done, block, got)) {
			ret = -EFAULT;
			break;
		}
		done += got;
	}

	kvfree_sensitive(block, room);

	/* What was read is returned, an error only without any */
	if (done)
		return (ssize_t)done;

	return ret;
}

static ssize_t esdm_cdev_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	/* Without entropy credit, as for everybody */
	return esdm_cdev_egd_insert_user(ubuf, count);
}

/*
 * poll() of /dev/esdm_random, as the kernel's random_poll(): readable once the
 * ESDM is operational, writable before.
 */
static __poll_t esdm_cdev_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &esdm_cdev_wait, wait);

	if (atomic_read(&esdm_cdev_operational))
		return EPOLLIN | EPOLLRDNORM;

	/* The watcher tells the poller once that changes */
	atomic_set(&esdm_cdev_pollers, 1);
	esdm_cdev_watch_kick();

	return EPOLLOUT | EPOLLWRNORM;
}

/*
 * The ioctls of drivers/char/random.c, with its checks: the caller's
 * capability first, then the arguments - stricter ones for the size of
 * RNDADDENTROPY, see there.
 *
 * The module is root towards the ESDM, which therefore carries out whatever it
 * sends. That makes the CAP_SYS_ADMIN check here the one that keeps an
 * unprivileged caller from changing the ESDM's entropy accounting.
 *
 * While the ESDM cannot be reached, they fail as the writes and the reads of
 * /dev/esdm_urandom do: -ENOTCONN when it cannot be connected to, -ETIMEDOUT
 * when it does not answer, -ECONNRESET or -EPIPE when it closes the connection
 * - as an ESDM from before the EGD extensions does - or -EPROTO for an answer
 * that does not fit.
 */
static long esdm_cdev_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	int __user *p = (int __user *)arg;
	int ent_count, size, ret;

	switch (cmd) {
	case RNDGETENTCNT: {
		u32 state[ESDM_EGD_STATE_NUM_FIELDS];

		ret = esdm_cdev_egd_get_state(state);
		if (ret)
			return ret;
		ent_count = (int)min_t(u32, state[ESDM_EGD_STATE_ENT_CNT],
				       INT_MAX);
		if (put_user(ent_count, p))
			return -EFAULT;
		return 0;
	}
	case RNDADDTOENTCNT:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (get_user(ent_count, p))
			return -EFAULT;
		if (ent_count < 0)
			return -EINVAL;
		return esdm_cdev_egd_priv(ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT,
					  true, (u32)ent_count);
	case RNDADDENTROPY: {
		ssize_t written;
		u32 bits;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (get_user(ent_count, p++))
			return -EFAULT;
		if (ent_count < 0)
			return -EINVAL;
		if (get_user(size, p++))
			return -EFAULT;
		/*
		 * Stricter than random.c, deliberately: a negative size is
		 * refused before any data is read, where random.c mixes in
		 * what it can read of that much memory and fails with -EFAULT,
		 * and a size of 0 credits nothing, where random.c credits the
		 * entropy count without any data.
		 */
		if (size < 0)
			return -EINVAL;
		if (!size)
			return 0;

		/*
		 * As random_ioctl(): all of the data first, then the credit,
		 * and none unless all of the data went in. The data goes in
		 * without entropy, into every auxiliary pool of the ESDM, the
		 * credit after it as that of RNDADDTOENTCNT, to the first one.
		 * The insertions themselves carry no claim: given to the first
		 * of several, it would be kept when a later one failed - a
		 * caller trying again would be credited twice.
		 */
		written = esdm_cdev_egd_insert_user((const char __user *)p,
						    (size_t)size);
		if (written < 0)
			return (long)written;
		/* As the kernel: credited, so it has to be all of it */
		if (written != size)
			return -EFAULT;

		/*
		 * No more than the data has bits, where random.c credits the
		 * count, up to the size of its pool
		 */
		bits = (u32)min_t(u64, (u64)ent_count, (u64)size * 8);
		if (!bits)
			return 0;
		return esdm_cdev_egd_priv(ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT,
					  true, bits);
	}
	case RNDZAPENTCNT:
	case RNDCLEARPOOL:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return esdm_cdev_egd_priv(ESDM_EGD_CMD_ESDM_CLEAR_POOL, false,
					  0);
	case RNDRESEEDCRNG:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return esdm_cdev_egd_priv(ESDM_EGD_CMD_ESDM_RESEED, false, 0);
	default:
		/* The kernel's random_ioctl() answers with -EINVAL, too */
		return -EINVAL;
	}
}

static const struct file_operations esdm_cdev_random_fops = {
	.owner = THIS_MODULE,
	.read = esdm_cdev_read,
	.write = esdm_cdev_write,
	.poll = esdm_cdev_poll,
	.unlocked_ioctl = esdm_cdev_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = noop_llseek,
};

/* As the kernel's urandom_fops: no poll, always readable and writable */
static const struct file_operations esdm_cdev_urandom_fops = {
	.owner = THIS_MODULE,
	.read = esdm_cdev_read,
	.write = esdm_cdev_write,
	.unlocked_ioctl = esdm_cdev_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice esdm_cdev_random_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "esdm_random",
	.fops = &esdm_cdev_random_fops,
	.mode = 0666,
};

static struct miscdevice esdm_cdev_urandom_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "esdm_urandom",
	.fops = &esdm_cdev_urandom_fops,
	.mode = 0666,
};

/********************************** Module ***********************************/

static void esdm_cdev_watch_stop(void)
{
	WRITE_ONCE(esdm_cdev_stopping, true);
	cancel_delayed_work_sync(&esdm_cdev_watch_work);
}

static int __init esdm_cdev_init(void)
{
	int ret;

	ret = esdm_cdev_egd_init();
	if (ret)
		return ret;

	ret = esdm_cdev_proc_init();
	if (ret)
		goto err_egd;

	ret = misc_register(&esdm_cdev_random_dev);
	if (ret)
		goto err_proc;

	ret = misc_register(&esdm_cdev_urandom_dev);
	if (ret)
		goto err_random;

	/* Learn the state of the ESDM, without waiting for it */
	esdm_cdev_watch_kick();

	return 0;

err_random:
	misc_deregister(&esdm_cdev_random_dev);
err_proc:
	esdm_cdev_proc_fini();
err_egd:
	esdm_cdev_watch_stop();
	esdm_cdev_egd_fini();
	return ret;
}

/*
 * The devices hold a reference to the module while they are open, so nobody
 * reads or waits in them once this runs. The proc files are removed waiting
 * for the ones being read, and the watcher is stopped before the connections
 * and the workqueue it uses go away.
 */
static void __exit esdm_cdev_exit(void)
{
	misc_deregister(&esdm_cdev_urandom_dev);
	misc_deregister(&esdm_cdev_random_dev);
	esdm_cdev_proc_fini();
	esdm_cdev_watch_stop();
	esdm_cdev_egd_fini();
}

module_init(esdm_cdev_init);
module_exit(esdm_cdev_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Markus Theil <theil.markus@gmail.com>");
MODULE_DESCRIPTION("ESDM character device frontend");
