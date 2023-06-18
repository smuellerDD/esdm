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
#include "esdm_es_ioctl.h"
#include "esdm_es_mgr_sched.h"
#include "esdm_es_sched.h"

static u32 esdm_requested_sched_bits = ESDM_DRNG_INIT_SEED_SIZE_BITS;

/* Available entropy in the entire ESDM considering all entropy sources */
static u32 esdm_avail_entropy_sched(u32 requested_bits)
{
	return esdm_es_sched.curr_entropy(requested_bits);
}

int esdm_es_mgr_sched_ioctl(unsigned int cmd, unsigned long arg)
{
	struct entropy_buf eb __aligned(ESDM_KCAPI_ALIGN);
	char status[250];
	u32 data, data2, __user *p = (int __user *)arg;
	int ret = 0;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case ESDM_SCHED_AVAIL_ENTROPY:
		data = esdm_avail_entropy_sched(esdm_requested_sched_bits);
		if (put_user(data, p))
			return -EFAULT;
		return 0;

	case ESDM_SCHED_ENT_BUF_SIZE:
		data = sizeof(eb);
		if (put_user(data, p++))
			return -EFAULT;
		data = esdm_int_es_sched;
		if (put_user(data, p))
			return -EFAULT;
		return 0;

	case ESDM_SCHED_ENT_BUF:
		memset(&eb, 0, sizeof(eb));
		esdm_es_sched.get_ent(&eb, esdm_requested_sched_bits);
		if (copy_to_user(argp, &eb, sizeof(eb)))
			ret = -EFAULT;
		memzero_explicit(&eb, sizeof(eb));
		break;

	case ESDM_SCHED_CONF:
		if (get_user(data, p++))
			return -EFAULT;
		if (get_user(data2, p++))
			return -EFAULT;

		if (data & ESDM_ES_MGR_RESET_BIT)
			esdm_es_mgr_sched_reset();

		/* Requested bits */
		data &= ESDM_ES_MGR_REQ_BITS_MASK;
		if (data > 0) {
			if (data != ESDM_DRNG_INIT_SEED_SIZE_BITS &&
			    data != ESDM_DRNG_SECURITY_STRENGTH_BITS)
				return -EINVAL;
			esdm_requested_sched_bits = data;
		}

		if (data2 > 0)
			esdm_es_sched.set_entropy_rate(data2);

		break;

	case ESDM_SCHED_STATUS:
		memset(status, 0, sizeof(status));
		esdm_es_sched.state(status, sizeof(status));
		if (copy_to_user(argp, &status, sizeof(status)))
			ret = -EFAULT;

		break;

	default:
		printk("ioctl6 %u\n", cmd);
		ret = -ENOIOCTLCMD;
		break;
	}

	return ret;
}

void esdm_es_mgr_sched_reset(void)
{
	esdm_es_sched.reset();
}

int __init esdm_es_mgr_sched_init(void)
{
	return esdm_es_sched_module_init();
}

void esdm_es_mgr_sched_exit(void)
{
	esdm_es_sched_module_exit();
}
