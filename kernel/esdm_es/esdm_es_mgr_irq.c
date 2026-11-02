// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM entropy source manager and external interface
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/module.h>

#include "esdm_definitions.h"
#include "esdm_es_ioctl.h"
#include "esdm_es_mgr_irq.h"
#include "esdm_es_irq.h"

/* The configuration a newly opened descriptor starts out with */
void esdm_es_mgr_irq_conf_init(struct esdm_es_conf *conf)
{
	conf->requested_bits = ESDM_DRNG_INIT_SEED_SIZE_BITS;
	/* the rate the module was loaded with */
	conf->entropy_rate = 0;
}

/*
 * @conf: the configuration of the IRQ ES by the descriptor the IOCTL is issued
 *	  on, serialized by the caller
 */
int esdm_es_mgr_irq_ioctl(unsigned int cmd, unsigned long arg,
			  struct esdm_es_conf *conf)
{
	struct entropy_buf eb __aligned(ESDM_KCAPI_ALIGN);
	char status[250];
	char status_json[ESDM_STATUS_JSON_BUFLEN];
	u32 data, data2, bits, __user *p = (int __user *)arg;
	int ret = 0;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case ESDM_IRQ_AVAIL_ENTROPY:
		data = esdm_es_irq.curr_entropy(conf->entropy_rate);
		if (put_user(data, p))
			return -EFAULT;
		return 0;

	case ESDM_IRQ_ENT_BUF_SIZE:
		data = sizeof(eb);
		if (put_user(data, p++))
			return -EFAULT;
		data = esdm_int_es_irq;
		if (put_user(data, p))
			return -EFAULT;
		return 0;

	case ESDM_IRQ_ENT_BUF:
		memset(&eb, 0, sizeof(eb));
		esdm_es_irq.get_ent(&eb, conf->requested_bits,
				    conf->entropy_rate);
		if (copy_to_user(argp, &eb, sizeof(eb)))
			ret = -EFAULT;
		memzero_explicit(&eb, sizeof(eb));
		break;

	case ESDM_IRQ_CONF:
		if (get_user(data, p++))
			return -EFAULT;
		if (get_user(data2, p++))
			return -EFAULT;

		/*
		 * Requested bits, 0 for unchanged: checked before anything is
		 * carried out, so that a request refused with -EINVAL leaves
		 * the entropy source as it is, without the reset it asks for.
		 */
		bits = data & ESDM_ES_MGR_REQ_BITS_MASK;
		if (bits && bits != ESDM_DRNG_INIT_SEED_SIZE_BITS &&
		    bits != (ESDM_DRNG_SECURITY_STRENGTH_BITS +
			     ESDM_OVERSAMPLE_ES_BITS) &&
		    bits != ESDM_DRNG_SECURITY_STRENGTH_BITS)
			return -EINVAL;

		if (data & ESDM_ES_MGR_RESET_BIT)
			esdm_es_mgr_irq_reset();

		/*
		 * Both settings belong to this descriptor: the other ESDMs
		 * reading the entropy source keep theirs.
		 */
		if (bits)
			conf->requested_bits = bits;

		/*
		 * Events per 256 bits of entropy: the entropy source keeps it
		 * from going below the default, i.e. from crediting more
		 * entropy, and every larger value is valid - U32_MAX credits
		 * none.
		 */
		if (data2 > 0)
			conf->entropy_rate = data2;

		break;

	case ESDM_IRQ_STATUS:
		memset(status, 0, sizeof(status));
		esdm_es_irq.state(status, sizeof(status), conf->entropy_rate);
		if (copy_to_user(argp, &status, sizeof(status)))
			ret = -EFAULT;

		break;

	case ESDM_IRQ_STATUS_JSON:
		if (!esdm_es_irq.state_json)
			return -EOPNOTSUPP;

		memset(status_json, 0, sizeof(status_json));
		esdm_es_irq.state_json(status_json, sizeof(status_json),
				       conf->entropy_rate);
		if (copy_to_user(argp, &status_json, sizeof(status_json)))
			ret = -EFAULT;

		break;

	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	return ret;
}

void esdm_es_mgr_irq_reset(void)
{
	esdm_es_irq.reset();
}

int __init esdm_es_mgr_irq_init(void)
{
	return esdm_es_irq_module_init();
}

void esdm_es_mgr_irq_exit(void)
{
	esdm_es_irq_module_exit();
}
