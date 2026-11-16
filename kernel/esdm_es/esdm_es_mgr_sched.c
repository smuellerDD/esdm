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
#include "esdm_es_mgr_sched.h"
#include "esdm_es_sched.h"

/* The configuration a newly opened descriptor starts out with */
void esdm_es_mgr_sched_conf_init(struct esdm_es_conf *conf)
{
	conf->requested_bits = ESDM_DRNG_INIT_SEED_SIZE_BITS;
	/* the rate the module was loaded with */
	conf->entropy_rate = 0;
}

/*
 * @arg: the argument of the IOCTL in kernel memory, copied in before and out
 *	 after by the caller, zeroed in between
 * @conf: the configuration of the scheduler ES by the descriptor the IOCTL is
 *	  issued on, serialized by the caller
 */
int esdm_es_mgr_sched_ioctl(unsigned int cmd, union esdm_es_ioctl_arg *arg,
			    struct esdm_es_conf *conf)
{
	u32 bits;

	switch (cmd) {
	case ESDM_SCHED_AVAIL_ENTROPY:
		arg->words[0] = esdm_es_sched.curr_entropy(conf->entropy_rate);
		return 0;

	case ESDM_SCHED_ENT_BUF_SIZE:
		arg->words[0] = sizeof(arg->eb);
		arg->words[1] = esdm_int_es_sched;
		return 0;

	case ESDM_SCHED_ENT_BUF:
		esdm_es_sched.get_ent(&arg->eb, conf->requested_bits,
				      conf->entropy_rate);
		return 0;

	case ESDM_SCHED_CONF:
		/*
		 * Requested bits, 0 for unchanged: checked before anything is
		 * carried out, so that a request refused with -EINVAL leaves
		 * the entropy source as it is, without the reset it asks for.
		 */
		bits = arg->words[0] & ESDM_ES_MGR_REQ_BITS_MASK;
		if (bits && bits != ESDM_DRNG_INIT_SEED_SIZE_BITS &&
		    bits != (ESDM_DRNG_SECURITY_STRENGTH_BITS +
			     ESDM_OVERSAMPLE_ES_BITS) &&
		    bits != ESDM_DRNG_SECURITY_STRENGTH_BITS)
			return -EINVAL;

		if (arg->words[0] & ESDM_ES_MGR_RESET_BIT)
			esdm_es_mgr_sched_reset();

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
		if (arg->words[1] > 0)
			conf->entropy_rate = arg->words[1];

		return 0;

	case ESDM_SCHED_STATUS_JSON:
		esdm_es_sched.state_json(arg->status_json,
					 sizeof(arg->status_json),
					 conf->entropy_rate);
		return 0;

	default:
		return -ENOIOCTLCMD;
	}
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
