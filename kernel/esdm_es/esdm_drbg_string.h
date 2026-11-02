/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM: seed data list element handed to the internal DRBG
 *
 * Up to Linux 7.1 struct drbg_string comes from <crypto/drbg.h>. Linux 7.2
 * reduced the kernel DRBG to a private HMAC_DRBG and removed that header, so
 * the definition (identical to the former kernel one) is provided here.
 *
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_DRBG_STRING_H
#define _ESDM_DRBG_STRING_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 2, 0)

#include <crypto/drbg.h>

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(7, 2, 0) */

#include <linux/list.h>
#include <linux/types.h>

struct drbg_string {
	const unsigned char *buf;
	size_t len;
	struct list_head list;
};

static inline void drbg_string_fill(struct drbg_string *string,
				    const unsigned char *buf, size_t len)
{
	string->buf = buf;
	string->len = len;
	INIT_LIST_HEAD(&string->list);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(7, 2, 0) */

#endif /* _ESDM_DRBG_STRING_H */
