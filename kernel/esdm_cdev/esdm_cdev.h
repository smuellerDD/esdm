/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * ESDM character device frontend - internal interfaces
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#ifndef ESDM_CDEV_H
#define ESDM_CDEV_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/uio.h>

#include "esdm_egd_protocol.h"

/* EGD client, esdm_cdev_egd.c */
int esdm_cdev_egd_init(void);
void esdm_cdev_egd_fini(void);

/*
 * The module's workqueue, unbound: the connects and the watcher of
 * esdm_cdev_main.c. Linux 7.2 deprecates system_unbound_wq, whose successor
 * system_dfl_wq only exists since 6.17.
 */
extern struct workqueue_struct *esdm_cdev_wq;

/*
 * Read up to @len bytes, at most ESDM_EGD_MAX_BULK, into @buf with the
 * non-blocking read @read - ESDM_EGD_CMD_READ_NONBLOCK, _ESDM_PR_READ_NONBLOCK
 * or _ESDM_READ_UNSEEDED. Returns the number of bytes delivered, which may be
 * fewer than asked for - none before the ESDM is operational -, or a negative
 * errno: -ERESTARTSYS when a signal interrupted the caller, any other when the
 * ESDM could not be asked.
 */
int esdm_cdev_egd_read(u8 read, u8 *buf, size_t len);

/*
 * Insert @len bytes of user memory at @ubuf into the auxiliary pool of the
 * ESDM, without entropy credit. Returns the number of bytes inserted, fewer
 * than @len when user memory was not readable, a signal or an error of the
 * ESDM came after some of them; without any, -EFAULT when user memory was not
 * readable, or another negative errno when the ESDM could not be reached.
 */
ssize_t esdm_cdev_egd_insert_user(const char __user *ubuf, size_t len);

/* The state of the ESDM, see ESDM_EGD_STATE_* */
int esdm_cdev_egd_get_state(u32 fields[ESDM_EGD_STATE_NUM_FIELDS]);

/*
 * The status report as text or JSON document (@json). On success, *@report
 * holds a NUL terminated copy of *@len bytes, to be released with kvfree().
 */
int esdm_cdev_egd_status(bool json, char **report, size_t *len);

/*
 * One of the privileged commands changing the entropy accounting or the
 * DRNGs, with its argument @arg if @has_arg. Returns the status the ESDM
 * answered with, or a negative errno when it could not be asked. Once sent,
 * the command is carried out by the ESDM, so it is never restarted: its answer
 * is waited for despite signals, -EINTR only for a fatal one. Only to be
 * invoked on behalf of a caller holding CAP_SYS_ADMIN.
 */
int esdm_cdev_egd_priv(u8 cmd, bool has_arg, u32 arg);

/* /proc/esdm, esdm_cdev_proc.c */
int esdm_cdev_proc_init(void);
void esdm_cdev_proc_fini(void);

#endif /* ESDM_CDEV_H */
