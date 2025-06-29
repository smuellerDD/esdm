/*
 * Copyright (C) 2025 Markus Theil <theil.markus@gmail.com>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef SYSTEMD_SUPPORT_H
#define SYSTEMD_SUPPORT_H

#include "config.h"
#include <unistd.h>
#include <stdbool.h>

#ifdef ESDM_SYSTEMD_SUPPORT
/*
 * systemd socket activation related code
 */
#define SYSTEMD_LISTEN_FDS_START 3

/*
 * systemd notify related code
 *
 * Code taken from: https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html#
 * Licensed under MIT-0, so "just copy without further attribution" is tolerated
 */

/* generic function with custom message */
int systemd_notify(const char *message);

/* helper functions with prepared messages */
int systemd_notify_ready(void);
int systemd_notify_stopping(void);
int systemd_notify_mainpid(pid_t pid);
int systemd_notify_access(char *mode);
int systemd_notify_status(char *msg);

int systemd_listen_pid(void);
int systemd_listen_fds(void);
int systemd_listen_fd_for_name(const char *name);

#else /* ESDM_SYSTEMD_SUPPORT */

static inline int systemd_notify(const char *message)
{
	(void)message;
	return 0;
}

static inline int systemd_notify_ready(void) { return 0; }
static inline int systemd_notify_stopping(void) { return 0; }
static inline int systemd_notify_mainpid(pid_t pid)
{
	(void)pid;
	return 0;
}

static inline int systemd_notify_access(char *mode)
{
	(void)mode;
	return 0;
}

static inline int systemd_notify_status(char *msg)
{
	(void)msg;
	return 0;
}

static inline int systemd_listen_pid(void) { return 0; }
static inline int systemd_listen_fds(void) { return 0; }
static inline int systemd_listen_fd_for_name(const char *name)
{
	(void)name;
	return 0;
}

#endif /* ESDM_SYSTEMD_SUPPORT */

#endif /* SYSTEMD_SUPPORT_H */
