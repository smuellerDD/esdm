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

/*
 * systemd socket activation related code
 */
#define SYSTEMD_LISTEN_FDS_START 3

int systemd_listen_pid(void);
int systemd_listen_fds(void);
int systemd_listen_fd_for_name(const char *name);

#endif
