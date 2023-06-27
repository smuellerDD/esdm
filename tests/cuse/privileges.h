/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef PRIVILEGES_H
#define PRIVILEGES_H

#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif

static inline void set_privileges(uid_t uid, gid_t gid)
{
	if (setegid(gid) == -1) {
		printf("Cannot drop to unprivileged group: %s\n",
		       strerror(errno));
	}

	/* Drop privileged user */
	if (seteuid(uid) == -1) {
		printf("Cannot drop to unprivileged user: %s\n",
		       strerror(errno));
	}
}

static inline void drop_privileges(void)
{
	set_privileges(65534, 65534);
}

static inline void raise_privilege(void)
{
	set_privileges(0, 0);
}

static inline int check_priv(void)
{
	if (getuid() != 0) {
		printf("Test must run as root\n");
		return EPERM;
	}
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* PRIVILEGES_H */
