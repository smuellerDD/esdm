/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#define _DEFAULT_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "privileges.h"
#include "visibility.h"

int drop_privileges_transient(const char *user)
{
	const struct passwd *pwd;
	static uid_t uid = 0;
	static gid_t gid = 0;
	int ret = 0;

	if (!user)
		return -EINVAL;

	if (gid == 0 || uid == 0) {
		pwd = getpwnam(user);
		if (pwd == NULL) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "User %s unknown\n", user);
			return -ENOENT;
		}

		uid = pwd->pw_uid;
		gid = pwd->pw_gid;

		/* Drop all supplemental groups */
		if (setgroups(0, NULL) == -1) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Cannot clear supplemental groups: %s\n",
				    strerror(errno));
		}
	}

	/* Drop privileged group */
	if (setegid(gid) == -1) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to unprivileged group: %s\n",
			    strerror(errno));
	}

	/* Drop privileged user */
	if (seteuid(uid) == -1) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to unprivileged user: %s\n",
			    strerror(errno));
	}

	esdm_logger(
		LOGGER_VERBOSE, LOGGER_C_ANY,
		"Successfully dropped privileges to user %s (UID %u, GID %u)\n",
		user, uid, gid);

	return ret;
}

int raise_privilege_transient(uid_t uid, gid_t gid)
{
	/* Raise privileged group */
	if (setegid(gid) == -1) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot raise to group %u: %s\n", gid,
			    strerror(errsv));
		return -errsv;
	}

	/* Drop privileged user */
	if (seteuid(uid) == -1) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to user %u: %s\n", uid,
			    strerror(errsv));
		return -errsv;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "Successfully raised privileges to UID %u, GID %u\n", uid,
		    gid);

	return 0;
}
