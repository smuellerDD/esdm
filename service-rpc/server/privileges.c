/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include "linux_support.h"
#include "esdm_logger.h"
#include "privileges.h"
#include "visibility.h"

int drop_privileges_permanent(const char *user, const char *group)
{
	const struct group *grp;
	const struct passwd *pwd;

	uid_t uid;
	gid_t gid;
	int ret = 0;

	if (!user)
		return -EINVAL;

	if (group != NULL) {
		grp = getgrnam(group);
		if (!grp) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Group %s unknown\n", group);
			return -ENOENT;
		}
	} else {
		grp = NULL;
	}

	ret = linux_isolate_namespace();
	if (ret)
		return ret;

	pwd = getpwnam(user);
	if (pwd == NULL) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY, "User %s unknown\n",
			    user);
		return -ENOENT;
	}

	uid = pwd->pw_uid;
	gid = pwd->pw_gid;

	if (grp) {
		if (setgroups(1, &grp->gr_gid) == -1) {
			ret = -errno;
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Cannot set supplemental groups: %s\n",
				    strerror(errno));
			return ret;
		}
	} else {
		/* Drop all supplemental groups */
		if (setgroups(0, NULL) == -1) {
			ret = -errno;
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Cannot clear supplemental groups: %s\n",
				    strerror(errno));
			return ret;
		}
	}

	/* Drop privileged group */
	if (setgid(gid) == -1) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to unprivileged group: %s\n",
			    strerror(errno));
		return ret;
	}

	/* Drop privileged user */
	if (setuid(uid) == -1) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to unprivileged user: %s\n",
			    strerror(errno));
		return ret;
	}

	if ((chdir("/")) < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot change directory: %s\n", strerror(errno));
		return ret;
	}

	esdm_logger(
		LOGGER_VERBOSE, LOGGER_C_ANY,
		"Successfully dropped privileges to user %s (UID %u, GID %u)\n",
		user, uid, gid);

	return 0;
}
