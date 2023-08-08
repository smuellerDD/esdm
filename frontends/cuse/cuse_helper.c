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

#include <errno.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cuse_helper.h"
#include "privileges.h"
#include "selinux.h"
#include "logger.h"

/******************************************************************************
 * Bind mount handling code
 ******************************************************************************/

int esdm_cuse_bind_mount(const char *mount_src, const char *mount_dst)
{
	/* This is only to shut up valgrind */
	static const char type[] = "bind";

	if (!mount_dst || !mount_src)
		return -EFAULT;

	if (mount(mount_src, mount_dst, type, MS_BIND, NULL) < 0) {
		int errsv = errno;

		logger(LOGGER_ERR, LOGGER_C_CUSE,
		       "Failed to created bind mount from %s to %s: %s\n",
		       mount_src, mount_dst, strerror(errsv));
		return -errsv;
	}

	if (esdm_cuse_restore_label(mount_dst) < 0) {
		int errsv = errno;

		umount(mount_dst);
		logger(LOGGER_ERR, LOGGER_C_CUSE,
		       "Failed properly relabel %s\n", mount_dst);
		return -errsv;
	}

	logger(LOGGER_VERBOSE, LOGGER_C_CUSE,
	       "Successfully created bind mount from %s to %s\n", mount_src,
	       mount_dst);
	return 0;
}

int esdm_cuse_bind_unmount(char **mount_src, char **mount_dst)
{
#define MAX_WAIT_SEC (8 * 5)
	char *m_s = *mount_src, *m_d = *mount_dst;
	struct timespec sleep = { 0, 1 << 27 };
	unsigned int ctr = 0;
	int ret, errsv;

	if (!m_d)
		return 0;

	ret = raise_privilege_transient(0, 0);
	if (ret < 0) {
		logger(LOGGER_WARN, LOGGER_C_CUSE,
		       "Failed to raise privilege for unmount bind mount\n");
		return ret;
	}

	do {
		errsv = 0;
		ret = umount(m_d);
		if (ret < 0 && errno == EBUSY) {
			errsv = errno;
			nanosleep(&sleep, NULL);
			ctr++;
		}
	} while (ret < 0 && errsv == EBUSY && ctr < MAX_WAIT_SEC);

	if (ret < 0) {
		errsv = errno;
		logger(LOGGER_WARN, LOGGER_C_CUSE,
		       "Failed to remove bind mount from %s\n", m_d);
		ret = -errsv;
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_CUSE,
		       "Successfully removed bind mount from %s\n", m_d);
	}

	if (m_s)
		free(m_s);
	*mount_src = NULL;
	if (m_d)
		free(m_d);
	*mount_dst = NULL;

	return ret;
}
