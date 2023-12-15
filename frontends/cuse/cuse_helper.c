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
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "cuse_helper.h"
#include "privileges.h"
#include "selinux.h"
#include "esdm_logger.h"

int esdm_cuse_file_name(char *outfile, size_t outfilelen, const char *name)
{
#ifdef ESDM_TESTMODE
	snprintf(outfile, outfilelen, "tst-%s", name);
#else
	snprintf(outfile, outfilelen, "%s", name);
#endif

	return 0;
}

int esdm_cuse_dev_file(char *outfile, size_t outfilelen, const char *name)
{
	if (outfilelen < 5)
		return -EINVAL;

	snprintf(outfile, outfilelen, "/dev/");
	return esdm_cuse_file_name(outfile + 5, outfilelen - 5, name);
}

/******************************************************************************
 * Bind mount handling code
 ******************************************************************************/

/*
 * This is a single instance of an application, thus we allow a global
 * variable.
 */
static int cuse_unlink = 0;

int esdm_cuse_bind_mount(const char *mount_src, const char *mount_dst)
{
	/* This is only to shut up valgrind */
	static const char type[] = "bind";
	struct stat statbuf;

	if (!mount_dst || !mount_src)
		return -EFAULT;

	if (stat(mount_dst, &statbuf)) {
		int errsv = errno, fd;

		if (errsv != ENOENT) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_CUSE,
				"Failed to find destination of bind mount %s: %s\n",
				mount_dst, strerror(errsv));
			return -errsv;
		}

		fd = creat(mount_dst, 0777);
		if (fd < 0) {
			errsv = errno;

			esdm_logger(
				LOGGER_ERR, LOGGER_C_CUSE,
				"Failed to create destination of bind mount %s: %s\n",
				mount_dst, strerror(errsv));
			return -errsv;
		}

		close(fd);
		cuse_unlink = 1;
	}

	if (mount(mount_src, mount_dst, type, MS_BIND, NULL) < 0) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Failed to created bind mount from %s to %s: %s\n",
			    mount_src, mount_dst, strerror(errsv));
		return -errsv;
	}

	if (esdm_cuse_restore_label(mount_dst) < 0) {
		int errsv = errno;

		umount(mount_dst);
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Failed properly relabel %s\n", mount_dst);
		return -errsv;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_CUSE,
		    "Successfully created bind mount from %s to %s\n",
		    mount_src, mount_dst);
	return 0;
}

int esdm_cuse_bind_unmount(char **mount_src, char **mount_dst)
{
#define WAIT_TILL_DETACH (5)
#define WAIT_TILL_FORCE (2 * WAIT_TILL_DETACH)
#define MAX_WAIT_SEC (8 * WAIT_TILL_DETACH)
	char *m_s = *mount_src, *m_d = *mount_dst;
	struct timespec sleep = { 0, 1 << 27 };
	unsigned int ctr = 0;
	int ret, errsv;

	if (!m_d)
		return 0;

	ret = raise_privilege_transient(0, 0);
	if (ret < 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_CUSE,
			"Failed to raise privilege for unmount bind mount\n");
		return ret;
	}

	do {
		errsv = 0;
		if (ctr > WAIT_TILL_FORCE)
			ret = umount2(m_d, MNT_DETACH | MNT_FORCE);
		else if (ctr > WAIT_TILL_DETACH)
			ret = umount2(m_d, MNT_DETACH);
		else
			ret = umount(m_d);
		if (ret < 0 && errno == EBUSY) {
			errsv = errno;
			nanosleep(&sleep, NULL);
			ctr++;
		}
	} while (ret < 0 && errsv == EBUSY && ctr < MAX_WAIT_SEC);

	if (ret < 0) {
		errsv = errno;
		esdm_logger(LOGGER_WARN, LOGGER_C_CUSE,
			    "Failed to remove bind mount from %s\n", m_d);
		ret = -errsv;
	} else {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
			    "Successfully removed bind mount from %s\n", m_d);
	}

	if (cuse_unlink)
		unlink(m_d);

	if (m_s)
		free(m_s);
	*mount_src = NULL;
	if (m_d)
		free(m_d);
	*mount_dst = NULL;

	return ret;
}
