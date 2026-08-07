/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

#ifndef TEST_NAMESPACE_H
#define TEST_NAMESPACE_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * A build tree below /tmp would be hidden by the private /tmp mounted below,
 * taking with it the daemons the test still has to exec and the coverage
 * counters it writes on exit. Keep the top level /tmp directory such a path
 * belongs to: the names that have to become private - the RPC sockets - live
 * directly in /tmp, not inside it.
 *
 * The directory is pinned with an O_PATH descriptor taken before the mount, so
 * it can be bound back afterwards through /proc/self/fd without leaving a
 * helper mount point behind anywhere.
 */
#define TEST_NS_KEEP_MAX 2

struct test_ns_keep {
	char name[256];
	int fd;
};

/* First path component below /tmp, e.g. "/tmp/build-x/y" -> "build-x" */
static inline int test_ns_tmp_entry(const char *path, char *out, size_t outlen)
{
	const char *start, *end;
	size_t len;

	if (!path || strncmp(path, "/tmp/", 5))
		return -1;

	start = path + 5;
	end = strchr(start, '/');
	len = end ? (size_t)(end - start) : strlen(start);
	if (!len || len >= outlen)
		return -1;

	memcpy(out, start, len);
	out[len] = '\0';

	return 0;
}

static inline void test_ns_pin(struct test_ns_keep *keep, unsigned int *n,
			       const char *path)
{
	char name[sizeof(keep[0].name)];
	char full[sizeof(keep[0].name) + 8];
	unsigned int i;

	if (*n >= TEST_NS_KEEP_MAX || test_ns_tmp_entry(path, name, sizeof(name)))
		return;

	/* Several of the paths normally live in the same tree */
	for (i = 0; i < *n; i++) {
		if (!strcmp(keep[i].name, name))
			return;
	}

	snprintf(full, sizeof(full), "/tmp/%.*s", (int)(sizeof(name) - 1),
		 name);

	keep[*n].fd = open(full, O_PATH | O_CLOEXEC);
	if (keep[*n].fd < 0)
		return;

	memcpy(keep[*n].name, name, sizeof(name));
	(*n)++;
}

/* Bind a pinned directory back to where it was before /tmp was replaced */
static inline int test_ns_restore(struct test_ns_keep *keep, unsigned int n)
{
	char target[sizeof(keep[0].name) + 8];
	char source[64];
	struct stat sb;
	unsigned int i;
	int ret = 0;

	for (i = 0; i < n; i++) {
		/* Bound the conversion so the destination provably fits */
		snprintf(target, sizeof(target), "/tmp/%.*s",
			 (int)(sizeof(keep[i].name) - 1), keep[i].name);
		snprintf(source, sizeof(source), "/proc/self/fd/%d",
			 keep[i].fd);

		if (fstat(keep[i].fd, &sb) < 0) {
			ret = -errno;
			break;
		}

		if (S_ISDIR(sb.st_mode)) {
			if (mkdir(target, 0755) < 0 && errno != EEXIST) {
				ret = -errno;
				break;
			}
		} else {
			int fd = open(target, O_WRONLY | O_CREAT | O_CLOEXEC,
				      0644);

			if (fd < 0) {
				ret = -errno;
				break;
			}
			close(fd);
		}

		if (mount(source, target, NULL, MS_BIND | MS_REC, NULL) < 0) {
			ret = -errno;
			break;
		}
	}

	for (i = 0; i < n; i++)
		close(keep[i].fd);

	return ret;
}

/*
 * Give a privileged test its own mount and IPC namespace.
 *
 * Everything the ESDM uses to find itself is a machine-global name: the RPC
 * sockets at fixed paths under /tmp, the POSIX semaphores in /dev/shm, and the
 * System V segments keyed by ftok(). Two tests running at once therefore fight
 * over the same names - the second server cannot bind, or worse, a client
 * silently talks to the other test's daemon - and a test that dies leaves those
 * names behind for whatever runs next.
 *
 * Unsharing the mount and IPC namespaces makes all of them private to the
 * process and the daemons it forks. That is what allows the privileged tests to
 * run in parallel, and it also stops a failed run from poisoning the machine:
 * the namespace and everything named in it is gone once the test exits.
 *
 * Requires real root - CLONE_NEWNS needs CAP_SYS_ADMIN, and a user namespace is
 * no substitute here because the ESDM drops privileges with setgroups(), which
 * is denied inside one.
 */
static inline int test_isolate_namespaces(void)
{
	struct test_ns_keep keep[TEST_NS_KEEP_MAX];
	unsigned int nkeep = 0;
	char self[4096];
	ssize_t len;

	if (unshare(CLONE_NEWNS | CLONE_NEWIPC) < 0)
		return -errno;

	/*
	 * Detach from the host's propagation so nothing mounted below shows up
	 * outside - without this a shared / would push the tmpfs onto the
	 * machine and defeat the point.
	 */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		return -errno;

	/* The POSIX semaphores of the shm status interface live here */
	if (mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL) < 0)
		return -errno;

	/*
	 * The RPC sockets live directly in /tmp, so a private one is what lets
	 * two servers coexist. Pin whatever the test still needs from there
	 * first - a build tree below /tmp holds the daemons it has to exec and
	 * is where its coverage counters are written on exit, and the mount
	 * would otherwise hide both.
	 */
	len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (len > 0) {
		self[len] = '\0';
		test_ns_pin(keep, &nkeep, self);
	}
	test_ns_pin(keep, &nkeep, getenv("ESDM_SERVER"));

	if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
		return -errno;

	return test_ns_restore(keep, nkeep);
}

#endif /* TEST_NAMESPACE_H */
