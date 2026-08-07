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

/*
 * Give a test that drives the ESDM in process its own System V IPC namespace.
 *
 * Those tests reach for machine-global names of two kinds: esdm_shm_status keys
 * its System V segment with ftok() and opens POSIX semaphores in /dev/shm. Two
 * tests at once share both, and either left behind by a run that died denies
 * every later unprivileged run with esdm_init() = -13, which reads like a
 * defect rather than a leftover. The two need different treatment: an IPC
 * namespace covers the System V side, the semaphores need a private /dev/shm.
 *
 * /tmp is deliberately left alone: unlike the daemon-starting tests these never
 * bind the RPC sockets, and whatever they put there they name with mkdtemp() -
 * so nothing collides, and a build tree below /tmp stays visible without the
 * pinning tests/test_namespace.h needs.
 *
 * How the namespaces are obtained depends on who runs the test:
 *
 * - Real root unshares directly, and must not take the user namespace of the
 *   other case: the ESDM drops privileges with setgroups(), denied inside one.
 * - An unprivileged test has no capabilities to unshare with, so a user
 *   namespace supplies the full set CLONE_NEWIPC requires. The identity mapping
 *   keeps the process' own credentials, so it does not appear to be root, which
 *   would send the code under test down other paths.
 *
 * Best effort: a kernel with unprivileged user namespaces disabled simply
 * leaves the test sharing the machine's IPC namespace. Runs as a constructor so
 * no test has to call it, and early (priority 101) so it precedes anything that
 * might already touch the segment.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

static int test_ipc_ns_write(const char *path, const char *value)
{
	ssize_t len = (ssize_t)__builtin_strlen(value);
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	int ret = 0;

	if (fd < 0)
		return -1;

	if (write(fd, value, (size_t)len) != len)
		ret = -1;

	close(fd);

	return ret;
}

/* The unprivileged case: borrow the capabilities from a user namespace */
static int test_ipc_ns_unshare_unpriv(void)
{
	char map[64];
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC) < 0)
		return -1;

	/*
	 * Map our own credentials onto themselves. setgroups has to be denied
	 * before the group map is accepted.
	 */
	snprintf(map, sizeof(map), "%u %u 1", (unsigned int)uid,
		 (unsigned int)uid);
	if (test_ipc_ns_write("/proc/self/uid_map", map))
		return -1;

	test_ipc_ns_write("/proc/self/setgroups", "deny");

	snprintf(map, sizeof(map), "%u %u 1", (unsigned int)gid,
		 (unsigned int)gid);
	test_ipc_ns_write("/proc/self/gid_map", map);

	return 0;
}

__attribute__((constructor(101))) static void test_ipc_ns_init(void);
static void test_ipc_ns_init(void)
{
	if (!geteuid()) {
		if (unshare(CLONE_NEWNS | CLONE_NEWIPC) < 0)
			return;
	} else if (test_ipc_ns_unshare_unpriv()) {
		return;
	}

	/*
	 * The POSIX semaphores are files, so the IPC namespace does nothing for
	 * them - give them a /dev/shm of their own. Detach propagation first so
	 * this cannot escape onto the machine.
	 */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		return;

	mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL);
}
