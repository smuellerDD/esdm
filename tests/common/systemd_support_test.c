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
 * Tests for common/systemd_support.c - the sd_notify protocol and the socket
 * activation handover, both reimplemented here rather than taken from libsystemd.
 *
 * The notification side is driven against a real AF_UNIX datagram socket this
 * test binds, so the exact bytes that would reach systemd are asserted. The
 * socket activation side latches its answer on first use and keeps it for the
 * process lifetime - deliberately, so a fork cannot make setup and teardown
 * disagree - so each environment needs a process of its own, hence the fork()ed
 * cases below.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"
#include "systemd_support.h"

static int notify_sock = -1;
static char notify_path[128];

/*
 * Run @fn in a child process so it can latch its own socket activation state,
 * and fold the checks it failed into this process' count.
 */
static void run_child(void (*fn)(void), const char *name)
{
	pid_t pid = fork();
	int status;

	if (pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return;
	}

	if (!pid) {
		common_test_failures = 0;
		fn();
		/*
		 * exit() rather than _exit(): the exit handlers have to run so
		 * an instrumented build writes out the coverage these children
		 * collected. Safe because nothing is buffered on stdout at fork
		 * time - the checks report on unbuffered stderr and the summary
		 * is printed once every child has been reaped.
		 */
		exit(common_test_failures > 200 ?
			     200 :
			     (int)common_test_failures);
	}

	if (waitpid(pid, &status, 0) != pid) {
		CHECK(0, "waitpid() for %s failed: %s", name, strerror(errno));
		return;
	}

	if (!WIFEXITED(status)) {
		CHECK(0, "%s died abnormally (status %d)", name, status);
		return;
	}

	if (WEXITSTATUS(status))
		common_test_failures += (unsigned int)WEXITSTATUS(status);
}

static bool notify_socket_setup(void)
{
	struct sockaddr_un sun;
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";

	snprintf(notify_path, sizeof(notify_path), "%s/esdm_notify_test_%u.sock",
		 tmp, (unsigned int)getpid());
	unlink(notify_path);

	notify_sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (notify_sock < 0) {
		CHECK(0, "socket() failed: %s", strerror(errno));
		return false;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlen(notify_path) >= sizeof(sun.sun_path)) {
		CHECK(0, "the temporary directory yields an overlong socket path");
		return false;
	}
	memcpy(sun.sun_path, notify_path, strlen(notify_path));

	if (bind(notify_sock, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		CHECK(0, "bind(%s) failed: %s", notify_path, strerror(errno));
		return false;
	}

	/* Never block on a message that a broken implementation never sends */
	setsockopt(notify_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	setenv("NOTIFY_SOCKET", notify_path, 1);
	return true;
}

static void notify_socket_teardown(void)
{
	if (notify_sock >= 0)
		close(notify_sock);
	notify_sock = -1;
	unlink(notify_path);
	unsetenv("NOTIFY_SOCKET");
}

/* Assert on the exact payload that arrived at the notification socket */
static void expect_message(const char *expected)
{
	char buf[4200];
	ssize_t rd = recv(notify_sock, buf, sizeof(buf) - 1, 0);

	if (rd < 0) {
		CHECK(0, "no notification arrived (expected \"%s\"): %s",
		      expected, strerror(errno));
		return;
	}

	buf[rd] = '\0';
	CHECK_STR_EQ(buf, expected);
}

static void test_notify_argument_checks(void)
{
	/* The message is validated before anything else is looked at */
	setenv("NOTIFY_SOCKET", "/nonexistent/notify.sock", 1);
	CHECK_EQ(systemd_notify(NULL), -EINVAL);
	CHECK_EQ(systemd_notify(""), -EINVAL);
	unsetenv("NOTIFY_SOCKET");

	/* Without the environment variable the protocol is a no-op */
	CHECK_EQ(systemd_notify("READY=1"), 0);
	CHECK_EQ(systemd_notify_ready(), 0);
	CHECK_EQ(systemd_notify_stopping(), 0);
	CHECK_EQ(systemd_notify_mainpid(getpid()), 0);
	CHECK_EQ(systemd_notify_access("all"), 0);
	CHECK_EQ(systemd_notify_status("idle"), 0);
}

static void test_notify_socket_validation(void)
{
	char toolong[160];

	/* Only path and abstract AF_UNIX sockets are supported */
	setenv("NOTIFY_SOCKET", "relative/notify.sock", 1);
	CHECK_EQ(systemd_notify("READY=1"), -EAFNOSUPPORT);
	setenv("NOTIFY_SOCKET", "tcp://localhost:1234", 1);
	CHECK_EQ(systemd_notify("READY=1"), -EAFNOSUPPORT);

	/* A path that does not fit into sun_path is rejected, not truncated */
	memset(toolong, 'a', sizeof(toolong) - 1);
	toolong[0] = '/';
	toolong[sizeof(toolong) - 1] = '\0';
	setenv("NOTIFY_SOCKET", toolong, 1);
	CHECK_EQ(systemd_notify("READY=1"), -E2BIG);

	/* A well formed path with nothing listening reports the connect error */
	setenv("NOTIFY_SOCKET", "/nonexistent-directory/notify.sock", 1);
	CHECK_EQ(systemd_notify("READY=1"), -ENOENT);

	unsetenv("NOTIFY_SOCKET");
}

static void test_notify_messages(void)
{
	if (!notify_socket_setup()) {
		notify_socket_teardown();
		return;
	}

	CHECK_EQ(systemd_notify("READY=1"), 1);
	expect_message("READY=1");

	CHECK_EQ(systemd_notify_ready(), 1);
	expect_message("READY=1");

	CHECK_EQ(systemd_notify_stopping(), 1);
	expect_message("STOPPING=1");

	{
		char expect[64];

		CHECK_EQ(systemd_notify_mainpid(4711), 1);
		snprintf(expect, sizeof(expect), "MAINPID=%d", 4711);
		expect_message(expect);
	}

	CHECK_EQ(systemd_notify_access("main"), 1);
	expect_message("NOTIFYACCESS=main");

	CHECK_EQ(systemd_notify_status("waiting for entropy"), 1);
	expect_message("STATUS=waiting for entropy");

	notify_socket_teardown();
}

static void test_notify_abstract_socket(void)
{
	struct sockaddr_un sun;
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	char name[64];
	socklen_t len;
	int fd;

	snprintf(name, sizeof(name), "esdm_notify_test_%u",
		 (unsigned int)getpid());

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		CHECK(0, "socket() failed: %s", strerror(errno));
		return;
	}

	/* An abstract socket has a leading NUL instead of a path component */
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path + 1, name, strlen(name));
	len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
			  strlen(name));

	if (bind(fd, (struct sockaddr *)&sun, len) < 0) {
		CHECK(0, "bind(@%s) failed: %s", name, strerror(errno));
		close(fd);
		return;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	{
		char env[80];

		snprintf(env, sizeof(env), "@%s", name);
		setenv("NOTIFY_SOCKET", env, 1);
	}

	notify_sock = fd;
	CHECK_EQ(systemd_notify_ready(), 1);
	expect_message("READY=1");
	notify_sock = -1;

	close(fd);
	unsetenv("NOTIFY_SOCKET");
}

static void test_listen_pid(void)
{
	unsetenv("LISTEN_PID");
	CHECK_EQ(systemd_listen_pid(), -1);

	/* Anything that is not a plain positive number is refused */
	setenv("LISTEN_PID", "", 1);
	CHECK_EQ(systemd_listen_pid(), -1);
	setenv("LISTEN_PID", "abc", 1);
	CHECK_EQ(systemd_listen_pid(), -1);
	setenv("LISTEN_PID", "12x", 1);
	CHECK_EQ(systemd_listen_pid(), -1);
	setenv("LISTEN_PID", "0", 1);
	CHECK_EQ(systemd_listen_pid(), -1);
	setenv("LISTEN_PID", "-5", 1);
	CHECK_EQ(systemd_listen_pid(), -1);
	setenv("LISTEN_PID", "99999999999999999999999", 1);
	CHECK_EQ(systemd_listen_pid(), -1);

	setenv("LISTEN_PID", "1234", 1);
	CHECK_EQ(systemd_listen_pid(), 1234);

	{
		char own[32];

		snprintf(own, sizeof(own), "%d", getpid());
		setenv("LISTEN_PID", own, 1);
		CHECK_EQ(systemd_listen_pid(), getpid());
	}

	unsetenv("LISTEN_PID");
}

static void set_listen_env(const char *fds, bool own_pid, const char *names)
{
	if (fds)
		setenv("LISTEN_FDS", fds, 1);
	else
		unsetenv("LISTEN_FDS");

	if (own_pid) {
		char own[32];

		snprintf(own, sizeof(own), "%d", getpid());
		setenv("LISTEN_PID", own, 1);
	} else {
		unsetenv("LISTEN_PID");
	}

	if (names)
		setenv("LISTEN_FDNAMES", names, 1);
	else
		unsetenv("LISTEN_FDNAMES");
}

static void child_no_listen_fds(void)
{
	set_listen_env(NULL, false, NULL);
	CHECK_EQ(systemd_listen_fds(), -1);
	/* No descriptors means no name can be resolved either */
	CHECK_EQ(systemd_listen_fd_for_name("unpriv"), -1);
}

static void child_zero_listen_fds(void)
{
	set_listen_env("0", true, "unpriv");
	CHECK_EQ(systemd_listen_fds(), -1);
	CHECK_EQ(systemd_listen_fd_for_name("unpriv"), -1);
}

static void child_malformed_listen_fds(void)
{
	set_listen_env("not-a-number", true, NULL);
	CHECK_EQ(systemd_listen_fds(), -1);
}

static void child_negative_listen_fds(void)
{
	set_listen_env("-1", true, NULL);
	CHECK_EQ(systemd_listen_fds(), -1);
}

static void child_matching_pid(void)
{
	set_listen_env("2", true, NULL);
	CHECK_EQ(systemd_listen_fds(), 2);
}

static void child_without_pid(void)
{
	/*
	 * Not every socket activation implementation sets LISTEN_PID, so the
	 * descriptors are accepted when it is absent.
	 */
	set_listen_env("3", false, NULL);
	CHECK_EQ(systemd_listen_fds(), 3);
}

static void child_foreign_pid(void)
{
	/*
	 * A LISTEN_PID naming somebody else means the descriptors were meant
	 * for another process and only happened to be inherited.
	 */
	set_listen_env("2", false, NULL);
	setenv("LISTEN_PID", "1", 1);
	CHECK_EQ(systemd_listen_fds(), -1);
}

static void child_latching(void)
{
	set_listen_env("2", true, NULL);
	CHECK_EQ(systemd_listen_fds(), 2);

	/*
	 * The answer is latched on first use: a later environment change - or a
	 * fork that invalidates LISTEN_PID - must not change it.
	 */
	set_listen_env("7", false, NULL);
	setenv("LISTEN_PID", "1", 1);
	CHECK_EQ(systemd_listen_fds(), 2);

	unsetenv("LISTEN_FDS");
	CHECK_EQ(systemd_listen_fds(), 2);

	/* An explicit re-initialization does not reopen the question either */
	systemd_listen_fds_init();
	CHECK_EQ(systemd_listen_fds(), 2);
}

static void child_fd_for_name(void)
{
	set_listen_env("3", true, "unpriv:priv:egd");

	/* The names map onto consecutive descriptors from the handover start */
	CHECK_EQ(systemd_listen_fd_for_name("unpriv"),
		 SYSTEMD_LISTEN_FDS_START);
	CHECK_EQ(systemd_listen_fd_for_name("priv"),
		 SYSTEMD_LISTEN_FDS_START + 1);
	CHECK_EQ(systemd_listen_fd_for_name("egd"),
		 SYSTEMD_LISTEN_FDS_START + 2);

	/* An unknown name resolves to nothing */
	CHECK_EQ(systemd_listen_fd_for_name("does-not-exist"), -1);
	CHECK_EQ(systemd_listen_fd_for_name(""), -1);
}

static void child_fd_for_single_name(void)
{
	/* Without a separator the whole value is one name */
	set_listen_env("1", true, "unpriv");
	CHECK_EQ(systemd_listen_fd_for_name("unpriv"),
		 SYSTEMD_LISTEN_FDS_START);
	CHECK_EQ(systemd_listen_fd_for_name("priv"), -1);
}

static void child_fd_for_name_beyond_fds(void)
{
	/*
	 * More names than descriptors: only the names covered by an actual
	 * descriptor resolve, the rest are ignored rather than pointing at a
	 * descriptor that was never handed over.
	 */
	set_listen_env("2", true, "unpriv:priv:egd:extra");
	CHECK_EQ(systemd_listen_fd_for_name("unpriv"),
		 SYSTEMD_LISTEN_FDS_START);
	CHECK_EQ(systemd_listen_fd_for_name("priv"),
		 SYSTEMD_LISTEN_FDS_START + 1);
	CHECK_EQ(systemd_listen_fd_for_name("egd"), -1);
	CHECK_EQ(systemd_listen_fd_for_name("extra"), -1);
}

static void child_fd_names_unset(void)
{
	set_listen_env("2", true, NULL);
	CHECK_EQ(systemd_listen_fd_for_name("unpriv"), -1);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_notify_argument_checks();
	test_notify_socket_validation();
	test_notify_messages();
	test_notify_abstract_socket();
	test_listen_pid();

	run_child(child_no_listen_fds, "no LISTEN_FDS");
	run_child(child_zero_listen_fds, "LISTEN_FDS=0");
	run_child(child_malformed_listen_fds, "malformed LISTEN_FDS");
	run_child(child_negative_listen_fds, "negative LISTEN_FDS");
	run_child(child_matching_pid, "matching LISTEN_PID");
	run_child(child_without_pid, "absent LISTEN_PID");
	run_child(child_foreign_pid, "foreign LISTEN_PID");
	run_child(child_latching, "latched handover state");
	run_child(child_fd_for_name, "LISTEN_FDNAMES lookup");
	run_child(child_fd_for_single_name, "single LISTEN_FDNAMES entry");
	run_child(child_fd_for_name_beyond_fds, "more names than descriptors");
	run_child(child_fd_names_unset, "no LISTEN_FDNAMES");

	return common_test_result("systemd_support");
}
