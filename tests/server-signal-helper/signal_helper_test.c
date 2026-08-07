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
 * Tests for esdm-server-signal-helper.
 *
 * The helper is what the suspend and resume systemd units run, so a
 * regression here is only noticed on the next suspend of a deployed system -
 * and then as "the ESDM did not reseed after resume", far away from the cause.
 * Everything it does is decided before any RPC happens: which mode the command
 * line selected, and whether the pidfile it was pointed at holds something
 * worth sending a signal to.
 *
 * The translation unit is compiled into the test so its static functions can
 * be called directly; the build renames its main() out of the way, and the
 * tests below call the renamed one to cover the argument parsing as well.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"

/*
 * The unit under test. Its main() is renamed by the build; declare the renamed
 * one so it does not trip -Wmissing-prototypes, and put the name back
 * afterwards for our own.
 */
int esdm_signal_helper_main_unused(int argc, char **argv);
#include "server_signal_helper.c"

#undef main

/* Set by the SIGUSR1 handler installed below */
static volatile sig_atomic_t got_sigusr1;

static void catch_sigusr1(int sig)
{
	(void)sig;
	got_sigusr1 = 1;
}

/* A pidfile in the test's private directory, holding @content verbatim */
static char pidfile_path[512];

static int write_pidfile(const char *content)
{
	FILE *f = fopen(pidfile_path, "w");

	if (!f)
		return -1;
	if (content && *content)
		fwrite(content, 1, strlen(content), f);
	return fclose(f);
}

static void test_suspend_no_pidfile(void)
{
	/* No --pid at all: nothing to signal, and it must not guess. */
	CHECK(!signal_suspend(NULL), "suspend accepted a NULL pidfile path");
}

static void test_suspend_missing_pidfile(void)
{
	CHECK(!signal_suspend("/nonexistent/esdm-server-signal-helper.pid"),
	      "suspend accepted a pidfile that cannot be opened");
}

static void test_suspend_empty_pidfile(void)
{
	CHECK_EQ(write_pidfile(""), 0);
	CHECK(!signal_suspend(pidfile_path),
	      "suspend accepted an empty pidfile");
}

static void test_suspend_garbage_pidfile(void)
{
	/*
	 * strtol() reports no error for this, it just converts nothing and
	 * returns 0 - so what rejects it is the pid <= 0 test, not errno.
	 */
	CHECK_EQ(write_pidfile("not-a-pid\n"), 0);
	CHECK(!signal_suspend(pidfile_path),
	      "suspend accepted a pidfile holding no number");
}

static void test_suspend_zero_pid(void)
{
	/*
	 * kill(0, ...) signals the whole process group, which here would
	 * include the test runner. This must never reach kill().
	 */
	CHECK_EQ(write_pidfile("0\n"), 0);
	CHECK(!signal_suspend(pidfile_path), "suspend accepted PID 0");
}

static void test_suspend_negative_pid(void)
{
	/* Likewise: a negative PID is a process group for kill(). */
	CHECK_EQ(write_pidfile("-1\n"), 0);
	CHECK(!signal_suspend(pidfile_path), "suspend accepted a negative PID");
}

static void test_suspend_out_of_range_pid(void)
{
	/* This is the one where strtol() does set errno (ERANGE). */
	CHECK_EQ(write_pidfile("999999999999999999999999\n"), 0);
	CHECK(!signal_suspend(pidfile_path),
	      "suspend accepted an out-of-range PID");
}

static void test_suspend_unsignalable_pid(void)
{
	/*
	 * Syntactically fine, but no such process - kill() fails and the
	 * helper has to report that rather than claim success.
	 */
	char buf[32];
	pid_t pid = fork();

	if (pid == 0)
		_exit(0);
	CHECK(pid > 0, "fork failed");
	if (pid <= 0)
		return;

	/* Reap it, so the PID names a process that is gone for good */
	waitpid(pid, NULL, 0);

	snprintf(buf, sizeof(buf), "%d\n", (int)pid);
	CHECK_EQ(write_pidfile(buf), 0);
	CHECK(!signal_suspend(pidfile_path),
	      "suspend claimed success for a PID that cannot be signalled");
}

static void test_suspend_signals(void)
{
	/*
	 * The one case that has to work: point it at ourselves and check that
	 * SIGUSR1 - the signal the server installs its suspend handler for -
	 * actually arrives.
	 */
	char buf[32];

	got_sigusr1 = 0;
	snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
	CHECK_EQ(write_pidfile(buf), 0);
	CHECK(signal_suspend(pidfile_path), "suspend failed for our own PID");
	CHECK(got_sigusr1, "suspend did not deliver SIGUSR1");
}

static void test_suspend_trailing_junk(void)
{
	/*
	 * The server writes the PID followed by a newline; anything trailing
	 * it must not stop the number in front from being used.
	 */
	char buf[64];

	got_sigusr1 = 0;
	snprintf(buf, sizeof(buf), "%d\njunk\n", (int)getpid());
	CHECK_EQ(write_pidfile(buf), 0);
	CHECK(signal_suspend(pidfile_path),
	      "suspend rejected a pidfile with trailing content");
	CHECK(got_sigusr1, "suspend did not deliver SIGUSR1");
}

static void test_resume_without_server(void)
{
	/*
	 * No server is running under this test, so the unprivileged service
	 * cannot be reached and resume signalling has to fail rather than
	 * report a reseed that never happened.
	 */
	CHECK(!signal_resume(), "resume claimed success without a server");
}

/* Run the helper's own main() with a fabricated command line */
static int run_main(int argc, char **argv)
{
	/*
	 * getopt has to be told to start over for each run; on glibc setting
	 * optind to 0 also re-initialises the internal state, which matters
	 * because these argv arrays differ in what they hold.
	 */
	optind = 0;
	errno = 0;
	return esdm_signal_helper_main_unused(argc, argv);
}

static void test_cli_help(void)
{
	char *argv[] = { (char *)"esdm-server-signal-helper", (char *)"--help",
			 NULL };
	char *argv_short[] = { (char *)"esdm-server-signal-helper",
			       (char *)"-h", NULL };

	CHECK_EQ(run_main(2, argv), EXIT_FAILURE);
	CHECK_EQ(run_main(2, argv_short), EXIT_FAILURE);
}

static void test_cli_suspend_without_pid(void)
{
	char *argv[] = { (char *)"esdm-server-signal-helper",
			 (char *)"--suspend", NULL };
	char *argv_short[] = { (char *)"esdm-server-signal-helper",
			       (char *)"-s", NULL };

	/* --suspend with no --pid has nothing to read the PID from */
	CHECK_EQ(run_main(2, argv), EXIT_FAILURE);
	CHECK_EQ(run_main(2, argv_short), EXIT_FAILURE);
}

static void test_cli_suspend_with_pid(void)
{
	char *argv[] = { (char *)"esdm-server-signal-helper", (char *)"--pid",
			 pidfile_path, (char *)"--suspend", NULL };
	char *argv_short[] = { (char *)"esdm-server-signal-helper",
			       (char *)"-p", pidfile_path, (char *)"-s", NULL };
	char buf[32];

	snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
	CHECK_EQ(write_pidfile(buf), 0);

	got_sigusr1 = 0;
	CHECK_EQ(run_main(4, argv), EXIT_SUCCESS);
	CHECK(got_sigusr1, "--pid/--suspend did not deliver SIGUSR1");

	got_sigusr1 = 0;
	CHECK_EQ(run_main(4, argv_short), EXIT_SUCCESS);
	CHECK(got_sigusr1, "-p/-s did not deliver SIGUSR1");
}

static void test_cli_suspend_bad_pidfile(void)
{
	char *argv[] = { (char *)"esdm-server-signal-helper", (char *)"--pid",
			 (char *)"/nonexistent/esdm.pid", (char *)"--suspend",
			 NULL };

	CHECK_EQ(run_main(4, argv), EXIT_FAILURE);
}

static void test_cli_resume(void)
{
	char *argv[] = { (char *)"esdm-server-signal-helper",
			 (char *)"--resume", NULL };

	/* Without a server behind it, resume signalling fails */
	CHECK_EQ(run_main(2, argv), EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	const char *tmpdir = getenv("TMPDIR");

	(void)argc;
	(void)argv;

	snprintf(pidfile_path, sizeof(pidfile_path), "%s/esdm-sighelper-%d.pid",
		 tmpdir && *tmpdir ? tmpdir : "/tmp", (int)getpid());

	/*
	 * Catch the signal the helper sends instead of dying from it - the
	 * default action for SIGUSR1 terminates the process.
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = catch_sigusr1;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		printf("cannot install the SIGUSR1 handler\n");
		return 1;
	}

	test_suspend_no_pidfile();
	test_suspend_missing_pidfile();
	test_suspend_empty_pidfile();
	test_suspend_garbage_pidfile();
	test_suspend_zero_pid();
	test_suspend_negative_pid();
	test_suspend_out_of_range_pid();
	test_suspend_unsignalable_pid();
	test_suspend_signals();
	test_suspend_trailing_junk();

	test_resume_without_server();

	test_cli_help();
	test_cli_suspend_without_pid();
	test_cli_suspend_with_pid();
	test_cli_suspend_bad_pidfile();
	test_cli_resume();

	unlink(pidfile_path);

	return common_test_result("signal_helper");
}
