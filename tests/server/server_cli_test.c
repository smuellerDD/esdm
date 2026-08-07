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
 * Tests for the esdm-server command line.
 *
 * The suite starts the daemon in several places, but always the same way: with
 * no options, or with the one or two that particular test needs. Everything
 * else the command line accepts - and everything it says when it is given
 * something it does not accept - was never executed.
 *
 * None of it needs the daemon to come up. The options are parsed before the
 * check that refuses to run as anything but root, so an unprivileged run
 * reaches all of the parsing and stops immediately afterwards, which is exactly
 * the part under test here. What the daemon does after that is covered by every
 * test that starts one.
 *
 * Two of them are their own answer instead: --help prints the usage and
 * --version prints the version, and both exit before anything else happens.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"

#include "../test_run.h"

/* What an unprivileged run gets to say before it stops */
#define TEST_NOT_ROOT "must start as root"

static void test_usage(void)
{
	const char *const help[] = { "-h", NULL };
	const char *const help_long[] = { "--help", NULL };
	struct test_run r;
	int rc = test_run(&r, help, NULL);

	/*
	 * The usage is what someone gets who does not know the options yet, so
	 * having asked for it is not success - there is no daemon afterwards.
	 */
	CHECK_EQ(rc, 1);
	CHECK(strstr(r.err, "ESDM RPC server") != NULL,
	      "the usage does not name the program (output: %.200s)", r.err);

	/*
	 * Spot-check the options that a user has to be told about: the two that
	 * decide who the daemon runs as, the one that keeps it in the
	 * foreground, and the one that hands it a socket to serve.
	 */
	CHECK(strstr(r.err, "--username") != NULL,
	      "the usage does not mention --username");
	CHECK(strstr(r.err, "--groupname") != NULL,
	      "the usage does not mention --groupname");
	CHECK(strstr(r.err, "--foreground") != NULL,
	      "the usage does not mention --foreground");
	CHECK(strstr(r.err, "--egd_socket") != NULL,
	      "the usage does not mention --egd_socket");

	/* The long form is the same answer */
	CHECK_EQ(test_run(&r, help_long, NULL), 1);
	CHECK(strstr(r.err, "ESDM RPC server") != NULL,
	      "--help does not print the usage (output: %.200s)", r.err);
}

static void test_version(void)
{
	const char *const opts[] = { "--version", NULL };
	struct test_run r;
	int rc = test_run(&r, opts, NULL);

	/* Asking what this is has an answer, so it is not a failure */
	CHECK_EQ(rc, 0);
	CHECK(strstr(r.err, "ESDM") != NULL,
	      "the version does not name the ESDM (output: %.200s)", r.err);
	CHECK(strstr(r.err, VERSION) != NULL,
	      "the version does not report " VERSION " (output: %.200s)",
	      r.err);
}

static void test_unknown_option(void)
{
	const char *const unknown[] = { "--no-such-option", NULL };
	const char *const unknown_short[] = { "-Z", NULL };
	struct test_run r;

	/*
	 * An option the daemon does not know is answered with the usage rather
	 * than ignored - starting a daemon that quietly did something other
	 * than what was asked is the outcome to avoid.
	 */
	CHECK_EQ(test_run(&r, unknown, NULL), 1);
	CHECK(strstr(r.err, "Usage") != NULL,
	      "an unknown option was rejected without the usage (output: %.200s)",
	      r.err);

	CHECK_EQ(test_run(&r, unknown_short, NULL), 1);
	CHECK(strstr(r.err, "Usage") != NULL,
	      "an unknown short option was rejected without the usage (output: %.200s)",
	      r.err);
}

/*
 * The options that only set something up for later. All of them are accepted
 * in one go: what each records is not observable from outside, but that the
 * parser takes them - and takes them in either spelling - is.
 */
static void test_options_accepted(void)
{
	static const char *const long_form[] = {
		"--verbose",     "--foreground",  "--force_irqes",
		"--force_schedes", "--memlock",   "--small_memory",
		"--keep_ipc",    "--jent_block_disable",
		"--raise_sched_priority",
		"--username",    "nobody",        "--groupname",
		"nogroup",       NULL
	};
	static const char *const short_form[] = { "-v", "-f",       "-i", "-s",
						  "-m", "-M",       "-P", "-u",
						  "nobody", "-g",   "nogroup",
						  NULL };
	static const char *const sockets[] = { "-e",
					       "/nonexistent/esdm-egd.socket",
					       "-E",
					       "/nonexistent/esdm-egd-pr.socket",
					       NULL };
	static const char *const sockets_long[] = {
		"--egd_socket", "/nonexistent/esdm-egd.socket",
		"--egd_socket_pr", "/nonexistent/esdm-egd-pr.socket", NULL
	};
	struct test_run r;

	if (!geteuid()) {
		printf("running as root - skipping the parse-only checks\n");
		return;
	}

	/*
	 * Each of these gets as far as the privilege check and no further,
	 * which is what says the parser accepted everything before it. A
	 * rejected option would have exited with the usage instead.
	 */
	CHECK_EQ(test_run(&r, long_form, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the long options were not all accepted (output: %.300s)", r.err);

	CHECK_EQ(test_run(&r, short_form, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the short options were not all accepted (output: %.300s)", r.err);

	/*
	 * The EGD sockets are only recorded here - they are bound once the
	 * daemon is up, so a path that cannot exist is accepted at this point.
	 */
	CHECK_EQ(test_run(&r, sockets, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the EGD socket options were not accepted (output: %.300s)",
	      r.err);

	CHECK_EQ(test_run(&r, sockets_long, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the long EGD socket options were not accepted (output: %.300s)",
	      r.err);
}

/*
 * --syslog sends everything the daemon has to say to the system log. The
 * refusal that follows therefore has to be looked for in the exit status: it is
 * no longer on stderr, and that is the point of the option.
 */
static void test_syslog(void)
{
	const char *const opts[] = { "--syslog", NULL };
	const char *const opts_short[] = { "-S", NULL };
	struct test_run r;

	if (!geteuid()) {
		printf("running as root - skipping the syslog checks\n");
		return;
	}

	CHECK_EQ(test_run(&r, opts, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) == NULL,
	      "--syslog left the log on stderr (output: %.300s)", r.err);

	CHECK_EQ(test_run(&r, opts_short, NULL), 1);
}

/*
 * The PID file path is taken while parsing and the file is only created once
 * the daemon starts, so an unprivileged run says nothing about the path - what
 * it does say is that the option was understood.
 */
static void test_pid_file_option(void)
{
	const char *const opts[] = { "--pid", "/nonexistent/esdm.pid", NULL };
	const char *const opts_short[] = { "-p", "/nonexistent/esdm.pid",
					   NULL };
	struct test_run r;

	if (!geteuid()) {
		printf("running as root - skipping the PID file checks\n");
		return;
	}

	CHECK_EQ(test_run(&r, opts, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "--pid was not accepted (output: %.300s)", r.err);

	CHECK_EQ(test_run(&r, opts_short, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "-p was not accepted (output: %.300s)", r.err);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("usage: %s <path to esdm-server>\n", argv[0]);
		return 1;
	}

	if (test_run_init(argv[1]))
		return 1;

	test_usage();
	test_version();
	test_unknown_option();
	test_options_accepted();
	test_syslog();
	test_pid_file_option();

	test_run_fini();

	return common_test_result("server_cli");
}
