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
 * esdm-tool driven against a real esdm-server.
 *
 * tests/tool/tool_cli_test.c covers what the tool decides on its own - the
 * arguments, the refusals, the failure of every command with nothing answering.
 * What is left is the larger half: every command's success path, reachable only
 * with a server behind it. The tool is executed rather than linked, so what is
 * checked is what a user and a script see: the exit status, the message and the
 * bytes on stdout. Skipped (77) unless run as root, since the esdm-server
 * refuses to start otherwise.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "esdm_rpc_service.h"
#include "../test_run.h"

#include "../status_json_check.h"
#include "../test_env.h"
#include "../test_namespace.h"
#include "../test_wait.h"

/*
 * Backstop for a command that never comes back - the tool waiting on a server
 * that stopped answering, say. Below the timeout the test harness applies to
 * the whole run, so the failure is this test's rather than the harness'.
 */
#define TEST_WATCHDOG_SEC 480

/* How long the ESDM is given to reach the fully seeded level */
#define TEST_SEED_TRIES "30"

/* Long enough to exercise the loop, short enough not to dominate the run */
#define TEST_STRESS_DURATION "1"

static pid_t server_pid;

static int server_start(void)
{
	const char *server = getenv("ESDM_SERVER");
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	struct stat sb;

	if (!server || stat(server, &sb) || !S_ISREG(sb.st_mode)) {
		printf("ESDM_SERVER does not point at the esdm-server binary\n");
		return 1;
	}

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	server_pid = fork();
	if (server_pid < 0) {
		printf("fork() failed: %s\n", strerror(errno));
		return 1;
	}

	if (!server_pid) {
		char buf[FILENAME_MAX];
		/*
		 * -f keeps the server in the foreground. Without it it forks
		 * and the process started here exits at once, leaving a daemon
		 * this test can neither wait for nor stop.
		 */
		char *argv[] = { buf, (char *)"-f", NULL };

		snprintf(buf, sizeof(buf), "%s", server);
		execve(server, argv, server_envp);
		_exit(127);
	}

	/* The server is up once it has bound its unprivileged RPC socket */
	if (!test_wait_for_type(ESDM_RPC_UNPRIV_SOCKET, S_IFSOCK,
				TEST_WAIT_TIMEOUT_MS)) {
		printf("the esdm-server did not come up\n");
		return 1;
	}

	return 0;
}

static void server_stop(void)
{
	if (server_pid <= 0)
		return;

	kill(server_pid, SIGTERM);
	waitpid(server_pid, NULL, 0);
	server_pid = 0;
}

/*
 * Announce what is about to run. The commands here take anything from
 * milliseconds to seconds, so a run that is killed - by the watchdog, or by
 * the harness' own timeout - has to say what it was doing at the time.
 */
static void announce(const char *const opts[])
{
	int i;

	printf("  esdm-tool");
	for (i = 0; opts[i]; i++)
		printf(" %s", opts[i]);
	printf("\n");
}

/* Run one command and check that it succeeded */
static void check_ok(const char *const opts[])
{
	struct test_run r;
	int rc;

	announce(opts);
	rc = test_run(&r, opts, NULL);

	CHECK(rc == EXIT_SUCCESS, "%s failed with status %d (output: %.300s)",
	      opts[0], rc, test_run_said(&r));
}

/* Run one command, check that it succeeded and that it said @says */
static void check_says(const char *const opts[], const char *says)
{
	struct test_run r;
	int rc;

	announce(opts);
	rc = test_run(&r, opts, NULL);

	CHECK(rc == EXIT_SUCCESS, "%s failed with status %d (output: %.300s)",
	      opts[0], rc, test_run_said(&r));
	CHECK(strstr(r.err, says) != NULL,
	      "%s did not report \"%s\" (output: %.300s)", opts[0], says,
	      r.err);
}

/*
 * Bound the socket is not the same as answering on it, and every command below
 * would otherwise spend the RPC client's connection attempts finding that out
 * one at a time. Ask once, and stop here if the answer does not come.
 */
static int test_server_answers(void)
{
	const char *const opts[] = { "--is-running", NULL };
	struct test_run r;
	int rc;

	announce(opts);
	rc = test_run(&r, opts, NULL);

	CHECK(rc == EXIT_SUCCESS,
	      "the esdm-server does not answer on its socket (status %d, output: %.300s)",
	      rc, test_run_said(&r));
	CHECK(strstr(r.err, "ESDM is running") != NULL,
	      "--is-running did not report a running ESDM (output: %.300s)",
	      r.err);

	return rc == EXIT_SUCCESS;
}

/*
 * The ESDM needs a moment after startup before it is fully seeded, and the
 * commands below expect it to be - so this is both the first check and the
 * barrier for the rest.
 */
static int test_wait_until_seeded(void)
{
	const char *const opts[] = { "-w", TEST_SEED_TRIES, NULL };
	struct test_run r;
	int rc;

	announce(opts);
	rc = test_run(&r, opts, NULL);

	CHECK(rc == EXIT_SUCCESS,
	      "the ESDM did not become fully seeded within " TEST_SEED_TRIES
	      " tries (status %d, output: %.300s)",
	      rc, test_run_said(&r));
	CHECK(strstr(r.err, "fully seeded") != NULL,
	      "the wait did not report the seeding (output: %.300s)", r.err);

	return rc == EXIT_SUCCESS;
}

static void test_status(void)
{
	const char *const status[] = { "-s", NULL };
	const char *const json[] = { "--status-json", NULL };
	const char *const jent[] = { "-J", NULL };
	const char *const syslog[] = { "--use-syslog", "-s", NULL };
	const char *const verbose[] = { "-v", "-v", "-V", "-s", NULL };
	struct test_run r;
	int rc;

	check_says(status, "Status --");

	/*
	 * The JSON document goes to stdout on its own so it can be piped into
	 * a consumer - which is only true as long as nothing else lands there,
	 * so it is parsed here rather than merely looked at.
	 */
	announce(json);
	rc = test_run(&r, json, NULL);
	CHECK(rc == EXIT_SUCCESS, "--status-json failed with status %d", rc);
	CHECK(!esdm_status_json_check(r.out),
	      "--status-json did not produce a valid status document: %.300s",
	      r.out);

	/* Present or not, the jitterentropy status must not fail the tool */
	check_ok(jent);

	/* The logging switches change where output goes, not whether it works */
	check_ok(syslog);
	check_ok(verbose);
}

static void test_get_random(void)
{
	const char *const hex[] = { "-r", "16", NULL };
	const char *const raw[] = { "-r", "16", "--raw-bytes", NULL };
	const char *const chunked[] = { "-r", "9000", "--raw-bytes", NULL };
	const char *const pr[] = { "--use-pr", "-r", "16", NULL };
	const char *const timeout[] = { "--timeout-msec", "2000", "-r", "16",
					NULL };
	const char *const unseeded[] = { "--allow-unseeded", "-r", "16", NULL };
	struct test_run r;
	size_t i;
	int rc;

	/* Hex is the default: two characters per byte, plus the newline */
	announce(hex);
	rc = test_run(&r, hex, NULL);
	CHECK(rc == EXIT_SUCCESS, "-r failed with status %d (output: %.300s)",
	      rc, test_run_said(&r));
	CHECK_EQ(r.outlen, 33);
	for (i = 0; i + 1 < r.outlen; i++)
		CHECK(strchr("0123456789ABCDEF", r.out[i]) != NULL,
		      "-r produced a non-hex character '%c'", r.out[i]);

	/* --raw-bytes is the byte count itself, for feeding into something */
	announce(raw);
	rc = test_run(&r, raw, NULL);
	CHECK(rc == EXIT_SUCCESS, "-r --raw-bytes failed with status %d", rc);
	CHECK_EQ(r.outlen, 16);

	/*
	 * More than the tool's 8192 byte buffer, so the request is split and
	 * the pieces have to be delivered whole and in order.
	 */
	announce(chunked);
	rc = test_run(&r, chunked, NULL);
	CHECK(rc == EXIT_SUCCESS, "a chunked request failed with status %d",
	      rc);
	CHECK_EQ(r.outlen, 9000);

	/* The other three request modes */
	check_ok(pr);
	check_ok(timeout);
	check_ok(unseeded);
}

static void test_entropy_reporting(void)
{
	const char *const count[] = { "-e", NULL };
	const char *const level[] = { "-E", NULL };
	const char *const seeded[] = { "-S", NULL };

	check_says(count, "Entropy count:");
	check_says(level, "Entropy level:");
	check_says(seeded, "ESDM fully seeded: 1");
}

static void test_get_seed(void)
{
	const char *const hex[] = { "--get-seed", NULL };
	const char *const raw[] = { "--get-seed", "--raw-bytes", NULL };
	const char *const unseeded[] = { "--get-seed", "--allow-unseeded",
					 NULL };
	struct test_run r;
	int rc;

	announce(hex);
	rc = test_run(&r, hex, NULL);

	CHECK(rc == EXIT_SUCCESS,
	      "--get-seed failed with status %d (output: %.300s)", rc,
	      test_run_said(&r));
	CHECK(r.outlen > 0, "--get-seed delivered no seed");

	check_ok(raw);
	check_ok(unseeded);
}

/*
 * The commands that change the ESDM's state rather than reporting on it. They
 * are the ones the tool refuses without root, so they are only driven with it:
 * an unprivileged run would be checking the refusal, which is what
 * tests/tool/tool_cli_test.c does.
 */
static void test_privileged_commands(void)
{
	const char *const write_aux[] = { "-W", "esdm-tool test entropy", "-B",
					  "16", NULL };
	const char *const clear[] = { "--clear-pool", NULL };
	const char *const reseed[] = { "--reseed-crng", NULL };

	if (geteuid()) {
		printf("not root - skipping the privileged commands\n");
		return;
	}

	check_ok(write_aux);
	check_ok(clear);
	check_ok(reseed);

	{
		/* The self tests, run on demand. */
		const char *const selftest[] = { "--selftest", NULL };

		check_says(selftest, "Self tests passed");
	}

#ifdef ESDM_HAS_AUX_CLIENT
	{
		/* Single shot seeding from the OS - the aux pool test helper */
		const char *const seed_via_os[] = { "--seed-via-os", NULL };

		check_ok(seed_via_os);
	}
#endif
}

/*
 * The PKCS#11 credentials are set through the privileged RPC interface. A
 * build without that entropy source refuses the call, which is a legitimate
 * answer - what is checked is that the tool passes the request on and reports
 * the outcome either way, rather than that the source exists.
 */
static void test_pkcs11_config(void)
{
	const char *const literal[] = { "--pkcs11-token-label", "esdm-test",
					"--pkcs11-pin", "1234", NULL };
	const char *const from_stdin[] = { "--pkcs11-pin", "-", NULL };
	struct test_run r;
	int rc;

	/* Also a privileged command, and refused outright without root */
	if (geteuid()) {
		printf("not root - skipping the PKCS#11 configuration\n");
		return;
	}

	announce(literal);
	rc = test_run(&r, literal, NULL);

	CHECK(rc == EXIT_SUCCESS || rc == EXIT_FAILURE,
	      "setting the PKCS#11 configuration ended with status %d", rc);
	CHECK(strstr(r.err, "PKCS#11 configuration updated") != NULL ||
		      strstr(r.err, "failed to update PKCS#11 configuration") !=
			      NULL,
	      "setting the PKCS#11 configuration said nothing about the outcome (output: %.300s)",
	      r.err);

	/* "-" reads the PIN instead of putting it in the process listing */
	announce(from_stdin);
	rc = test_run(&r, from_stdin, "1234\n");
	CHECK(rc == EXIT_SUCCESS || rc == EXIT_FAILURE,
	      "a PIN read from stdin ended with status %d", rc);
	CHECK(strstr(r.err, "PKCS#11") != NULL,
	      "a PIN read from stdin was not passed on (output: %.300s)",
	      r.err);
}

/*
 * The stress and benchmark modes. They are drivers rather than checks - what
 * matters here is that each one runs its loop against a real server and comes
 * back successfully, because a mode that breaks is otherwise only noticed by
 * whoever reaches for it.
 */
static void test_stress_modes(void)
{
	const char *const delay[] = { "--stress-delay", "--stress-duration",
				      TEST_STRESS_DURATION,
				      "--stress-request-size", "32",
				      "--stress-cpu-usage", NULL };
	const char *const thread[] = { "--stress-thread", "--stress-duration",
				       TEST_STRESS_DURATION, NULL };
	const char *const process[] = { "--stress-process", "--stress-duration",
					TEST_STRESS_DURATION, NULL };
	const char *const init_fini[] = { "--stress-init-fini",
					  "--stress-duration",
					  TEST_STRESS_DURATION, NULL };
	const char *const fork_test[] = { "--stress-fork", NULL };

	check_ok(delay);
	check_ok(thread);
	check_ok(process);
	check_ok(init_fini);
	check_ok(fork_test);
}

static void test_benchmark(void)
{
	/*
	 * Only the prediction resistant half: it stops at 64 byte requests and
	 * 20 iterations each, where the full mode runs thousands of iterations
	 * per buffer size and would dominate the suite.
	 */
	const char *const pr[] = { "--benchmark-mode", "pr", NULL };
	struct test_run r;
	int rc;

	announce(pr);
	rc = test_run(&r, pr, NULL);

	CHECK(rc == EXIT_SUCCESS,
	      "--benchmark-mode pr failed with status %d (output: %.300s)", rc,
	      test_run_said(&r));
	CHECK(strstr(r.out, "Data Rate:") != NULL,
	      "the benchmark reported no data rate (output: %.300s)", r.out);
}

/*
 * The endless stress mode runs until something goes wrong, so it is run
 * against a server that is already gone: it then reports the first failure and
 * returns, which is the whole loop.
 */
static void test_endless_stress_without_server(void)
{
	const char *const opts[] = { "--endless-stress", NULL };
	struct test_run r;
	int rc;

	/* Privileged as well, so it is only driven with root */
	if (geteuid()) {
		printf("not root - skipping the endless stress mode\n");
		return;
	}

	announce(opts);
	rc = test_run(&r, opts, NULL);

	CHECK(rc == EXIT_SUCCESS,
	      "--endless-stress ended with status %d (output: %.300s)", rc,
	      test_run_said(&r));
	CHECK(strstr(r.err, "failed to") != NULL,
	      "--endless-stress did not report the failure it stopped on (output: %.300s)",
	      r.err);
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 2) {
		printf("usage: %s <path to esdm-tool>\n", argv[0]);
		return 1;
	}

	/*
	 * The server shares this output, so keep the test's own progress in
	 * step with it - and keep it readable should the run be killed part
	 * way through.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	/*
	 * The server claims the fixed socket, semaphore and IPC names. Run in
	 * namespaces of our own so those cannot collide with another test
	 * using the same ones - see tests/test_namespace.h.
	 */
	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	if (test_run_init(argv[1]))
		return 1;

	if (server_start())
		return 1;

	if (test_server_answers() && test_wait_until_seeded()) {
		test_status();
		test_get_random();
		test_entropy_reporting();
		test_get_seed();
		test_stress_modes();
		test_benchmark();
		test_privileged_commands();
		test_pkcs11_config();
	}

	server_stop();

	test_endless_stress_without_server();

	test_run_fini();

	return common_test_result("tool_server");
}
