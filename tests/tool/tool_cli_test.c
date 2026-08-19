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
 * Tests for the esdm-tool command line handling - everything that can be
 * observed without a running esdm-server, and without privileges.
 *
 * Three layers, all of them met before the tool does any work:
 *
 * - what it makes of its arguments and what it says when they are wrong. A
 *   silently ignored option, or a refusal with no explanation, is a bug a user
 *   cannot work around.
 * - the refusal of the commands needing root, checked in front of every one of
 *   them, so a command slipping past would fail much later and less clearly.
 * - what each command does when nothing answers it - the ordinary "server is
 *   not running" case, and the only way to reach each handler's error branch.
 *
 * The FIPS check file creation is covered as well: it needs no server and is
 * what the packaging calls to sign the installed binaries, so a regression
 * there breaks an install rather than a command. What the tool does with a
 * server behind it is tests/tool/tool_server_test.c.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "../test_run.h"

static void test_usage(void)
{
	const char *const opts[] = { "-h", NULL };
	struct test_run r;
	int rc = test_run(&r, opts, NULL);

	/*
	 * Asking for help is not an error in the sense of having done anything
	 * wrong, but the tool has nothing to do afterwards and says so with a
	 * non-zero status.
	 */
	CHECK_EQ(rc, EXIT_FAILURE);

	/* The listing has to actually describe the options */
	CHECK(strstr(r.err, "--help") != NULL,
	      "the usage does not mention --help (output: %.200s)", r.err);
	CHECK(strstr(r.err, "--status") != NULL,
	      "the usage does not mention --status");
	CHECK(strstr(r.err, "--get-random") != NULL,
	      "the usage does not mention --get-random");
#ifdef ESDM_FIPS140
	/* Only a FIPS build has the check file options to describe */
	CHECK(strstr(r.err, "--fips-checkfile") != NULL,
	      "the usage does not mention --fips-checkfile");
#endif
}

/* Without a request the tool has nothing to do, and says what it accepts */
static void test_no_arguments(void)
{
	const char *const opts[] = { NULL };
	struct test_run r;
	int rc = test_run(&r, opts, NULL);

	CHECK_EQ(rc, EXIT_FAILURE);
	CHECK(strstr(r.err, "--help") != NULL,
	      "an empty command line was rejected without showing the usage");
}

static void test_unknown_option(void)
{
	const char *const opts[] = { "--no-such-option", NULL };
	struct test_run r;
	int rc = test_run(&r, opts, NULL);

	/* An option the tool does not know must not be quietly ignored */
	CHECK(rc != EXIT_SUCCESS, "an unknown option was accepted (status %d)",
	      rc);
	CHECK(r.err[0] != '\0',
	      "an unknown option was rejected without a word");
}

/*
 * Every numeric argument goes through the same converter, so what is checked
 * here is that each option actually uses it - a missing check would turn
 * garbage into a silent zero.
 */
static void test_malformed_numbers(void)
{
	static const char *const cases[][3] = {
		{ "-r", "12abc", "bytes" },
		{ "-w", "12abc", "seed tries" },
		{ "-B", "not-a-number", "entropy bits" },
		{ "--stress-duration", "1x", "stress-duration" },
		{ "--stress-request-size", "x", "stress-request-size" },
		{ "--timeout-msec", "", "timeout-msec" },
		{ "--reseed-delay-ms", "1.5", "reseed-delay-ms" },
		{ "--max-reseed-secs", "10min", "max reseed seconds" },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const char *const opts[] = { cases[i][0], cases[i][1], NULL };
		struct test_run r;
		int rc = test_run(&r, opts, NULL);

		/*
		 * Trailing garbage is rejected rather than silently truncated
		 * to the part that did parse - asking for "12abc" bytes is a
		 * mistake worth hearing about.
		 */
		CHECK(rc != EXIT_SUCCESS, "%s %s was accepted (status %d)",
		      cases[i][0], cases[i][1], rc);
		CHECK(strstr(r.err, cases[i][2]) != NULL,
		      "%s %s was rejected without naming the argument (output: %.200s)",
		      cases[i][0], cases[i][1], r.err);
	}
}

/* Numbers that parse but cannot mean anything */
static void test_out_of_range_numbers(void)
{
	static const char *const cases[][3] = {
		{ "-r", "-1", "non-negative" },
		{ "-B", "4294967296", "out of range" },
		{ "--stress-request-size", "-1", "out of range" },
		{ "--benchmark-mode", "sideways", "full, pr or both" },
		/* Zero is a value of its own here - a negative one is not */
		{ "--max-reseed-secs", "-1", "out of range" },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const char *const opts[] = { cases[i][0], cases[i][1], NULL };
		struct test_run r;
		int rc = test_run(&r, opts, NULL);

		CHECK(rc != EXIT_SUCCESS, "%s %s was accepted (status %d)",
		      cases[i][0], cases[i][1], rc);
		CHECK(strstr(r.err, cases[i][2]) != NULL,
		      "%s %s was rejected without explaining why (output: %.200s)",
		      cases[i][0], cases[i][1], r.err);
	}
}

/*
 * The commands that change the ESDM's state are refused without root. The
 * check is one condition covering all of them, so each one is listed: an
 * omission there is exactly the kind of mistake that gives an unprivileged
 * caller a confusing failure from deep inside the RPC layer instead.
 */
static void test_privileged_commands_refused(void)
{
	static const char *const cases[][2] = {
		{ "--clear-pool", NULL },
		{ "--reseed-crng", NULL },
		{ "--max-reseed-secs", "60" },
		/*
		 * Zero asks for a reseed before every request rather than
		 * being refused up front, so it gets as far as the root check
		 * like any other interval.
		 */
		{ "--max-reseed-secs", "0" },
		{ "-W", "some entropy" },
		{ "--endless-stress", NULL },
		{ "--selftest", NULL },
		{ "--pkcs11-pin", "1234" },
		{ "--pkcs11-token-label", "a-token" },
#ifdef ESDM_HAS_AUX_CLIENT
		{ "--seed-via-os", NULL },
		{ "--reseed-via-os", NULL },
#endif
	};
	size_t i;

	if (!geteuid()) {
		printf("running as root - skipping the refusal checks\n");
		return;
	}

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const char *const opts[] = { cases[i][0], cases[i][1], NULL };
		struct test_run r;
		int rc = test_run(&r, opts, NULL);

		CHECK_EQ(rc, EXIT_FAILURE);
		CHECK(strstr(r.err, "must start as root") != NULL,
		      "%s was refused without saying root is needed (output: %.200s)",
		      cases[i][0], r.err);
	}
}

/*
 * "--pkcs11-pin -" reads the PIN rather than taking it from the command line,
 * where it would be visible in the process listing.
 */
static void test_pkcs11_pin_from_stdin(void)
{
	const char *const opts[] = { "--pkcs11-pin", "-", NULL };
	struct test_run r;
	int rc;

	if (!geteuid()) {
		printf("running as root - skipping the PIN reading checks\n");
		return;
	}

	/* A PIN is there to be read: the run gets as far as the root check */
	rc = test_run(&r, opts, "1234\n");
	CHECK_EQ(rc, EXIT_FAILURE);
	CHECK(strstr(r.err, "must start as root") != NULL,
	      "the PIN was not read from stdin (output: %.200s)", r.err);

	/* Nothing to read is a failure of its own, and is reported as one */
	rc = test_run(&r, opts, NULL);
	CHECK_EQ(rc, EXIT_FAILURE);
	CHECK(strstr(r.err, "failed to read PKCS#11 PIN") != NULL,
	      "an unreadable PIN was not reported (output: %.200s)", r.err);
}

/*
 * With no server to talk to, every command has to fail in its own way and say
 * so. The runs are started together because each of them spends seconds in the
 * RPC client's connection attempts, and they have nothing to do with each
 * other.
 */
static void test_without_server(void)
{
	static const struct {
		const char *opts[4];
		const char *says;
		int status;
	} cases[] = {
		{ { "-S", NULL }, "fully seeded status failed", EXIT_FAILURE },
		{ { "-r", "16", NULL }, "fetching random data failed",
		  EXIT_FAILURE },
		{ { "-e", NULL }, "entropy count failed", EXIT_FAILURE },
		{ { "-E", NULL }, "entropy level failed", EXIT_FAILURE },
		{ { "--get-seed", NULL }, "Unable to fetch seed", EXIT_FAILURE },
		{ { "-w", "1", NULL }, "Waiting another round", EXIT_FAILURE },
		/*
		 * The status commands report the failure but exit successfully:
		 * they have no result to withhold. Only the message is checked
		 * here, the status is what it is.
		 */
		{ { "-s", NULL }, "Fetching ESDM status failed", -1 },
		{ { "--status-json", NULL }, "Fetching ESDM status failed", -1 },
		{ { "-J", NULL }, "jitterentropy status failed", -1 },
		{ { "--benchmark-mode", "pr", NULL },
		  "Failed to get bytes from ESDM", EXIT_FAILURE },
	};
	static const char *const is_running[] = { "--is-running", NULL };
	struct test_run runs[sizeof(cases) / sizeof(cases[0])];
	size_t i, n = sizeof(cases) / sizeof(cases[0]);
	struct test_run r;

	/*
	 * Ask the tool itself whether anything is listening, which is both the
	 * first case and the guard for the rest: a server of this build's kind
	 * may be running on the machine. The suite's own is in a mount
	 * namespace of its own and cannot be it, but a developer's can, and
	 * everything below expects nothing to answer.
	 */
	if (test_run(&r, is_running, NULL) == EXIT_SUCCESS) {
		printf("an esdm-server is running - skipping the checks that expect none\n");
		return;
	}

	CHECK(strstr(r.err, "ESDM not running") != NULL ||
		      strstr(r.err, "ESDM is not running") != NULL,
	      "--is-running without a server did not say so (output: %.300s)",
	      r.err);

	for (i = 0; i < n; i++) {
		if (test_run_start(&runs[i], cases[i].opts, NULL))
			return;
	}

	for (i = 0; i < n; i++) {
		int rc = test_run_wait(&runs[i]);

		if (cases[i].status != -1)
			CHECK(rc == cases[i].status,
			      "%s without a server: got status %d, expected %d",
			      cases[i].opts[0], rc, cases[i].status);
		CHECK(strstr(runs[i].err, cases[i].says) != NULL,
		      "%s without a server did not report \"%s\" (output: %.300s)",
		      cases[i].opts[0], cases[i].says, runs[i].err);
	}
}

static void test_fips_checkfile(void)
{
	char target[640], checkfile[768];
	const char *opts[5];
	struct test_run r;
	struct stat sb;
	FILE *f;
	int rc;

	snprintf(target, sizeof(target), "%s/esdm_tool_target_%u.bin",
		 test_run_dir, (unsigned int)getpid());
	snprintf(checkfile, sizeof(checkfile), "%s/esdm_tool_check_%u.hmac",
		 test_run_dir, (unsigned int)getpid());
	unlink(checkfile);

	f = fopen(target, "w");
	if (!f) {
		CHECK(0, "cannot create %s: %s", target, strerror(errno));
		return;
	}
	fwrite("esdm-tool check file test\n", 1, 26, f);
	fclose(f);

	opts[0] = "--fips-checkfile";
	opts[1] = checkfile;
	opts[2] = "--fips-targetfile";
	opts[3] = target;
	opts[4] = NULL;

	rc = test_run(&r, opts, NULL);

#ifdef ESDM_FIPS140
	CHECK_EQ(rc, EXIT_SUCCESS);

	/* A SHA-256 HMAC written as hex, plus the newline */
	if (!stat(checkfile, &sb))
		CHECK_EQ(sb.st_size, 65);
	else
		CHECK(0, "no check file was created at %s", checkfile);

	/*
	 * Running it again refuses rather than overwriting: replacing a check
	 * file silently would turn a detected modification into a fresh,
	 * matching digest.
	 */
	rc = test_run(&r, opts, NULL);
	CHECK_EQ(rc, EXIT_FAILURE);
	CHECK(strstr(r.err, "Already existing") != NULL,
	      "the refusal does not say the file exists (output: %.200s)",
	      r.err);
#else
	/* Without FIPS support the request is refused, and explained */
	CHECK_EQ(rc, EXIT_FAILURE);
	CHECK(strstr(r.err, "FIPS disabled") != NULL,
	      "the refusal does not mention FIPS being disabled (output: %.200s)",
	      r.err);
	CHECK(stat(checkfile, &sb) != 0,
	      "a check file was created although FIPS is disabled");
#endif

	unlink(checkfile);
	unlink(target);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("usage: %s <path to esdm-tool>\n", argv[0]);
		return 1;
	}
	if (test_run_init(argv[1]))
		return 1;

	test_usage();
	test_no_arguments();
	test_unknown_option();
	test_malformed_numbers();
	test_out_of_range_numbers();
	test_privileged_commands_refused();
	test_pkcs11_pin_from_stdin();
	test_without_server();
	test_fips_checkfile();

	test_run_fini();

	return common_test_result("tool_cli");
}
