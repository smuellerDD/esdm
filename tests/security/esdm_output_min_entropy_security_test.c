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
 * Assess 1 MiB of esdm_get_random_bytes_full() output with the SP800-90B
 * non-IID estimators of ea_non_iid: more than 6 bits of min-entropy per byte
 * are required. Full entropy scores close to 8, so 6 or less points at a
 * broken DRNG, not at estimator noise. Skips without ea_non_iid.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_logger.h"
#include "../test_plan.h"

#define ESDM_SEC_BYTES (1024 * 1024)
#define ESDM_SEC_MIN_BITS 6.0

static char esdm_sec_workdir[400];

/* esdm_sec_run_ea_non_iid() results other than an exit status of ea_non_iid */
#define ESDM_SEC_EA_NOT_INSTALLED -1 /* not found on PATH - skip */
#define ESDM_SEC_EA_SETUP_ERROR -2 /* the test could not run it - hard error */
#define ESDM_SEC_EA_ABNORMAL -3 /* it died from a signal - failure */

/* What the child reports through the pipe when it does not get to exec */
struct esdm_sec_ea_child_err {
	int chdir_failed;
	int err;
};

/*
 * Run ea_non_iid in esdm_sec_workdir with relative paths, as its usage asks.
 * Returns its exit status or an ESDM_SEC_EA_* code. A failed chdir() or
 * execvp() is reported through a close-on-exec pipe, as any exit code could be
 * ea_non_iid's own.
 */
static int esdm_sec_run_ea_non_iid(void)
{
	char *argv[] = {
		(char *)"ea_non_iid", (char *)"-i", (char *)"-v",
		(char *)"-a",	      (char *)"-o", (char *)"result.json",
		(char *)"random.bin", (char *)"8",  NULL
	};
	struct esdm_sec_ea_child_err cerr = { 0, 0 };
	int pipefd[2], status;
	ssize_t rc;
	pid_t pid;

	if (pipe2(pipefd, O_CLOEXEC) < 0) {
		printf("cannot create a pipe: %s\n", strerror(errno));
		return ESDM_SEC_EA_SETUP_ERROR;
	}

	/* What was printed so far comes before the output of ea_non_iid */
	fflush(stdout);
	pid = fork();
	if (pid < 0) {
		printf("cannot fork: %s\n", strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		return ESDM_SEC_EA_SETUP_ERROR;
	}

	if (pid == 0) {
		/* Its verbose report goes to the log, the JSON file is read */
		close(pipefd[0]);
		if (chdir(esdm_sec_workdir) < 0) {
			cerr.chdir_failed = 1;
			cerr.err = errno;
		} else {
			execvp("ea_non_iid", argv);
			cerr.err = errno;
		}
		/* If this fails, the parent sees a short read */
		rc = write(pipefd[1], &cerr, sizeof(cerr));
		(void)rc;
		_exit(127);
	}

	close(pipefd[1]);
	do {
		rc = read(pipefd[0], &cerr, sizeof(cerr));
	} while (rc < 0 && errno == EINTR);
	close(pipefd[0]);

	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			printf("cannot wait for ea_non_iid: %s\n",
			       strerror(errno));
			return ESDM_SEC_EA_SETUP_ERROR;
		}
	}

	if (rc == sizeof(cerr)) {
		if (cerr.chdir_failed) {
			printf("cannot change to %s: %s\n", esdm_sec_workdir,
			       strerror(cerr.err));
			return ESDM_SEC_EA_SETUP_ERROR;
		}
		printf("cannot execute ea_non_iid: %s\n", strerror(cerr.err));
		return cerr.err == ENOENT ? ESDM_SEC_EA_NOT_INSTALLED :
					    ESDM_SEC_EA_SETUP_ERROR;
	}
	if (rc != 0) {
		printf("cannot tell whether ea_non_iid started\n");
		return ESDM_SEC_EA_SETUP_ERROR;
	}

	if (!WIFEXITED(status)) {
		printf("ea_non_iid terminated abnormally\n");
		return ESDM_SEC_EA_ABNORMAL;
	}
	return WEXITSTATUS(status);
}

static int esdm_sec_write_samples(void)
{
	char path[sizeof(esdm_sec_workdir) + 16];
	uint8_t *buf;
	size_t written = 0;
	ssize_t rc;
	FILE *f;
	int ret = 1;

	buf = malloc(ESDM_SEC_BYTES);
	if (!buf)
		return 1;

	TEST_STEP("request %d bytes from esdm_get_random_bytes_full",
		  ESDM_SEC_BYTES);
	rc = esdm_get_random_bytes_full(buf, ESDM_SEC_BYTES);
	TEST_REQUIRE("%d bytes are returned", ESDM_SEC_BYTES);
	if (!TEST_CHECK(rc == ESDM_SEC_BYTES, "%zd", rc))
		goto out;

	snprintf(path, sizeof(path), "%s/random.bin", esdm_sec_workdir);
	TEST_STEP("write the bytes to random.bin in a temporary directory");
	f = fopen(path, "wb");
	if (f) {
		written = fwrite(buf, 1, ESDM_SEC_BYTES, f);
		/* A failed flush loses what was written */
		if (fclose(f))
			written = 0;
	}

	TEST_REQUIRE("all %d bytes are written to the file", ESDM_SEC_BYTES);
	if (!TEST_CHECK(written == ESDM_SEC_BYTES, "%zu", written))
		goto out;

	ret = 0;

out:
	free(buf);
	return ret;
}

/*
 * Returns the assessed min-entropy per sample - "hAssessed" of the "Overall"
 * test case - or a negative value if the report does not carry it.
 */
static double esdm_sec_assessed_min_entropy(void)
{
	char path[sizeof(esdm_sec_workdir) + 16];
	struct json_object *root, *cases, *tc, *desc, *h;
	double ret = -1.0;
	size_t i, n;

	snprintf(path, sizeof(path), "%s/result.json", esdm_sec_workdir);
	root = json_object_from_file(path);
	if (!root) {
		printf("cannot parse %s: %s\n", path, json_util_get_last_err());
		return -1.0;
	}

	if (!json_object_object_get_ex(root, "testCases", &cases) ||
	    !json_object_is_type(cases, json_type_array)) {
		printf("report carries no testCases array\n");
		goto out;
	}

	n = json_object_array_length(cases);
	for (i = 0; i < n; i++) {
		tc = json_object_array_get_idx(cases, i);

		if (!json_object_object_get_ex(tc, "testCaseDesc", &desc) ||
		    strcmp(json_object_get_string(desc), "Overall"))
			continue;

		if (!json_object_object_get_ex(tc, "hAssessed", &h) ||
		    !json_object_is_type(h, json_type_double)) {
			printf("Overall test case carries no hAssessed\n");
			goto out;
		}

		ret = json_object_get_double(h);
		goto out;
	}

	printf("report carries no Overall test case\n");

out:
	json_object_put(root);
	return ret;
}

static void esdm_sec_cleanup(void)
{
	char path[sizeof(esdm_sec_workdir) + 16];

	snprintf(path, sizeof(path), "%s/random.bin", esdm_sec_workdir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/result.json", esdm_sec_workdir);
	unlink(path);
	rmdir(esdm_sec_workdir);
}

int main(int argc, char *argv[])
{
	const char *tmpdir = getenv("TMPDIR");
	double h;
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	snprintf(esdm_sec_workdir, sizeof(esdm_sec_workdir),
		 "%s/esdm-output-min-entropy-XXXXXX",
		 tmpdir && *tmpdir ? tmpdir : "/tmp");
	if (!mkdtemp(esdm_sec_workdir)) {
		printf("cannot create a working directory\n");
		return 1;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);
	TEST_STEP("initialize the ESDM");
	TEST_REQUIRE("the ESDM initializes");
	ret = esdm_init();
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto fini;

	ret = esdm_sec_write_samples();

fini:
	TEST_STEP("shut the ESDM down");
	esdm_fini();
	if (ret)
		goto out;

	TEST_STEP(
		"assess the bytes with the SP800-90B non-IID estimators of ea_non_iid -i -v -a: the initial entropy estimate over all bits, 8 bits per sample");
	ret = esdm_sec_run_ea_non_iid();
	TEST_REQUIRE("ea_non_iid is installed (test skipped otherwise)");
	if (!TEST_CHECK(ret != ESDM_SEC_EA_NOT_INSTALLED, "%d", ret)) {
		printf("ea_non_iid is not available - skipping\n");
		ret = 77;
		goto out;
	}
	TEST_REQUIRE("ea_non_iid completes successfully");
	if (!TEST_CHECK(ret == 0, "%d", ret)) {
		if (ret == ESDM_SEC_EA_SETUP_ERROR) {
			/* The hard error of the GNU test protocol */
			ret = 99;
			goto out;
		}
		ret = 1;
		goto out;
	}

	TEST_STEP(
		"read the overall assessed min-entropy from the ea_non_iid report");
	h = esdm_sec_assessed_min_entropy();
	TEST_REQUIRE("the report carries the overall assessed min-entropy");
	if (!TEST_CHECK(h >= 0, "%f", h)) {
		ret = 1;
		goto out;
	}

	printf("assessed min-entropy: %f bits per byte\n", h);
	TEST_REQUIRE("the assessed min-entropy is above %.1f bits per byte",
		     ESDM_SEC_MIN_BITS);
	if (!TEST_CHECK(h > ESDM_SEC_MIN_BITS, "%f", h))
		ret = 1;

out:
	esdm_sec_cleanup();
	return ret;
}
