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
 * Running one of the installed binaries from a test.
 *
 * They are driven the way a user drives them - executed, with arguments -
 * rather than by linking their code, because what is under test is what a user
 * and a script get: the exit status, the message and the bytes on stdout.
 *
 * stdout and stderr are captured separately. Results go to stdout and
 * everything the logger produces to stderr, and a test that wants to parse the
 * result (the JSON status document, the hex bytes) must not have the log mixed
 * into it.
 *
 * Starting and collecting are separate calls so that runs which spend their
 * time waiting - the ones with no server to answer them, where the RPC client
 * spends seconds on its connection attempts - can be done at once rather than
 * one after the other.
 */

#ifndef TEST_RUN_H
#define TEST_RUN_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"

/* Enough for a usage text, which is the longest thing these print */
#define TEST_RUN_OUT_MAX 16384

/* argv[0] plus the options a single invocation is given */
#define TEST_RUN_ARGS_MAX 16

struct test_run {
	pid_t pid;
	int status;
	char out[TEST_RUN_OUT_MAX]; /* stdout: what the binary produced */
	char err[TEST_RUN_OUT_MAX]; /* stderr: what the logger said */
	size_t outlen;
	char out_path[512];
	char err_path[512];
	char in_path[512];
};

static const char *test_run_path;
static char test_run_dir[384];
static unsigned int test_run_seq;

/*
 * @binary is what every run below executes. A directory of its own is created
 * for the captures, which keeps concurrent runs of the same test apart.
 *
 * $TMPDIR is preferred but not trusted: a test that isolated itself first has
 * replaced /tmp with a private one, and the build's $TMPDIR may be a path that
 * no longer exists there. /tmp is what remains in that case, and it is the one
 * directory such a test is certain to have.
 */
static inline int test_run_init(const char *binary)
{
	const char *tmp = getenv("TMPDIR");

	test_run_path = binary;

	if (tmp && *tmp) {
		snprintf(test_run_dir, sizeof(test_run_dir),
			 "%s/esdm-run-test-XXXXXX", tmp);
		if (mkdtemp(test_run_dir))
			return 0;
	}

	snprintf(test_run_dir, sizeof(test_run_dir),
		 "/tmp/esdm-run-test-XXXXXX");
	if (!mkdtemp(test_run_dir)) {
		CHECK(0, "cannot create a directory for the captures: %s",
		      strerror(errno));
		return -1;
	}

	return 0;
}

static inline void test_run_fini(void)
{
	rmdir(test_run_dir);
}

static inline void test_run_slurp(const char *path, char *buf, size_t buflen,
				  size_t *len)
{
	FILE *f = fopen(path, "r");
	size_t rd = 0;

	if (f) {
		rd = fread(buf, 1, buflen - 1, f);
		fclose(f);
	}

	buf[rd] = '\0';
	if (len)
		*len = rd;
}

/*
 * Start the binary with @opts, a NULL terminated list of arguments.
 * @stdin_data becomes its standard input; NULL means an empty one.
 */
static inline int test_run_start(struct test_run *r, const char *const opts[],
				 const char *stdin_data)
{
	char *argv[TEST_RUN_ARGS_MAX + 1];
	unsigned int id = test_run_seq++;
	int i, fd_out, fd_err, fd_in;

	memset(r, 0, sizeof(*r));
	r->pid = -1;

	snprintf(r->out_path, sizeof(r->out_path), "%s/esdm_run_%u_%u.out",
		 test_run_dir, (unsigned int)getpid(), id);
	snprintf(r->err_path, sizeof(r->err_path), "%s/esdm_run_%u_%u.err",
		 test_run_dir, (unsigned int)getpid(), id);
	snprintf(r->in_path, sizeof(r->in_path), "%s/esdm_run_%u_%u.in",
		 test_run_dir, (unsigned int)getpid(), id);

	argv[0] = (char *)test_run_path;
	for (i = 0; i < TEST_RUN_ARGS_MAX && opts[i]; i++)
		argv[i + 1] = (char *)opts[i];
	argv[i + 1] = NULL;

	if (stdin_data) {
		FILE *f = fopen(r->in_path, "w");

		if (!f) {
			CHECK(0, "cannot create %s: %s", r->in_path,
			      strerror(errno));
			return -1;
		}
		fputs(stdin_data, f);
		fclose(f);
	}

	r->pid = fork();
	if (r->pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return -1;
	}

	if (!r->pid) {
		fd_out = open(r->out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		fd_err = open(r->err_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		fd_in = open(stdin_data ? r->in_path : "/dev/null", O_RDONLY);
		if (fd_out < 0 || fd_err < 0 || fd_in < 0) {
			/* Still the test's own stderr, so this is seen */
			fprintf(stderr, "cannot capture the output of %s: %s\n",
				test_run_path, strerror(errno));
			_exit(127);
		}
		dup2(fd_out, STDOUT_FILENO);
		dup2(fd_err, STDERR_FILENO);
		dup2(fd_in, STDIN_FILENO);
		close(fd_out);
		close(fd_err);
		close(fd_in);

		/*
		 * Leave the controlling terminal behind. --pkcs11-pin - prompts
		 * on /dev/tty when there is one, and a test run from an
		 * interactive shell would sit there waiting for someone to type
		 * a PIN instead of reading the standard input it was given.
		 */
		setsid();

		execv(test_run_path, argv);

		/* Captured as the run's stderr, so the reason is not lost */
		fprintf(stderr, "cannot execute %s: %s\n", test_run_path,
			strerror(errno));
		_exit(127);
	}

	return 0;
}

/* Wait for a started run and collect what it produced. Returns its exit status */
static inline int test_run_wait(struct test_run *r)
{
	if (r->pid <= 0)
		return -1;

	if (waitpid(r->pid, &r->status, 0) != r->pid) {
		CHECK(0, "waitpid() failed: %s", strerror(errno));
		return -1;
	}

	test_run_slurp(r->out_path, r->out, sizeof(r->out), &r->outlen);
	test_run_slurp(r->err_path, r->err, sizeof(r->err), NULL);
	unlink(r->out_path);
	unlink(r->err_path);
	unlink(r->in_path);

	if (!WIFEXITED(r->status)) {
		CHECK(0, "%s died abnormally (status %d)", test_run_path,
		      r->status);
		return -1;
	}

	return WEXITSTATUS(r->status);
}

static inline int test_run(struct test_run *r, const char *const opts[],
			   const char *stdin_data)
{
	if (test_run_start(r, opts, stdin_data))
		return -1;

	return test_run_wait(r);
}

/* Everything the invocation said, on either stream - for a failure message */
static inline const char *test_run_said(struct test_run *r)
{
	return r->err[0] ? r->err : r->out;
}

#endif /* TEST_RUN_H */
