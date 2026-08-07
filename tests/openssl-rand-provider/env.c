/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "env.h"
#include "../test_env.h"
#include "../test_namespace.h"
#include "../test_wait.h"
#include "esdm_rpc_service.h"

/* Where this test has the server serve EGD, see env_init() */
#define ESDM_TEST_EGD_SOCKET "/tmp/esdm-egd-openssl-test.socket"
#define ESDM_EGD_SOCKET_ENV "ESDM_EGD_SOCKET"

static pid_t server_pid = 0;

void env_fini(void)
{
	if (server_pid > 0) {
		printf("Killing server PID %u\n", server_pid);
		kill(server_pid, SIGTERM);
		waitpid(server_pid, NULL, 0);
	}
	server_pid = 0;
}

static int env_check_file(const char *path)
{
	struct stat sb;

	if (!path) {
		printf("No file provided\n");
		return ENOENT;
	}

	if (stat(path, &sb) == 1) {
		printf("File not found\n");
		return errno;
	}

	if (!S_ISREG(sb.st_mode)) {
		printf("File not regular file\n");
		return EPERM;
	}

	return 0;
}

int env_init(void)
{
	const char *server = getenv("ESDM_SERVER");
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	pid_t pid;
	int ret;

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	/*
	 * Run in namespaces of our own so the fixed socket, semaphore and
	 * IPC names this test needs cannot collide with another test using
	 * the same ones - see tests/test_namespace.h.
	 */
	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return -ret;
	}

	ret = env_check_file(server);
	if (ret)
		goto out;

	/*
	 * The EGD provider does not use the RPC interface at all - it speaks
	 * the EGD protocol over a socket of its own - so the server is given
	 * one and the client is pointed at it. Doing this unconditionally
	 * costs the RPC based providers nothing and keeps one server startup
	 * for every provider under test. /tmp is private to this test, so the
	 * fixed name cannot collide with another one.
	 */
	setenv(ESDM_EGD_SOCKET_ENV, ESDM_TEST_EGD_SOCKET, 1);

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	/* Server forking */
	pid = fork();
	if (pid < 0)
		return errno;
	if (pid == 0) {
		char buf[FILENAME_MAX];
		char *server_argv[] = { buf,	    "-vvvvv", "--egd_socket",
					(char *)ESDM_TEST_EGD_SOCKET, NULL };

		snprintf(buf, sizeof(buf), "%s", server);
		execve(server, server_argv, server_envp);

		/* NOTREACHED */
		return EFAULT;
	}
	server_pid = pid;
	/* The server is up once it has bound its unprivileged RPC socket */
	test_wait_for_type(ESDM_RPC_UNPRIV_SOCKET, S_IFSOCK,
			   TEST_WAIT_TIMEOUT_MS);
	/* and serving EGD once that socket is there as well */
	test_wait_for_type(ESDM_TEST_EGD_SOCKET, S_IFSOCK,
			   TEST_WAIT_TIMEOUT_MS);

out:
	return ret;
}
