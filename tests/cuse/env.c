/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "env.h"
#include "privileges.h"
#include "ret_checkers.h"
#include "test_pertubation.h"

static pid_t server_pid = 0;
static pid_t random_pid = 0;
static pid_t urandom_pid = 0;

void env_fini(void)
{
	raise_privilege();
	esdm_test_shm_status_fini();

	if (random_pid > 0) {
		printf("Killing random PID %u\n", random_pid);
		kill(random_pid, SIGTERM);
	}
	random_pid = 0;
	if (urandom_pid > 0) {
		printf("Killing urandom PID %u\n", urandom_pid);
		kill(urandom_pid, SIGTERM);
	}
	urandom_pid = 0;
	if (server_pid > 0) {
		printf("Killing server PID %u\n", server_pid);
		kill(server_pid, SIGTERM);
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

	if ((sb.st_mode & S_IFMT) != S_IFREG) {
		printf("File not regular file\n");
		return EPERM;
	}

	return 0;
}

int env_init(int disable_fallback)
{
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
	const char *random = getenv("ESDM_CUSE_RANDOM");
	const char *urandom = getenv("ESDM_CUSE_URANDOM");
	const char *server = getenv("ESDM_SERVER");
	pid_t pid;
	int ret;

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

#ifndef ESDM_TESTMODE
	if (disable_fallback)
		return 77;
#endif

	CKINT(env_check_file(random));
	CKINT(env_check_file(urandom));
	CKINT(env_check_file(server));
	CKINT(esdm_test_shm_status_init());

	/* Server forking */
	pid = fork();
	if (pid < 0)
		return errno;
	if (pid == 0) {
		char buf[FILENAME_MAX];
		char *server_argv[] = { buf, "-vvvvv", NULL };

		CKNULL(server, -EFAULT);
		snprintf(buf, sizeof(buf), "%s", server);
		execve(server, server_argv, NULL);

		/* NOTREACHED */
		return EFAULT;
	}
	server_pid = pid;
	nanosleep(&ts, NULL);

	/* random forking */
	pid = fork();
	if (pid < 0) {
		env_fini();
		return errno;
	}
	if (pid == 0) {
		char buf[FILENAME_MAX];
		char *random_argv[] = { buf,  "-f", "-d", "-v", "5", NULL };
		char *random_argv_dis[]  = { buf,  "-f", "-d", "-v", "5",
					     "--disable_fallback=1", NULL };

		CKNULL(random, -EFAULT);
		snprintf(buf, sizeof(buf), "%s", random);
		execve(random, disable_fallback ? random_argv_dis : random_argv,
		       NULL);

		/* NOTREACHED */
		return EFAULT;
	}
	random_pid = pid;
	nanosleep(&ts, NULL);

	/* urandom forking */
	pid = fork();
	if (pid < 0) {
		env_fini();
		return errno;
	}
	if (pid == 0) {
		char buf[FILENAME_MAX];
		char *urandom_argv[] = { buf,  "-f", "-d", "-v", "5", NULL };
		char *urandom_argv_dis[]  = { buf,  "-f", "-d", "-v", "5",
					      "--disable_fallback=1", NULL };

		CKNULL(urandom, -EFAULT);
		snprintf(buf, sizeof(buf), "%s", urandom);
		execve(urandom, disable_fallback ?
				urandom_argv_dis : urandom_argv, NULL);

		/* NOTREACHED */
		return EFAULT;
	}
	urandom_pid = pid;
	nanosleep(&ts, NULL);

out:
	return ret;
}

void env_kill_server(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 1<<29 };

	if (server_pid > 0) {
		printf("Killing server PID %u\n", server_pid);
		raise_privilege();
		kill(server_pid, SIGTERM);
	}
	server_pid = 0;
	nanosleep(&ts, NULL);
}
