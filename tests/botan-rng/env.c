/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "env.h"

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
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
	const char *server = getenv("ESDM_SERVER");
	pid_t pid;
	int ret;

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	ret = env_check_file(server);
	if (ret)
		goto out;

	/* Server forking */
	pid = fork();
	if (pid < 0)
		return errno;
	if (pid == 0) {
		char buf[FILENAME_MAX];
		char *server_argv[] = { buf, "-vvvvv", NULL };

		snprintf(buf, sizeof(buf), "%s", server);
		execve(server, server_argv, NULL);

		/* NOTREACHED */
		return EFAULT;
	}
	server_pid = pid;
	nanosleep(&ts, NULL);

out:
	return ret;
}
