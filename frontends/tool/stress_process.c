/*
 * Copyright (C) 2025, Markus Theil <theil.markus@gmail.com>
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

#include "tool.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <signal.h>
#include <esdm_rpc_client.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <assert.h>

static pid_t *processes = NULL;
static atomic_bool should_terminate = false;

static void process_fn(double timeout_sec, long id, int sock_fd,
		       uint32_t request_size)
{
	esdm_rpcc_init_unpriv_service(NULL);

	handle_stress_delay_one_core(timeout_sec, id, sock_fd, request_size);

	esdm_rpcc_fini_unpriv_service();

	exit(EXIT_SUCCESS);
}

static void handle_sigint(int signal)
{
	long cores = sysconf(_SC_NPROCESSORS_ONLN);
	long i;

	bool expected = false;

	(void)signal;

	if (atomic_compare_exchange_strong(&should_terminate, &expected, true)) {
		for (i = 0; i < cores; ++i) {
			/*
			 * Only signal real children. A not-yet-forked entry is 0
			 * (calloc); kill(0, ...) would signal the entire process
			 * group - including this parent and unrelated members.
			 */
			if (processes[i] <= 0)
				continue;
			kill(processes[i], SIGKILL);
		}

		exit(EXIT_FAILURE);
	}
}

void handle_stress_process(double timeout_sec, uint32_t request_size,
			   bool show_cpu_usage)
{
	long cores = sysconf(_SC_NPROCESSORS_ONLN);
	int *sockets = calloc((size_t)cores, sizeof(int));
	long i;

	if (processes == NULL) {
		processes = calloc((size_t)cores, sizeof(pid_t));
	}

	if (!sockets || !processes) {
		free(sockets);
		free(processes);
		processes = NULL;
		return;
	}

	{
		struct sigaction sa;
		sa.sa_handler = SIG_IGN;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		if (sigaction(SIGCHLD, &sa, 0) == -1) {
			perror("sigaction");
			exit(EXIT_FAILURE);
		}
	}

	signal(SIGINT, handle_sigint);

	for (i = 0; i < cores; ++i) {
		int socks[2];
		int ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, socks);
		assert(ret == 0);
		(void)ret;
		sockets[i] = socks[0];

		pid_t pid = fork();

		if (pid == 0) {
			for (int j = 0; j <= i; ++j)
				close(sockets[j]);

			if (freopen("/dev/null", "r", stdin) == NULL) {
				exit(EXIT_FAILURE);
			}
			if (freopen("/dev/null", "w", stdout) == NULL) {
				exit(EXIT_FAILURE);
			}
			if (freopen("/dev/null", "w", stderr) == NULL) {
				exit(EXIT_FAILURE);
			}

			// needed to deliver STRG+C cleanly to the parent
			struct sigaction sa;
			sa.sa_handler = SIG_IGN;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = 0;
			if (sigaction(SIGINT, &sa, 0) == -1) {
				exit(EXIT_FAILURE);
			}

			process_fn(timeout_sec, i, socks[1], request_size);
		}

		if (pid > 0) {
			close(socks[1]);
			processes[i] = pid;
		}
	}

	handle_messages(sockets, (size_t)cores, show_cpu_usage);

	for (i = 0; i < cores; ++i) {
		waitpid(processes[i], NULL, 0);
		close(sockets[i]);
	}
	free(sockets);
}
