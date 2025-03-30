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
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <assert.h>

static void process_fn(double timeout_sec, long id, int sock_fd)
{
	handle_stress_delay_one_core(timeout_sec, id, sock_fd);

	exit(EXIT_SUCCESS);
}

void handle_stress_process(double timeout_sec)
{
	long cores = sysconf(_SC_NPROCESSORS_ONLN);
	pid_t *processes = calloc((size_t)cores, sizeof(pid_t));
	int *sockets = calloc((size_t)cores, sizeof(int));
	long i;

	for (i = 0; i < cores; ++i) {
		int socks[2];
		int ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, socks);
		assert(ret == 0);
		sockets[i] = socks[0];

		pid_t pid = fork();

		if (pid == 0) {
			close(socks[0]);
			process_fn(timeout_sec, i, socks[1]);
		}

		if (pid > 0) {
			close(socks[1]);
			processes[i] = pid;
		}
	}

	handle_messages(sockets, (size_t)cores);

	for (i = 0; i < cores; ++i) {
		waitpid(processes[i], NULL, 0);
	}
}
