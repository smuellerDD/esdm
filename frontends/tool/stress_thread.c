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
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

struct thread_arg {
	double timeout;
	long id;
	int sock_fd;
};

static void *thread_fn(void *arg)
{
	struct thread_arg *a = (struct thread_arg *)arg;
	handle_stress_delay_one_core(a->timeout, a->id, a->sock_fd);
	free(a);
	return NULL;
}

void handle_stress_thread(double timeout_sec, int num_threads)
{
	long cores = sysconf(_SC_NPROCESSORS_ONLN);
	pthread_t *threads;
	int *sockets;
	long i;

	if (num_threads > 0) {
		cores = num_threads;
	}

	threads = calloc((size_t)cores, sizeof(pthread_t));
	sockets = calloc((size_t)cores, sizeof(int));

	for (i = 0; i < cores; ++i) {
		int socks[2];
		int ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, socks);
		assert(ret == 0);
		sockets[i] = socks[0];

		struct thread_arg *arg = malloc(sizeof(struct thread_arg));
		arg->timeout = timeout_sec;
		arg->id = i;
		arg->sock_fd = socks[1];
		pthread_create(&threads[i], NULL, thread_fn, arg);
	}

	handle_messages(sockets, (size_t)cores);

	for (i = 0; i < cores; ++i) {
		pthread_join(threads[i], NULL);
	}
}
