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
 * Tests for common/helper.c and the macros of common/helper.h.
 *
 * The interesting part is esdm_safe_read()/esdm_safe_write(), the short
 * read/write loops every pipe and socket consumer in the tree relies on. Both
 * have to tell three easily confused outcomes apart: a partial transfer to be
 * resumed, an end of file, and a genuine error reported as a negative errno.
 * EINTR belongs to the first group and is provoked here with a real signal.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "helper.h"

static volatile sig_atomic_t signals_seen;

static void sigusr1_handler(int sig)
{
	(void)sig;
	signals_seen++;
}

static void test_online_nodes(void)
{
	uint32_t nodes = esdm_online_nodes();
	unsigned int i;

	CHECK(nodes >= 1, "esdm_online_nodes returned %u", nodes);
	CHECK(nodes <= THREADING_MAX_WORKER_THREADS,
	      "esdm_online_nodes returned %u, more than the %u worker threads",
	      nodes, (unsigned int)THREADING_MAX_WORKER_THREADS);

	/* The value is cached, so it must not change between calls */
	CHECK_EQ(esdm_online_nodes(), nodes);

	/* The node a caller is steered to always has to be a valid index */
	for (i = 0; i < 10000; i++) {
		uint32_t node = esdm_curr_node();

		if (node >= nodes) {
			CHECK(0, "esdm_curr_node returned %u for %u nodes",
			      node, nodes);
			break;
		}
	}
}

static void test_helper_macros(void)
{
	static const int array[7] = { 0 };
	uint8_t buf[16] __aligned(8);

	CHECK_EQ(ARRAY_SIZE(array), 7);

	CHECK_EQ(aligned(buf, 7), 1);
	CHECK_EQ(aligned(buf + 1, 7), 0);
	CHECK_EQ(aligned(buf + 4, 3), 1);
	CHECK_EQ(aligned(buf + 4, 7), 0);
}

static void test_safe_read_write_roundtrip(void)
{
	uint8_t out[512], in[512];
	int fds[2];
	unsigned int i;

	for (i = 0; i < sizeof(out); i++)
		out[i] = (uint8_t)(i * 11 + 5);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	CHECK_EQ(esdm_safe_write(fds[1], out, sizeof(out)),
		 (ssize_t)sizeof(out));
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), (ssize_t)sizeof(in));
	CHECK_MEM_EQ(in, out, sizeof(out));

	/* A zero-length transfer is a no-op rather than an error */
	CHECK_EQ(esdm_safe_write(fds[1], out, 0), 0);
	CHECK_EQ(esdm_safe_read(fds[0], in, 0), 0);

	close(fds[0]);
	close(fds[1]);
}

struct chunked_writer {
	int fd;
	const uint8_t *data;
	size_t len;
	size_t chunk;
};

static void *chunked_writer(void *arg)
{
	struct chunked_writer *w = arg;
	size_t off;

	for (off = 0; off < w->len; off += w->chunk) {
		size_t this = w->len - off < w->chunk ? w->len - off : w->chunk;

		if (write(w->fd, w->data + off, this) < 0)
			break;
		usleep(1000);
	}

	close(w->fd);
	return NULL;
}

static void test_safe_read_partial(void)
{
	uint8_t out[4096], in[4096];
	struct chunked_writer w;
	pthread_t tid;
	int fds[2];
	unsigned int i;

	for (i = 0; i < sizeof(out); i++)
		out[i] = (uint8_t)(i * 7 + 1);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	w.fd = fds[1];
	w.data = out;
	w.len = sizeof(out);
	w.chunk = 137;

	CHECK_EQ(pthread_create(&tid, NULL, chunked_writer, &w), 0);

	/* The data arrives in many small chunks - all of it has to be assembled */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), (ssize_t)sizeof(in));
	CHECK_MEM_EQ(in, out, sizeof(out));

	pthread_join(tid, NULL);
	close(fds[0]);
}

static void test_safe_read_eof(void)
{
	uint8_t out[16], in[128];
	int fds[2];

	memset(out, 0x5a, sizeof(out));

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	CHECK_EQ(write(fds[1], out, sizeof(out)), (ssize_t)sizeof(out));
	close(fds[1]);

	/* Asking for more than the peer sent returns what arrived before EOF */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), (ssize_t)sizeof(out));
	CHECK_MEM_EQ(in, out, sizeof(out));

	/* Reading past the end of file yields zero, not an error */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), 0);

	close(fds[0]);
}

struct drainer {
	int fd;
	size_t len;
};

static void *drainer(void *arg)
{
	struct drainer *d = arg;
	uint8_t buf[1024];
	size_t done = 0;

	while (done < d->len) {
		ssize_t r = read(d->fd, buf, sizeof(buf));

		if (r <= 0)
			break;
		done += (size_t)r;
	}

	close(d->fd);
	return NULL;
}

static void test_safe_write_partial(void)
{
	/* Larger than the default pipe capacity, so write() must go short */
	static uint8_t out[512 * 1024];
	struct drainer d;
	pthread_t tid;
	int fds[2];

	memset(out, 0x3c, sizeof(out));

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	d.fd = fds[0];
	d.len = sizeof(out);

	CHECK_EQ(pthread_create(&tid, NULL, drainer, &d), 0);

	CHECK_EQ(esdm_safe_write(fds[1], out, sizeof(out)),
		 (ssize_t)sizeof(out));

	close(fds[1]);
	pthread_join(tid, NULL);
}

struct interrupter {
	pthread_t target;
	int fd;
	const uint8_t *data;
	size_t len;
};

static void *interrupter(void *arg)
{
	struct interrupter *in = arg;
	unsigned int i;
	sigset_t block;

	/* Keep the signals aimed at the reader from landing here */
	sigemptyset(&block);
	sigaddset(&block, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &block, NULL);

	for (i = 0; i < 5; i++) {
		usleep(20000);
		pthread_kill(in->target, SIGUSR1);
	}

	usleep(20000);
	if (write(in->fd, in->data, in->len) < 0) {
		/* reported by the reader's short result */
	}
	close(in->fd);
	return NULL;
}

static void test_safe_read_eintr(void)
{
	uint8_t out[64], in[64];
	struct interrupter arg;
	struct sigaction sa, old;
	pthread_t tid;
	int fds[2];

	memset(out, 0xa7, sizeof(out));

	/* No SA_RESTART: the blocked read() has to come back with EINTR */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	CHECK_EQ(sigaction(SIGUSR1, &sa, &old), 0);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		sigaction(SIGUSR1, &old, NULL);
		return;
	}

	arg.target = pthread_self();
	arg.fd = fds[1];
	arg.data = out;
	arg.len = sizeof(out);
	signals_seen = 0;

	CHECK_EQ(pthread_create(&tid, NULL, interrupter, &arg), 0);

	/*
	 * The read blocks while the signals arrive. Every one of them makes
	 * read() fail with EINTR, which esdm_safe_read has to retry instead of
	 * reporting - otherwise this returns -EINTR and loses the data.
	 */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), (ssize_t)sizeof(in));
	CHECK_MEM_EQ(in, out, sizeof(out));
	CHECK(signals_seen > 0, "no signal was delivered to the reader");

	pthread_join(tid, NULL);
	close(fds[0]);
	sigaction(SIGUSR1, &old, NULL);
}

static void test_safe_read_write_errors(void)
{
	uint8_t buf[16];
	int fds[2];

	memset(buf, 0, sizeof(buf));

	/* A bad descriptor is reported as a negative errno */
	CHECK_EQ(esdm_safe_read(-1, buf, sizeof(buf)), -EBADF);
	CHECK_EQ(esdm_safe_write(-1, buf, sizeof(buf)), -EBADF);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	/* Writing into a pipe whose reader is gone reports EPIPE */
	signal(SIGPIPE, SIG_IGN);
	close(fds[0]);
	CHECK_EQ(esdm_safe_write(fds[1], buf, sizeof(buf)), -EPIPE);
	close(fds[1]);
	signal(SIGPIPE, SIG_DFL);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	/* No-op unless the tree was configured with memory-debug */
	may_enable_memory_debugging();

	test_online_nodes();
	test_helper_macros();
	test_safe_read_write_roundtrip();
	test_safe_read_partial();
	test_safe_read_eof();
	test_safe_write_partial();
	test_safe_read_eintr();
	test_safe_read_write_errors();

	return common_test_result("helper");
}
