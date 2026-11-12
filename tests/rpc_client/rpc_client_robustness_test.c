/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The RPC client against a server that accepts connections but never answers:
 * every call has to give up within a few seconds, so that callers without an
 * interrupt function get to their fallbacks. Also from a thread with a small
 * stack - the client's scratch buffers must not be carved from it. And against
 * a socket file nobody listens on, where a call fails at once.
 *
 * Runs unprivileged: the namespaces of tests/test_ipc_ns.c give it a /tmp of
 * its own to bind the socket in.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "../test_namespace.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"

/* What the client may take at most, with ample slack for a loaded machine */
#define TEST_MAX_SECONDS 20

/* A refused connect fails at once - see test_stale_socket() */
#define TEST_STALE_MAX_SECONDS 0.5

/* Below the ~130 kB the client buffers took as static TLS */
#define TEST_SMALL_STACK (96 * 1024)

static double test_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* A server that is there, but stuck: it never accepts, let alone answers */
static int test_stuck_server(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -errno;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);
	unlink(ESDM_RPC_UNPRIV_SOCKET);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(fd, 64) < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}

	return fd;
}

struct test_call {
	ssize_t ret;
	double seconds;
};

static void *test_get_full(void *arg)
{
	struct test_call *call = arg;
	uint8_t buf[32];
	double start = test_now();

	call->ret = esdm_rpcc_get_random_bytes_full(buf, sizeof(buf));
	call->seconds = test_now() - start;

	return NULL;
}

/*
 * A socket file left by a stopped server: a client never served has no restart
 * to wait for, so the call fails at once and the caller (the shim's
 * getrandom() with GRND_NONBLOCK too) reaches its fallback.
 */
static int test_stale_socket(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct test_call call = { 0 };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return 1;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);
	unlink(ESDM_RPC_UNPRIV_SOCKET);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return 1;
	}

	test_get_full(&call);
	close(fd);
	unlink(ESDM_RPC_UNPRIV_SOCKET);

	printf("stale socket: returned %zd after %.3f s\n", call.ret,
	       call.seconds);
	if (call.ret >= 0) {
		printf("stale socket: delivered data without a server\n");
		return 1;
	}
	if (call.seconds > TEST_STALE_MAX_SECONDS) {
		printf("stale socket: took longer than %.1f s\n",
		       TEST_STALE_MAX_SECONDS);
		return 1;
	}

	return 0;
}

static int test_check(const char *what, const struct test_call *call)
{
	printf("%s: returned %zd after %.1f s\n", what, call->ret,
	       call->seconds);

	if (call->ret >= 0) {
		printf("%s: a server that never answers delivered data\n",
		       what);
		return 1;
	}
	if (call->seconds > TEST_MAX_SECONDS) {
		printf("%s: took longer than %d s\n", what, TEST_MAX_SECONDS);
		return 1;
	}

	return 0;
}

int main(void)
{
	struct test_call call = { 0 };
	size_t stack = TEST_SMALL_STACK;
	pthread_attr_t attr;
	pthread_t thread;
	long min_stack;
	int fd = -1, ret;

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 77;
	}

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("Cannot initialize the RPC client\n");
		return 1;
	}

	/* First, while no server has served this process yet */
	ret = test_stale_socket();

	fd = test_stuck_server();
	if (fd < 0) {
		printf("Cannot set up the server socket: %s\n", strerror(-fd));
		esdm_rpcc_fini_unpriv_service();
		return 77;
	}

	/* No interrupt function - only the client's own bound ends the call */
	test_get_full(&call);
	ret |= test_check("calling thread", &call);

	/* At least the minimum of the platform: 128 kB on arm64 with glibc 2.35 */
	min_stack = sysconf(_SC_THREAD_STACK_MIN);
	if (min_stack > 0 && (size_t)min_stack > stack)
		stack = (size_t)min_stack;

	memset(&call, 0, sizeof(call));
	if (pthread_attr_init(&attr) ||
	    pthread_attr_setstacksize(&attr, stack)) {
		printf("Cannot set up the thread attributes\n");
		ret = 1;
		goto out_fini;
	}
	if (pthread_create(&thread, &attr, test_get_full, &call)) {
		printf("Cannot start a thread with a %zu kB stack\n",
		       stack / 1024);
		ret = 1;
	} else {
		pthread_join(thread, NULL);
		ret |= test_check("small stack thread", &call);
	}
	pthread_attr_destroy(&attr);

out_fini:
	esdm_rpcc_fini_unpriv_service();
	close(fd);
	unlink(ESDM_RPC_UNPRIV_SOCKET);
	return ret;
}
