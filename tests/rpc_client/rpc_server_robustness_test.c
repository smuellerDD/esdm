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
 * The unprivileged RPC interface served from a thread of this process, like
 * in tests/fuzz/rpc_client_fuzz.c: a fork() while requests are in flight
 * leaves the parent's connections intact.
 *
 * Runs unprivileged: the namespaces of tests/test_ipc_ns.c give it a /tmp of
 * its own to bind the socket in.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../test_namespace.h"
#include "esdm_logger.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

/* From esdm.h, whose definitions clash with those of esdm_rpc_client.h */
int esdm_init(void);
void esdm_fini(void);

#define TEST_FORKS 50

static pthread_t test_server;
static bool test_server_started = false;
static atomic_bool test_server_returned = false;

static void test_sleep_ms(long ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

static void *test_serve(void *unused)
{
	int ret;

	(void)unused;

	ret = esdm_rpcs_serve_in_process(
		ESDM_RPC_UNPRIV_SOCKET,
		(ProtobufCService *)&unpriv_access_service, false);
	if (ret)
		printf("RPC server did not run: %s\n", strerror(-ret));
	atomic_store(&test_server_returned, true);

	return NULL;
}

static atomic_bool test_fork_done = false;
static atomic_uint test_fork_failures = 0;

static void *test_fork_requester(void *unused)
{
	uint8_t buf[32];

	(void)unused;

	while (!atomic_load(&test_fork_done)) {
		ssize_t ret = esdm_rpcc_get_random_bytes(buf, sizeof(buf));

		if (ret != (ssize_t)sizeof(buf)) {
			printf("fork: request failed with %zd\n", ret);
			atomic_fetch_add(&test_fork_failures, 1);
		}
	}

	return NULL;
}

/* A child inherits the connections - its exit must not end the parent's */
static int test_fork(void)
{
	pthread_t thread;
	unsigned int i;

	if (pthread_create(&thread, NULL, test_fork_requester, NULL)) {
		printf("fork: cannot start the requesting thread\n");
		return 1;
	}

	for (i = 0; i < TEST_FORKS; i++) {
		pid_t pid = fork();

		if (pid == 0)
			_exit(0);
		if (pid > 0)
			waitpid(pid, NULL, 0);
		test_sleep_ms(10);
	}

	atomic_store(&test_fork_done, true);
	pthread_join(thread, NULL);

	printf("fork: %u failed requests during %u forks\n",
	       atomic_load(&test_fork_failures), TEST_FORKS);
	return atomic_load(&test_fork_failures) != 0;
}

static int test_start_server(void)
{
	struct stat sb;
	uint8_t buf[32];
	unsigned int i;

	if (esdm_init() || esdm_test_shm_status_init() || thread_init(1)) {
		printf("Cannot initialize the ESDM\n");
		return 1;
	}

	if (pthread_create(&test_server, NULL, test_serve, NULL)) {
		printf("Cannot start the RPC server thread\n");
		return 1;
	}
	test_server_started = true;

	for (i = 0; i < 500; i++) {
		if (atomic_load(&test_server_returned))
			return 1;
		if (!stat(ESDM_RPC_UNPRIV_SOCKET, &sb) && S_ISSOCK(sb.st_mode))
			break;
		test_sleep_ms(10);
	}

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("Cannot initialize the RPC client\n");
		return 1;
	}

	/* Until the ESDM is seeded - the test wants its data */
	if (esdm_rpcc_get_random_bytes_full(buf, sizeof(buf)) !=
	    (ssize_t)sizeof(buf)) {
		printf("The RPC server does not deliver data\n");
		return 1;
	}

	return 0;
}

int main(void)
{
	int ret;

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 77;
	}

	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	if (test_start_server()) {
		ret = 1;
		goto out;
	}

	ret = test_fork();

	esdm_rpcc_fini_unpriv_service();

out:
	esdm_rpc_server_signal_exit();
	if (test_server_started)
		pthread_join(test_server, NULL);
	esdm_fini();

	return ret;
}
