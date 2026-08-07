/*
 * Tests of the EGD interface of the esdm-server
 *
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
 * The counterpart of egd_client_test: that one drives the client against a
 * peer of its own to reach the answers a correct server never gives, this one
 * drives it against the real esdm-server started with --egd_socket. Both sides
 * of the protocol are only covered together.
 *
 * The server refuses to run unprivileged, so this skips (77) when it is not
 * started as root.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "esdm_egd_client.h"
#include "esdm_egd_protocol.h"

#include "../test_env.h"
#include "../test_namespace.h"

/*
 * The blocking read waits for the ESDM to become operational, which right
 * after its start legitimately takes a moment.
 */
#define TEST_TIMEOUT_MS 30000

/* How long the server is given to create its socket. */
#define TEST_SERVER_START_SEC 30

/*
 * Backstop for a request that never comes back - a server that created its
 * socket but does not serve it, say. Below the timeout the test harness applies
 * to the whole run, so the failure is this test's rather than the harness'.
 */
#define TEST_WATCHDOG_SEC 240

static char tmpdir[] = "/tmp/esdm-egd-server-test-XXXXXX";
static char sockpath[sizeof(tmpdir) + 32];
static pid_t server_pid;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL: ");                                    \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			ret = 1;                                               \
		}                                                              \
	} while (0)

static int server_start(void)
{
	const char *server = getenv("ESDM_SERVER");
	struct timespec wait = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	struct stat sb;
	unsigned int i;

	if (server == NULL || stat(server, &sb) < 0 || !S_ISREG(sb.st_mode)) {
		printf("ESDM_SERVER does not point at the esdm-server binary\n");
		return 1;
	}

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	server_pid = fork();
	if (server_pid < 0)
		return 1;

	if (server_pid == 0) {
		char binary[FILENAME_MAX];
		char socket_arg[sizeof(sockpath)];
		/* Verbose logging implies staying in the foreground. */
		char *argv[] = { binary, (char *)"-vvvvv",
				 (char *)"--egd_socket", socket_arg, NULL };

		snprintf(binary, sizeof(binary), "%s", server);
		snprintf(socket_arg, sizeof(socket_arg), "%s", sockpath);
		execve(server, argv, server_envp);

		/* NOTREACHED */
		_exit(1);
	}

	/* The socket appears once the server is ready to serve it. */
	for (i = 0; i < TEST_SERVER_START_SEC * 5; i++) {
		if (!stat(sockpath, &sb) && S_ISSOCK(sb.st_mode))
			return 0;
		if (waitpid(server_pid, NULL, WNOHANG) == server_pid) {
			printf("The esdm-server terminated during its start\n");
			server_pid = 0;
			return 1;
		}
		nanosleep(&wait, NULL);
	}

	printf("The esdm-server did not create %s\n", sockpath);

	return 1;
}

static void server_stop(void)
{
	struct timespec wait = { .tv_sec = 1, .tv_nsec = 0 };

	if (server_pid <= 0)
		return;

	printf("Killing server PID %u\n", (unsigned int)server_pid);
	kill(server_pid, SIGTERM);
	waitpid(server_pid, NULL, 0);
	server_pid = 0;

	nanosleep(&wait, NULL);
}

int main(int argc, char *argv[])
{
	struct esdm_egd_client *client = NULL;
	/* More than one protocol transfer, so the server serves two. */
	uint8_t buf[300];
	uint8_t zero[sizeof(buf)];
	uint8_t seed[32];
	size_t generated = 0;
	uint32_t bits = 0;
	unsigned int i;
	pid_t pid = 0;
	int ret = 0;

	(void)argc;
	(void)argv;

	memset(zero, 0, sizeof(zero));

	/*
	 * The server shares this output and is started with verbose logging, so
	 * keep the test's own progress in step with it - and keep it readable
	 * should the run be killed part way through.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	/*
	 * The EGD socket below is named uniquely, but the server started on it
	 * also claims the fixed RPC socket, semaphore and IPC names. Run in
	 * namespaces of our own so those cannot collide with another test using
	 * the same ones - see tests/test_namespace.h.
	 */
	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		return 1;
	}
	snprintf(sockpath, sizeof(sockpath), "%s/egd.sock", tmpdir);

	if (server_start()) {
		rmdir(tmpdir);
		return 1;
	}

	if (esdm_egd_client_alloc(&client, sockpath, TEST_TIMEOUT_MS)) {
		printf("Cannot allocate the client\n");
		server_stop();
		rmdir(tmpdir);
		return 1;
	}

	printf("EGD server: PID request\n");
	CHECK(esdm_egd_client_get_pid(client, &pid) == 0,
	      "the PID request failed");
	/*
	 * What the protocol promises is a PID the caller can act on, not one
	 * particular process of the daemon - so check that it is alive rather
	 * than which one it is.
	 */
	CHECK(pid > 0 && kill(pid, 0) == 0,
	      "the reported PID %d is not a running process", (int)pid);
	printf("  the server reports PID %d, started as %d\n", (int)pid,
	       (int)server_pid);

	printf("EGD server: entropy count\n");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");
	printf("  %u bits available\n", bits);

	printf("EGD server: blocking read\n");
	memset(buf, 0, sizeof(buf));
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");
	CHECK(memcmp(buf, zero, sizeof(buf)) != 0,
	      "the blocking read delivered nothing but zeroes");

	printf("EGD server: non-blocking read\n");
	CHECK(esdm_egd_client_get_random_nonblock(client, buf,
						  ESDM_EGD_MAX_TRANSFER,
						  &generated) == 0,
	      "the non-blocking read failed");
	/* A short answer is legitimate, more than was asked for is not. */
	CHECK(generated <= ESDM_EGD_MAX_TRANSFER,
	      "%zu bytes delivered, at most %u were asked for", generated,
	      ESDM_EGD_MAX_TRANSFER);
	printf("  %zu of %u bytes delivered right away\n", generated,
	       ESDM_EGD_MAX_TRANSFER);

	printf("EGD server: entropy insertion\n");
	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;
	CHECK(esdm_egd_client_write_entropy(client, seed, sizeof(seed),
					    8 * sizeof(seed)) == 0,
	      "the entropy insertion failed");
	/*
	 * The command has no answer of its own, so a following request is what
	 * shows that the server kept the stream in sync over it.
	 */
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count after an insertion failed");

	printf("EGD server: many requests on one connection\n");
	for (i = 0; i < 16; i++) {
		if (esdm_egd_client_get_random(client, buf, 64)) {
			CHECK(0, "request %u failed", i);
			break;
		}
	}

	/*
	 * The daemon goes away underneath the client: the request must come
	 * back with an error rather than hang or take the caller down with a
	 * SIGPIPE.
	 */
	printf("EGD server: the daemon goes away\n");
	server_stop();
	CHECK(esdm_egd_client_get_random(client, buf, 16) < 0,
	      "a request against the stopped daemon succeeded");

	esdm_egd_client_free(client);
	rmdir(tmpdir);

	printf("EGD server: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
