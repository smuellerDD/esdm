/*
 * Recovery of the EGD client's locks from a caller that died holding one
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
 * The client lock is held across the whole request / response exchange, bounded
 * by nothing but the client's timeout. A caller killed in that window - an
 * application shot while waiting for a not yet operational ESDM - is what the
 * robust locks exist for: a plain mutex would stay locked for the rest of the
 * process lifetime. A peer that accepts but never answers puts a thread into
 * exactly that window, where it is cancelled. Everything after has a deadline,
 * so a wedged client fails the test instead of hanging it.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "egd_peer.h"
#include "esdm_egd_client.h"

/*
 * The requests of this test are all unanswered by design, so each one runs
 * into this bound - twice, as an operation is retried once on a fresh
 * connection.
 */
#define TEST_TIMEOUT_MS 1000

/*
 * What a request may take end to end. Two attempts of TEST_TIMEOUT_MS plus room
 * for a loaded machine - and far below anything that could be confused with the
 * wait for a lock that is never released.
 */
#define TEST_DEADLINE_MS (6 * TEST_TIMEOUT_MS)

/*
 * Backstop for the case the recovery does not work at all: the process is
 * killed rather than left waiting for the test harness to time it out, which
 * makes the reason visible in the log.
 */
#define TEST_WATCHDOG_SEC 60

static char tmpdir[] = "/tmp/esdm-egd-robust-XXXXXX";
static char sockpath[sizeof(tmpdir) + 32];

static struct esdm_egd_client *client;

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/*
 * Take the client lock and wait for an answer that never comes. The request is
 * expected to be cancelled rather than to return.
 */
static void *blocked_caller(void *arg)
{
	uint8_t buf[16];

	(void)arg;

	esdm_egd_client_get_random(client, buf, sizeof(buf));

	printf("  FAIL: the blocked caller returned instead of being cancelled\n");

	return (void *)1;
}

int main(int argc, char *argv[])
{
	struct egd_peer *peer;
	struct timespec settle = { .tv_sec = 0, .tv_nsec = 300 * 1000 * 1000 };
	pthread_t caller;
	uint64_t elapsed;
	uint32_t bits;
	void *thread_ret = NULL;
	int status = 0;
	pid_t pid;
	int ret = 0;

	(void)argc;
	(void)argv;

	/* Keep the progress readable should the watchdog have to kill this. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		return 1;
	}
	snprintf(sockpath, sizeof(sockpath), "%s/egd.sock", tmpdir);

	if (egd_peer_start(&peer, sockpath, EGD_PEER_SILENT)) {
		printf("Cannot start the test peer\n");
		rmdir(tmpdir);
		return 1;
	}

	if (esdm_egd_client_alloc(&client, sockpath, TEST_TIMEOUT_MS)) {
		printf("Cannot allocate the client\n");
		egd_peer_stop(peer);
		rmdir(tmpdir);
		return 1;
	}

	printf("EGD robustness: a caller killed while holding the client lock\n");

	if (pthread_create(&caller, NULL, blocked_caller, NULL)) {
		printf("  FAIL: cannot create the caller thread\n");
		ret = 1;
		goto out;
	}

	/* Let it get as far as waiting for the answer, then kill it there. */
	nanosleep(&settle, NULL);
	pthread_cancel(caller);
	pthread_join(caller, &thread_ret);

	if (thread_ret != PTHREAD_CANCELED) {
		printf("  FAIL: the caller was not cancelled inside the request\n");
		ret = 1;
		goto out;
	}

	/*
	 * The lock now has an owner that no longer exists. This request has to
	 * take it over - it fails, as the peer still does not answer, but it
	 * must come back at all.
	 */
	elapsed = now_ms();
	if (esdm_egd_client_entropy_count(client, &bits) == 0) {
		printf("  FAIL: the silent peer answered the entropy count\n");
		ret = 1;
	}
	elapsed = now_ms() - elapsed;

	printf("  the request returned after %llu ms\n",
	       (unsigned long long)elapsed);
	if (elapsed > TEST_DEADLINE_MS) {
		printf("  FAIL: it took longer than the %u ms deadline - the lock was not handed over right away\n",
		       TEST_DEADLINE_MS);
		ret = 1;
	}

	/*
	 * A fork after the death: the child cannot inherit the parent's lock
	 * ownership, so its locks are recreated rather than unlocked. Using and
	 * releasing the client there must work.
	 */
	printf("EGD robustness: a fork after the death\n");
	pid = fork();
	if (pid < 0) {
		printf("  FAIL: fork failed\n");
		ret = 1;
		goto out;
	}
	if (pid == 0) {
		uint32_t child_bits;

		alarm(TEST_WATCHDOG_SEC);
		esdm_egd_client_entropy_count(client, &child_bits);
		esdm_egd_client_free(client);
		_exit(0);
	}

	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("  FAIL: the child did not survive using the client (status %#x)\n",
		       status);
		ret = 1;
	}

out:
	esdm_egd_client_free(client);
	egd_peer_stop(peer);
	rmdir(tmpdir);

	printf("EGD robustness: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
