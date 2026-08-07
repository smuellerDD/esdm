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
 * Tests for the ESDM auxiliary client library.
 *
 * This is the interface an external entropy provider uses: attach, sleep until
 * the ESDM wants entropy, insert some, repeat. It needs neither privileges nor
 * a running server - the semaphore and the shared memory segment are created by
 * whichever side gets there first - so what is covered here is the behaviour a
 * provider meets before and without a server, which is what its documented
 * timeout exists for.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "esdm_aux_client.h"

static double elapsed_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	return ((double)now.tv_sec - (double)start->tv_sec) +
	       ((double)now.tv_nsec - (double)start->tv_nsec) / 1e9;
}

/* Build the absolute CLOCK_MONOTONIC deadline the API takes */
static void deadline_in(struct timespec *ts, time_t sec)
{
	clock_gettime(CLOCK_MONOTONIC, ts);
	ts->tv_sec += sec;
}

static void test_wait_without_init(void)
{
	struct timespec ts;
	int rc;

	deadline_in(&ts, 1);

	/*
	 * Waiting before attaching is a caller error, and it is reported as one
	 * rather than blocking on a semaphore that was never opened.
	 */
	errno = 0;
	rc = esdm_aux_timedwait_for_need_entropy(&ts);
	CHECK_EQ(rc, -1);
	CHECK_EQ(errno, EINVAL);
}

static void test_init_fini(void)
{
	/* Detaching without attaching first is a no-op, not a crash */
	esdm_aux_fini_wait_for_need_entropy();

	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);
	esdm_aux_fini_wait_for_need_entropy();

	/* and detaching twice does not take the second one down either */
	esdm_aux_fini_wait_for_need_entropy();

	/* The whole cycle can be repeated - a provider may reconnect */
	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);
	esdm_aux_fini_wait_for_need_entropy();
}

/*
 * The documented contract: the call returns at the timeout even though the
 * semaphore did not fire. A provider started before the ESDM server - the
 * ordinary case under one service manager - depends on that to notice and
 * retry. Run in a child with a hard bound, so a wait that never returns fails
 * the test instead of hanging it.
 */
static void test_wait_honours_timeout(void)
{
	static const unsigned int bound_sec = 10;
	struct timespec start;
	int status;
	pid_t pid;

	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);

	clock_gettime(CLOCK_MONOTONIC, &start);

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return;
	}

	if (!pid) {
		struct timespec ts;
		int rc;

		deadline_in(&ts, 1);
		alarm(bound_sec);
		errno = 0;
		rc = esdm_aux_timedwait_for_need_entropy(&ts);
		/* No server, so nothing can have signalled: it must time out */
		_exit(rc == -1 && errno == ETIMEDOUT ? 0 : 1);
	}

	if (waitpid(pid, &status, 0) != pid) {
		CHECK(0, "waitpid() failed: %s", strerror(errno));
		return;
	}

	if (!WIFEXITED(status)) {
		CHECK(0,
		      "the timed wait did not return within %u s although a 1 s timeout was given - it blocks until an ESDM server shows up (elapsed %.1f s)",
		      bound_sec, elapsed_since(&start));
	} else {
		CHECK(elapsed_since(&start) < (double)bound_sec,
		      "the timed wait took %.1f s for a 1 s timeout",
		      elapsed_since(&start));
		CHECK_EQ(WEXITSTATUS(status), 0);
	}

	esdm_aux_fini_wait_for_need_entropy();
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_wait_without_init();
	test_init_fini();
	test_wait_honours_timeout();

	return common_test_result("aux_client");
}
