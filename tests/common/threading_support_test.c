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
 * Tests for common/threading_support.c - the worker pool the server, the RPC
 * services and the entropy source monitor all run on.
 *
 * Covered are the properties the pool promises and its users would silently
 * lose if they broke:
 *
 *   - a thread group keeps its own slots, so a fully occupied group cannot
 *     starve another (which is what the group split exists for),
 *   - the return codes of the spawned jobs reach the waiter, ORed together,
 *   - a group outside the configured range - including the gap below the
 *     special groups - is rejected rather than indexing the slot array out of
 *     bounds,
 *   - the reserved special groups each get their own slot,
 *   - thread_fork_join() runs every task exactly once, whether it can spawn
 *     threads or falls back to running them inline.
 *
 * Every wait is bounded, so a regression that wedges the pool shows up as a
 * failed check rather than a test that never returns.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "threading_support.h"

#define TEST_GROUPS 2
#define TEST_PER_GROUP (THREADING_MAX_THREADS / TEST_GROUPS)

/* Upper bound for every wait below - generous, but never reached when sane */
#define WAIT_TIMEOUT_MS 20000
#define WAIT_STEP_US 1000

static atomic_uint jobs_run;
static atomic_bool release_workers;
static atomic_uint blocked_workers;
static atomic_bool signal_target_running;
static volatile sig_atomic_t signal_received;

static bool wait_until_uint(atomic_uint *flag, unsigned int value)
{
	unsigned int waited;

	for (waited = 0; waited < WAIT_TIMEOUT_MS * 1000;
	     waited += WAIT_STEP_US) {
		if (atomic_load(flag) >= value)
			return true;
		usleep(WAIT_STEP_US);
	}

	return atomic_load(flag) >= value;
}

static bool wait_until_bool(atomic_bool *flag)
{
	unsigned int waited;

	for (waited = 0; waited < WAIT_TIMEOUT_MS * 1000;
	     waited += WAIT_STEP_US) {
		if (atomic_load(flag))
			return true;
		usleep(WAIT_STEP_US);
	}

	return atomic_load(flag);
}

static void sighup_handler(int sig)
{
	(void)sig;
	signal_received = 1;
}

/* A job that simply records that it ran */
static int job_count(void *data)
{
	(void)data;
	atomic_fetch_add(&jobs_run, 1);
	return 0;
}

/* A job that reports the return code it was handed */
static int job_retcode(void *data)
{
	atomic_fetch_add(&jobs_run, 1);
	return (int)(intptr_t)data;
}

/*
 * A job that occupies its slot until it is released. It gives up on its own
 * after the timeout so a broken pool fails the test instead of hanging it.
 */
static int job_block(void *data)
{
	unsigned int waited;

	(void)data;
	atomic_fetch_add(&blocked_workers, 1);

	for (waited = 0; waited < WAIT_TIMEOUT_MS * 1000;
	     waited += WAIT_STEP_US) {
		if (atomic_load(&release_workers))
			return 0;
		usleep(WAIT_STEP_US);
	}

	return -ETIMEDOUT;
}

static void test_init(void)
{
	/*
	 * A reduced stack size has to be configured before the pool is set up,
	 * because the pool applies it to the thread attribute it creates.
	 */
	thread_set_default_stacksize(512 * 1024);

	/* More groups than there are slots cannot be honored */
	CHECK_EQ(thread_init(THREADING_MAX_THREADS + 1), -EINVAL);

	CHECK_EQ(thread_init(TEST_GROUPS), 0);

	/* The pool is initialized once; a repeated call is a no-op */
	CHECK_EQ(thread_init(TEST_GROUPS), 0);

	/* The range check applies to the repeated call as well */
	CHECK_EQ(thread_init(THREADING_MAX_THREADS + 1), -EINVAL);
}

static void test_start_and_wait(void)
{
	unsigned int i;

	atomic_store(&jobs_run, 0);

	for (i = 0; i < 4; i++)
		CHECK_EQ(thread_start(job_count, NULL, 0, NULL), 0);

	CHECK_EQ(thread_wait(false), 0);
	CHECK_EQ(atomic_load(&jobs_run), 4);

	CHECK_EQ(thread_wait_all(true), 0);
}

static void test_return_codes(void)
{
	int ret_ancestor = -1;

	atomic_store(&jobs_run, 0);

	/* The waiter receives the return codes of its children ORed together */
	CHECK_EQ(thread_start(job_retcode, (void *)(intptr_t)1, 0, NULL), 0);
	CHECK_EQ(thread_start(job_retcode, (void *)(intptr_t)2, 0, NULL), 0);
	CHECK_EQ(thread_start(job_retcode, (void *)(intptr_t)4, 1, NULL), 0);

	CHECK_EQ(thread_wait(false), 7);
	CHECK_EQ(atomic_load(&jobs_run), 3);

	/*
	 * The same codes are handed out once more by the final wait, which
	 * joins the threads and clears the slots afterwards.
	 */
	CHECK_EQ(thread_wait_all(true), 7);

	/* With the slots cleared, a fresh job reports no ancestor code */
	atomic_store(&jobs_run, 0);
	CHECK_EQ(thread_start(job_count, NULL, 0, &ret_ancestor), 0);
	CHECK_EQ(ret_ancestor, 0);
	CHECK_EQ(thread_wait(false), 0);
	CHECK_EQ(atomic_load(&jobs_run), 1);
	CHECK_EQ(thread_wait_all(true), 0);
}

static void test_invalid_group(void)
{
	atomic_store(&jobs_run, 0);

	/* The first group beyond the configured ones */
	CHECK_EQ(thread_start(job_count, NULL, TEST_GROUPS, NULL), -EINVAL);
	CHECK_EQ(thread_start(job_count, NULL, TEST_GROUPS + 1000, NULL),
		 -EINVAL);

	/*
	 * The values between the regular groups and the special ones are not
	 * special either: they must be rejected rather than mapped onto a
	 * wrapped slot number.
	 */
	CHECK_EQ(thread_start(job_count, NULL,
			      (uint32_t)-(ESDM_THREAD_MAX_SPECIAL_GROUPS + 1),
			      NULL),
		 -EINVAL);
	CHECK_EQ(thread_start(job_count, NULL,
			      (uint32_t)-(ESDM_THREAD_MAX_SPECIAL_GROUPS + 2),
			      NULL),
		 -EINVAL);

	CHECK_EQ(atomic_load(&jobs_run), 0);
}

static void test_special_groups(void)
{
	static const uint32_t special[] = {
		ESDM_THREAD_CUSE_POLL_GROUP,  ESDM_THREAD_ES_MONITOR,
		ESDM_THREAD_RPC_UNPRIV_GROUP, ESDM_THREAD_EGD_GROUP,
		ESDM_THREAD_DRNG_RESEED,      ESDM_THREAD_PERIODIC_SELFTEST
	};
	const unsigned int num =
		(unsigned int)(sizeof(special) / sizeof(special[0]));
	unsigned int i;

	atomic_store(&jobs_run, 0);

	/*
	 * Each special group has a slot of its own, so all of them can be
	 * occupied at the same time even though the regular pool is untouched.
	 */
	for (i = 0; i < num; i++)
		CHECK_EQ(thread_start(job_count, NULL, special[i], NULL), 0);

	/* thread_wait() covers the regular pool only - poll for the specials */
	CHECK(wait_until_uint(&jobs_run, num),
	      "only %u of %u special group jobs ran", atomic_load(&jobs_run),
	      num);

	/* Which is what waiting for the system threads is for */
	CHECK_EQ(thread_wait_all(true), 0);
}

static void test_group_isolation(void)
{
	unsigned int i;

	atomic_store(&jobs_run, 0);
	atomic_store(&blocked_workers, 0);
	atomic_store(&release_workers, false);

	/* Fill every slot of group 0 with a job that will not finish yet */
	for (i = 0; i < TEST_PER_GROUP; i++)
		CHECK_EQ(thread_start(job_block, NULL, 0, NULL), 0);

	CHECK(wait_until_uint(&blocked_workers, TEST_PER_GROUP),
	      "only %u of %u group 0 workers started",
	      atomic_load(&blocked_workers), (unsigned int)TEST_PER_GROUP);

	/*
	 * Group 1 keeps its own slots, so this must be scheduled right away
	 * instead of waiting for group 0 to drain - which it never would,
	 * since this very job is what releases group 0.
	 */
	CHECK_EQ(thread_start(job_count, NULL, 1, NULL), 0);
	CHECK(wait_until_uint(&jobs_run, 1),
	      "group 1 did not get a slot while group 0 was fully occupied");

	atomic_store(&release_workers, true);

	CHECK_EQ(thread_wait(false), 0);
	CHECK_EQ(thread_wait_all(true), 0);
}

/* The grandchild that the signal is aimed at */
static int job_await_signal(void *data)
{
	unsigned int waited;

	(void)data;
	atomic_store(&signal_target_running, true);

	for (waited = 0; waited < WAIT_TIMEOUT_MS * 1000;
	     waited += WAIT_STEP_US) {
		if (signal_received)
			return 0;
		usleep(WAIT_STEP_US);
	}

	return -ETIMEDOUT;
}

/* Schedules the grandchild and returns, so its parent is not the main thread */
static int job_spawn_signal_target(void *data)
{
	(void)data;
	return thread_start(job_await_signal, NULL, 1, NULL);
}

static void test_send_signal(void)
{
	struct sigaction sa, old;
	unsigned int waited;

	/* Out of range groups are ignored rather than indexing the slot array */
	thread_send_signal(TEST_GROUPS, SIGHUP);
	thread_send_signal(TEST_GROUPS + 1000, SIGHUP);
	thread_send_signal((uint32_t)-(ESDM_THREAD_MAX_SPECIAL_GROUPS + 1),
			   SIGHUP);
	/* An empty group is a no-op too */
	thread_send_signal(0, SIGHUP);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sighup_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	CHECK_EQ(sigaction(SIGHUP, &sa, &old), 0);

	signal_received = 0;
	atomic_store(&signal_target_running, false);

	/*
	 * thread_send_signal() deliberately never signals the caller's own
	 * children, so the target is scheduled by a child instead: it ends up
	 * in group 1 with a parent that is not this thread.
	 */
	CHECK_EQ(thread_start(job_spawn_signal_target, NULL, 0, NULL), 0);
	CHECK(wait_until_bool(&signal_target_running),
	      "the signal target thread did not start");

	for (waited = 0; !signal_received && waited < WAIT_TIMEOUT_MS * 1000;
	     waited += WAIT_STEP_US) {
		thread_send_signal(1, SIGHUP);
		usleep(WAIT_STEP_US);
	}

	CHECK(signal_received, "the signal never reached the thread group");

	CHECK_EQ(thread_wait(false), 0);
	CHECK_EQ(thread_wait_all(true), 0);
	CHECK_EQ(sigaction(SIGHUP, &old, NULL), 0);
}

struct fork_join_arg {
	unsigned int index;
	unsigned int runs;
	pthread_t tid;
};

static void *fork_join_task(void *arg)
{
	struct fork_join_arg *a = arg;

	a->runs++;
	a->tid = pthread_self();
	return NULL;
}

static void test_fork_join(void)
{
	struct fork_join_arg args[8];
	unsigned int i;

	for (i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
		args[i].index = i;
		args[i].runs = 0;
		args[i].tid = 0;
	}

	/* Zero tasks is a no-op */
	thread_fork_join(fork_join_task, args, sizeof(args[0]), 0);
	CHECK_EQ(args[0].runs, 0);

	/* A single task always runs inline, on the caller's own thread */
	thread_fork_join(fork_join_task, args, sizeof(args[0]), 1);
	CHECK_EQ(args[0].runs, 1);
	CHECK(pthread_equal(args[0].tid, pthread_self()),
	      "a single fork/join task did not run inline");
	CHECK_EQ(args[1].runs, 0);

	/* Every task of a batch runs exactly once, against its own argument */
	for (i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
		args[i].runs = 0;
		args[i].tid = 0;
	}
	thread_fork_join(fork_join_task, args, sizeof(args[0]),
			 sizeof(args) / sizeof(args[0]));
	for (i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
		CHECK(args[i].runs == 1, "task %u ran %u times", i,
		      args[i].runs);
		CHECK_EQ(args[i].index, i);
	}
}

static void check_thread_name(enum esdm_request_type type, uint32_t id,
			      const char *expect)
{
	char name[ESDM_THREAD_MAX_NAMELEN];

	CHECK_EQ(thread_set_name(type, id), 0);

	memset(name, 0, sizeof(name));
	CHECK_EQ(thread_get_name(name, sizeof(name)), 0);
	CHECK_STR_EQ(name, expect);
}

static void test_thread_names(void)
{
	char name[ESDM_THREAD_MAX_NAMELEN];

	check_thread_name(es_monitor, 0, "ESDM es_monitor");
	check_thread_name(es_kernel_feeder, 0, "ESDM krnl_feed");
	check_thread_name(rpc_unpriv_server, 0, "ESDM unpriv_rpc");
	check_thread_name(rpc_priv_server, 0, "ESDM priv_rpc");
	check_thread_name(rpc_handler_unpriv, 7, "ESDM rpc_up007");
	check_thread_name(rpc_handler_priv, 7, "ESDM rpc_p007");
	check_thread_name(cuse_poll, 0, "ESDM cuse_poll");
	check_thread_name(egd_server, 0, "ESDM egd_server");
	check_thread_name(drng_reseed, 0, "ESDM drng_rsd");
	check_thread_name(periodic_selftest, 0, "ESDM selftest");

	/* A buffer too small for the name is reported rather than truncated */
	CHECK_EQ(thread_get_name(name, 4), -ERANGE);
}

static void test_stop_spawning(void)
{
	struct fork_join_arg args[4];
	unsigned int i;

	for (i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
		args[i].index = i;
		args[i].runs = 0;
		args[i].tid = 0;
	}

	atomic_store(&jobs_run, 0);

	/* Once spawning is stopped, no further job is accepted ... */
	thread_stop_spawning();
	CHECK_EQ(thread_start(job_count, NULL, 0, NULL), -ESHUTDOWN);
	CHECK_EQ(thread_start(job_count, NULL, ESDM_THREAD_ES_MONITOR, NULL),
		 -ESHUTDOWN);
	CHECK_EQ(atomic_load(&jobs_run), 0);

	/*
	 * ... while thread_fork_join() still completes its batch, inline: its
	 * tasks write into the caller's stack frame and must not be orphaned
	 * by a teardown.
	 */
	thread_fork_join(fork_join_task, args, sizeof(args[0]),
			 sizeof(args) / sizeof(args[0]));
	for (i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
		CHECK(args[i].runs == 1, "task %u ran %u times during teardown",
		      i, args[i].runs);
		CHECK(pthread_equal(args[i].tid, pthread_self()),
		      "task %u was not run inline during teardown", i);
	}

	/* A wait while a cancellation is pending is turned into one */
	CHECK_EQ(thread_release(false, true), 0);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_init();
	test_start_and_wait();
	test_return_codes();
	test_invalid_group();
	test_special_groups();
	test_group_isolation();
	test_send_signal();
	test_fork_join();
	test_thread_names();

	/* Stops the pool for good, so it has to come last */
	test_stop_spawning();

	return common_test_result("threading_support");
}
