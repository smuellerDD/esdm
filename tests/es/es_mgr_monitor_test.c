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
 * Test of the entropy source monitor of the ES manager.
 *
 * The monitor is a long-running worker loop, so it is driven here exactly the
 * way the RPC server drives it: esdm_init(), then esdm_init_monitor() on a
 * thread of the ESDM_THREAD_ES_MONITOR group. The test then asserts the
 * contract the rest of the code base relies on:
 *
 * - the privileged-initialization completion callback is invoked, exactly
 *   once, and reasonably promptly - the RPC server blocks its startup on this
 *   notification, so a monitor that never issues it hangs the daemon,
 * - esdm_es_mgr_running() reports the monitor's life cycle,
 * - esdm_es_mgr_monitor_pause() is mutually exclusive, i.e. a second pause
 *   blocks until the first one resumed. This is the property esdm_reinit()
 *   depends on to keep a monitor pass off the entropy sources while they are
 *   torn down and re-initialized,
 * - esdm_reinit(), the actual user of pause/resume, completes while the
 *   monitor is running,
 * - esdm_es_mgr_monitor_wakeup() is safe before, during and after the monitor
 *   runs, and
 * - shutdown terminates the loop instead of sitting out its sleep interval -
 *   the sleep is an interruptible wait for exactly this reason. A regression
 *   to an uninterruptible sleep shows up as this test running into its meson
 *   timeout.
 *
 * Note what is NOT covered: that no monitor pass is *in flight* while a pause
 * is held. Observing that from the outside would need instrumentation of the
 * per-ES monitor callbacks; the mutual exclusion checked here is the part that
 * is externally visible.
 *
 * If no active entropy source provides a monitor_es callback, the monitor
 * completes the notification and returns right away. The test detects that and
 * keeps checking everything that still applies rather than claiming to have
 * exercised the loop.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "threading_support.h"

/* Bound for every wait in this test - generous, as it only guards a hang. */
#define ES_MGR_MONITOR_TIMEOUT_MS 30000

/* How long a blocked pause is observed before it is considered blocked. */
#define ES_MGR_MONITOR_BLOCK_CHECK_MS 300

/*
 * Deadline for the whole test, comfortably below the meson timeout.
 *
 * Not every wait here can be bounded from the calling thread: pause(),
 * esdm_reinit() and esdm_fini() block on the ES monitor lock and on joining
 * the monitor, and there is no timed variant of either. Should one of them
 * fail to return, a watchdog thread reports the step the test was in and
 * aborts, which turns an unexplained meson timeout into a diagnosable failure.
 */
#define ES_MGR_MONITOR_DEADLINE_SEC 90

static atomic_uint priv_init_calls = 0;
static atomic_bool monitor_returned = false;
static atomic_int monitor_rc = 0;

/* State of the helper thread of the pause serialization test */
static atomic_bool helper_running = false;
static atomic_bool helper_acquired = false;

/* Name of the step the test is currently in, for the watchdog below. */
static const char *_Atomic es_mgr_step = "startup";

static void es_mgr_enter(const char *step)
{
	atomic_store(&es_mgr_step, step);
}

static void es_mgr_priv_init_completion(void)
{
	atomic_fetch_add(&priv_init_calls, 1);
}

static int es_mgr_monitor_thread(void *unused)
{
	int rc;

	(void)unused;

	thread_set_name(es_monitor, 0);
	rc = esdm_init_monitor(es_mgr_priv_init_completion);

	atomic_store(&monitor_rc, rc);
	atomic_store(&monitor_returned, true);

	return rc;
}

static void es_mgr_sleep_ms(unsigned int msecs)
{
	struct timespec ts = { .tv_sec = msecs / 1000,
			       .tv_nsec = (long)(msecs % 1000) * 1000 * 1000 };

	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

/* Wait until @flag is set, but no longer than @timeout_ms. */
static bool es_mgr_wait_flag(atomic_bool *flag, unsigned int timeout_ms)
{
	unsigned int waited;

	for (waited = 0; waited < timeout_ms; waited += 10) {
		if (atomic_load(flag))
			return true;
		es_mgr_sleep_ms(10);
	}

	return atomic_load(flag);
}

/* Wait until the completion callback fired, but no longer than @timeout_ms. */
static bool es_mgr_wait_priv_init(unsigned int timeout_ms)
{
	unsigned int waited;

	for (waited = 0; waited < timeout_ms; waited += 10) {
		if (atomic_load(&priv_init_calls))
			return true;
		es_mgr_sleep_ms(10);
	}

	return atomic_load(&priv_init_calls) != 0;
}

/*
 * Watchdog for the waits that cannot be bounded by their caller - see
 * ES_MGR_MONITOR_DEADLINE_SEC.
 */
static void *es_mgr_watchdog(void *unused)
{
	unsigned int waited;

	(void)unused;

	for (waited = 0; waited < ES_MGR_MONITOR_DEADLINE_SEC; waited++) {
		if (atomic_load(&es_mgr_step) == NULL)
			return NULL;
		es_mgr_sleep_ms(1000);
	}

	printf("ES monitor - fail: stuck in step \"%s\" for %u seconds, aborting\n",
	       atomic_load(&es_mgr_step), ES_MGR_MONITOR_DEADLINE_SEC);
	fflush(stdout);

	/*
	 * _exit rather than abort: a core dump of a deliberately killed test
	 * is noise, and the failure is already on stdout.
	 */
	_exit(1);
}

/****************************** Test cases ***********************************/

static int es_mgr_monitor_startup(void)
{
	if (!es_mgr_wait_priv_init(ES_MGR_MONITOR_TIMEOUT_MS)) {
		printf("ES monitor - fail: privileged initialization completion not signalled\n");
		return 1;
	}
	printf("ES monitor - pass: privileged initialization completion signalled\n");

	if (!esdm_es_mgr_running()) {
		printf("ES monitor - fail: ES manager reports not running while the monitor is up\n");
		return 1;
	}
	printf("ES monitor - pass: ES manager reports running\n");

	return 0;
}

/*
 * The wakeup is a broadcast on the monitor's wait queue. It must be a no-op -
 * and in particular must not crash - no matter whether the monitor currently
 * sleeps, runs a pass or has already exited.
 */
static int es_mgr_monitor_wakeup(void)
{
	unsigned int i;

	for (i = 0; i < 10; i++)
		esdm_es_mgr_monitor_wakeup();

	printf("ES monitor - pass: repeated wakeup is safe\n");
	return 0;
}

static void *es_mgr_pause_helper(void *unused)
{
	(void)unused;

	atomic_store(&helper_running, true);

	/*
	 * Blocks as long as the main thread holds the pause. Resumed
	 * immediately so the monitor is not left quiesced.
	 */
	esdm_es_mgr_monitor_pause();
	atomic_store(&helper_acquired, true);
	esdm_es_mgr_monitor_resume();

	return NULL;
}

static int es_mgr_monitor_pause_serialize(void)
{
	pthread_t helper;
	int ret = 0;

	esdm_es_mgr_monitor_pause();

	if (pthread_create(&helper, NULL, es_mgr_pause_helper, NULL)) {
		esdm_es_mgr_monitor_resume();
		printf("ES monitor - fail: helper thread could not be created\n");
		return 1;
	}

	/* Ensure the helper actually reached the pause call. */
	if (!es_mgr_wait_flag(&helper_running, ES_MGR_MONITOR_TIMEOUT_MS)) {
		esdm_es_mgr_monitor_resume();
		pthread_join(helper, NULL);
		printf("ES monitor - fail: helper thread did not start\n");
		return 1;
	}

	es_mgr_sleep_ms(ES_MGR_MONITOR_BLOCK_CHECK_MS);

	if (atomic_load(&helper_acquired)) {
		printf("ES monitor - fail: pause is not mutually exclusive - second pause succeeded while the first was held\n");
		ret = 1;
	} else {
		printf("ES monitor - pass: second pause blocks while the first is held\n");
	}

	esdm_es_mgr_monitor_resume();

	if (!es_mgr_wait_flag(&helper_acquired, ES_MGR_MONITOR_TIMEOUT_MS)) {
		printf("ES monitor - fail: second pause not granted after resume\n");
		ret = 1;
	} else {
		printf("ES monitor - pass: second pause granted after resume\n");
	}

	pthread_join(helper, NULL);

	/* A pause/resume cycle must leave the lock reusable. */
	esdm_es_mgr_monitor_pause();
	esdm_es_mgr_monitor_resume();
	printf("ES monitor - pass: pause/resume cycle repeatable\n");

	return ret;
}

/*
 * esdm_reinit() brackets the reinitialization of all entropy sources with
 * pause/resume. Run it against the live monitor - a pause that does not
 * release, or a resume that is skipped on an error path, deadlocks here.
 */
static int es_mgr_monitor_reinit(void)
{
	int rc = esdm_reinit();

	if (rc) {
		printf("ES monitor - fail: esdm_reinit() while the monitor runs returned %d\n",
		       rc);
		return 1;
	}

	if (!esdm_es_mgr_running()) {
		printf("ES monitor - fail: ES manager stopped running across esdm_reinit()\n");
		return 1;
	}

	printf("ES monitor - pass: esdm_reinit() completes while the monitor runs\n");
	return 0;
}

static int es_mgr_monitor_shutdown(void)
{
	int ret = 0;

	/*
	 * esdm_fini() sets the terminate flag, wakes the monitor and joins it.
	 * Returning from here at all is the assertion: a monitor that ignores
	 * the termination request never gets joined and the test hits the
	 * meson timeout.
	 */
	esdm_fini();

	if (esdm_es_mgr_running()) {
		printf("ES monitor - fail: ES manager still reports running after esdm_fini()\n");
		ret = 1;
	} else {
		printf("ES monitor - pass: ES manager reports stopped after esdm_fini()\n");
	}

	if (!es_mgr_wait_flag(&monitor_returned, ES_MGR_MONITOR_TIMEOUT_MS)) {
		printf("ES monitor - fail: monitor did not return after esdm_fini()\n");
		return ret + 1;
	}
	printf("ES monitor - pass: monitor returned after esdm_fini()\n");

	if (atomic_load(&monitor_rc)) {
		printf("ES monitor - fail: monitor returned %d\n",
		       atomic_load(&monitor_rc));
		ret += 1;
	}

	if (atomic_load(&priv_init_calls) != 1) {
		printf("ES monitor - fail: completion callback invoked %u times, expected once\n",
		       atomic_load(&priv_init_calls));
		ret += 1;
	} else {
		printf("ES monitor - pass: completion callback invoked exactly once\n");
	}

	/* Waking a monitor that is gone must not fault. */
	esdm_es_mgr_monitor_wakeup();
	printf("ES monitor - pass: wakeup after shutdown is safe\n");

	return ret;
}

int main(int argc, char *argv[])
{
	pthread_t watchdog;
	int ret;

	(void)argc;
	(void)argv;

	/*
	 * Unbuffered progress output: should the process be killed - by the
	 * watchdog below or by the meson timeout - the record of how far the
	 * test got must not die with it in a block buffered pipe.
	 */
	setvbuf(stdout, NULL, _IONBF, 0);

	if (pthread_create(&watchdog, NULL, es_mgr_watchdog, NULL)) {
		printf("ES monitor - fail: watchdog thread could not be created\n");
		return 1;
	}
	pthread_detach(watchdog);

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* Waking a monitor that was never started must not fault. */
	esdm_es_mgr_monitor_wakeup();

	ret = esdm_init();
	if (ret) {
		printf("ES monitor - fail: esdm_init() returned %d\n", ret);
		return 1;
	}

	/* Same setup as the RPC server: one regular thread group. */
	ret = thread_init(1);
	if (ret) {
		printf("ES monitor - fail: thread_init() returned %d\n", ret);
		esdm_fini();
		return 1;
	}

	ret = thread_start(es_mgr_monitor_thread, NULL, ESDM_THREAD_ES_MONITOR,
			   NULL);
	if (ret) {
		printf("ES monitor - fail: monitor thread could not be started: %d\n",
		       ret);
		esdm_fini();
		thread_release(true, true);
		return 1;
	}

	ret = es_mgr_monitor_startup();

	if (atomic_load(&monitor_returned)) {
		printf("ES monitor - info: no active entropy source provides a monitor callback, the monitor loop is not exercised\n");
	} else {
		printf("ES monitor - info: monitor loop is running\n");
	}

	es_mgr_enter("wakeup");
	ret += es_mgr_monitor_wakeup();

	es_mgr_enter("pause serialization");
	ret += es_mgr_monitor_pause_serialize();

	es_mgr_enter("esdm_reinit");
	ret += es_mgr_monitor_reinit();

	es_mgr_enter("shutdown");
	ret += es_mgr_monitor_shutdown();

	es_mgr_enter("thread_release");
	thread_release(true, true);

	/* Retire the watchdog before returning. */
	atomic_store(&es_mgr_step, NULL);

	return ret;
}
