/*
 * Self tests of the ESDM: the crypto implementations and the entropy sources
 *
 * The known answer tests of the hash and the DRNG implementation decide
 * whether the ESDM hands out random bits at all, and the entropy sources are
 * asked in the same pass whether they still work.
 *
 * There is one such pass - esdm_selftest_run() - and it is what the ESDM runs
 * when it comes up, what an operator reaches over the privileged RPC endpoint,
 * and what the worker at the end of this file repeats on a fixed interval. The
 * three differ in what makes them happen, not in what they do or in what they
 * leave behind: one state, one count of completed passes, and one interval
 * timed from whichever pass ran last.
 *
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

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_es_mgr_cb.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "esdm_selftest.h"
#include "helper.h"
#include "mutex_w.h"
#include "queue.h"
#include "ret_checkers.h"
#include "threading_support.h"
#include "visibility.h"

/************************ Self tests of the crypto ****************************/

/*
 * Outcome of the self tests of the hash and the DRNG implementation. Atomic:
 * the worker writes it while every generate path reads it unlocked. It starts
 * out undone, which holds the output back just like a failure does.
 */
static atomic_int esdm_selftest_result = esdm_selftest_undone;

DSO_PUBLIC
enum esdm_selftest_state esdm_selftest_crypto_state(void)
{
	return (enum esdm_selftest_state)atomic_load(&esdm_selftest_result);
}

DSO_PUBLIC
bool esdm_selftest_crypto_passed(void)
{
	return (esdm_selftest_crypto_state() == esdm_selftest_passed);
}

const char *esdm_selftest_crypto_state_name(void)
{
	switch (esdm_selftest_crypto_state()) {
	case esdm_selftest_passed:
		return "passed";
	case esdm_selftest_failed:
		return "failed";
	case esdm_selftest_undone:
	default:
		return "undone";
	}
}

/* Record the outcome of a self test run. A failure is final - see below. */
static void esdm_selftest_record(int ret)
{
	int expected = esdm_selftest_undone;

	if (ret) {
		if (atomic_exchange(&esdm_selftest_result,
				    esdm_selftest_failed) !=
		    esdm_selftest_failed) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_DRNG,
				"Self test failed (%d) - the ESDM stops handing out random bits\n",
				ret);
		}
		return;
	}

	/* A pass never clears a failure - see above. */
	atomic_compare_exchange_strong(&esdm_selftest_result, &expected,
				       esdm_selftest_passed);
}

#ifdef ESDM_TESTMODE
void esdm_test_selftest_set_failed(void)
{
	esdm_selftest_record(-EFAULT);
}
#endif

int esdm_selftest_crypto(void)
{
	struct esdm_drng *drng = esdm_drng_node_instance();
	const struct esdm_hash_cb *hash_cb;
	const struct esdm_drng_cb *drng_cb;
	int ret = 0;

	/* Perform selftest of current crypto implementations */
	hash_cb = drng->hash_cb;
	if (hash_cb->hash_selftest)
		ret = hash_cb->hash_selftest();
	else
		esdm_logger(LOGGER_WARN, LOGGER_C_DRNG,
			    "Hash self test missing\n");
	CKINT_LOG(ret, "Hash self test failed: %d\n", ret);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		    "Hash self test passed successfully\n");

	mutex_w_lock(&drng->lock);
	drng_cb = drng->drng_cb;
	if (drng_cb->drng_selftest)
		ret = drng_cb->drng_selftest();
	else
		esdm_logger(LOGGER_WARN, LOGGER_C_DRNG,
			    "DRNG self test missing\n");
	mutex_w_unlock(&drng->lock);
	CKINT_LOG(ret, "DRNG self test failed: %d\n", ret);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		    "DRNG self test passed successfully\n");

out:
	esdm_drng_put_instances();
	esdm_selftest_record(ret);
	return ret;
}

/******************** Self tests of the entropy sources ***********************/

/*
 * Outcome of the last pass over the entropy source self tests, and how many
 * sources it covered.
 */
static atomic_int esdm_es_selftest_result = esdm_selftest_undone;
static atomic_uint_fast32_t esdm_es_selftest_tested = 0;
static atomic_uint_fast32_t esdm_es_selftest_failed = 0;

DSO_PUBLIC
enum esdm_selftest_state esdm_selftest_es_state(void)
{
	return (enum esdm_selftest_state)atomic_load(&esdm_es_selftest_result);
}

const char *esdm_selftest_es_state_name(void)
{
	switch (esdm_selftest_es_state()) {
	case esdm_selftest_passed:
		return "passed";
	case esdm_selftest_failed:
		return "failed";
	case esdm_selftest_undone:
	default:
		return "undone";
	}
}

DSO_PUBLIC
uint32_t esdm_selftest_es_sources(void)
{
	return (uint32_t)atomic_load(&esdm_es_selftest_tested);
}

DSO_PUBLIC
uint32_t esdm_selftest_es_failures(void)
{
	return (uint32_t)atomic_load(&esdm_es_selftest_failed);
}

int esdm_selftest_es(void)
{
	uint32_t tested = 0, failed = 0, i;
	int ret = 0;

	for_each_esdm_es (i) {
		int es_ret;

		if (!esdm_es[i]->selftest) {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
				    "%s ES: no self test\n", esdm_es[i]->name);
			continue;
		}

		tested++;
		es_ret = esdm_es[i]->selftest();
		if (es_ret) {
			failed++;
			/* The first failure is the one reported to the caller */
			if (!ret)
				ret = es_ret;
			esdm_logger(LOGGER_ERR, LOGGER_C_ES,
				    "%s ES: self test failed: %d\n",
				    esdm_es[i]->name, es_ret);
		} else {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
				    "%s ES: self test passed\n",
				    esdm_es[i]->name);
		}
	}

	atomic_store(&esdm_es_selftest_tested, tested);
	atomic_store(&esdm_es_selftest_failed, failed);
	atomic_store(&esdm_es_selftest_result,
		     failed ? esdm_selftest_failed : esdm_selftest_passed);

	return ret;
}

/***************************** The self test pass *****************************/

/*
 * How many self test passes completed, and when the last one did on
 * CLOCK_MONOTONIC.
 */
static atomic_llong esdm_selftest_passes_done = 0;
static atomic_llong esdm_selftest_last_pass = 0;

DSO_PUBLIC
int esdm_selftest_run(void)
{
	int ret, es_ret;

	ret = esdm_selftest_crypto();

	/* The entropy sources are asked the same question in the same pass. */
	es_ret = esdm_selftest_es();

	/*
	 * Stamped when the pass is over rather than when it started: what the
	 * interval derived from it bounds is the time the implementations go
	 * unverified, so a run that took a while does not shorten the next
	 * wait.
	 */
	atomic_store(&esdm_selftest_last_pass, esdm_monotonic_now());
	atomic_fetch_add(&esdm_selftest_passes_done, 1);

	return ret ? ret : es_ret;
}

long long esdm_selftest_passes(void)
{
	return atomic_load(&esdm_selftest_passes_done);
}

/************************ The periodic self test worker ***********************/

/*
 * Is the periodic self test worker on duty? Only the thread that flips this to
 * true spawns one, and the worker clears it when it leaves.
 */
static atomic_bool esdm_selftest_worker_active = false;

/* Where the worker waits between its self test runs - see the worker below. */
static DECLARE_WAIT_QUEUE(esdm_selftest_wait);

/*
 * Shutdown request for the worker, separate from the DRNG manager terminating
 * for the same reason as the reseed worker's: it has to be gone before the
 * threads are joined, which happens while the DRNGs are still operating.
 */
static atomic_bool esdm_selftest_worker_terminate = false;

/* Is the worker to stop what it is doing and leave? */
static bool esdm_selftest_stop(void)
{
	return esdm_drng_mgr_terminating() ||
	       atomic_load(&esdm_selftest_worker_terminate);
}

bool esdm_selftest_periodic_running(void)
{
	return atomic_load(&esdm_selftest_worker_active);
}

uint32_t esdm_selftest_periodic_interval(void)
{
	return ESDM_SELFTEST_INTERVAL_SEC;
}

void esdm_selftest_periodic_stop(void)
{
	atomic_store(&esdm_selftest_worker_terminate, true);
	thread_wake_all(&esdm_selftest_wait);
}

/*
 * The worker waits in slices of this length rather than for the whole interval
 * at once: a wakeup delivered just before it starts waiting is not remembered,
 * so a shutdown request could otherwise be sat out for a full self test
 * interval - which is long, and which the join in esdm_fini() would wait for.
 */
static const struct timespec esdm_selftest_wait_slice = { .tv_sec = 1,
							  .tv_nsec = 0 };

/*
 * Is the next pass due? Timed from the last pass that completed, whoever ran
 * it: the ESDM coming up, an operator asking for one and the worker repeating
 * them all verify the same implementations, so a pass that happened for another
 * reason defers the periodic one just as much as the worker's own.
 */
static bool esdm_selftest_due(void)
{
	time_t last = (time_t)atomic_load(&esdm_selftest_last_pass);

	/* No pass recorded yet - one is due now */
	if (!last)
		return true;

	return !!esdm_time_after_now(last + ESDM_SELFTEST_INTERVAL_SEC);
}

static int esdm_periodic_selftest_worker(void *unused)
{
	/* Written by thread_timedwait_no_event() below */
	int ret = 0;

	(void)unused;

	thread_set_name(periodic_selftest, 0);

	while (!esdm_selftest_stop()) {
		thread_timedwait_no_event(&esdm_selftest_wait,
					  &esdm_selftest_wait_slice);

		if (esdm_selftest_stop())
			break;

		/* Not due yet - go back to waiting */
		if (!esdm_selftest_due())
			continue;

		esdm_selftest_run();

		/*
		 * A failed self test is not recovered from within this process,
		 * so there is nothing left for the worker to find out - and the
		 * DRNG lock is not taken every interval to find it out again.
		 */
		if (!esdm_selftest_crypto_passed())
			break;
	}

	atomic_store(&esdm_selftest_worker_active, false);

	/* A wait that timed out is what the worker does, not a failure. */
	(void)ret;
	return 0;
}

bool esdm_selftest_periodic_start(void)
{
	if (esdm_selftest_stop())
		return false;

	if (atomic_load(&esdm_selftest_worker_active))
		return true;

	/*
	 * No thread pool in this process - a library user that never called
	 * thread_init().
	 */
	if (!thread_available())
		return false;

	if (atomic_exchange(&esdm_selftest_worker_active, true))
		return true;

	if (thread_start(esdm_periodic_selftest_worker, NULL,
			 ESDM_THREAD_PERIODIC_SELFTEST, NULL)) {
		atomic_store(&esdm_selftest_worker_active, false);
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"No worker available for the periodic self tests - the crypto implementations are only tested at start up\n");
		return false;
	}

	return true;
}
