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
 * Stress test for the reference counting of the RPC client library.
 *
 * esdm_rpcc_init_*_service() may be called any number of times within one
 * process - by an application and a preloaded library independently of each
 * other - and the connections are only released once as many finis as inits
 * were seen. Getting that wrong is not visible in a single-threaded run: a
 * count that drops too early frees connections that a concurrent caller still
 * holds, and one that never reaches zero leaks them silently.
 *
 * The test therefore drives init/fini from many threads at once and checks the
 * one invariant the reference counting has to provide: while a caller holds a
 * reference, the service must stay usable, no matter how many other threads
 * init and fini around it.
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "esdm_rpc_client.h"
#include "esdm_logger.h"
#include "tool.h"

struct init_fini_stats {
	atomic_uint_least64_t unpriv_cycles;
	atomic_uint_least64_t priv_cycles;
	atomic_uint_least64_t rpc_calls;
	/* Violations of the reference counting contract - must stay 0. */
	atomic_uint_least64_t ref_errors;
	/* RPC failures, only meaningful when a server was reachable. */
	atomic_uint_least64_t rpc_errors;
};

struct init_fini_thread_arg {
	struct init_fini_stats *stats;
	struct timespec deadline;
	bool do_rpc;
};

static bool deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	if (now.tv_sec > deadline->tv_sec)
		return true;
	if (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)
		return true;

	return false;
}

/*
 * Check out a connection and hand it straight back. This must succeed for as
 * long as the caller holds an init reference - if it does not, a concurrent
 * fini tore the connections down while they were still referenced.
 */
static void check_service_usable(struct init_fini_stats *stats, const char *ctx)
{
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	int ret = esdm_rpcc_get_unpriv_service(&rpc_conn, NULL);

	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_TOOL,
			"%s: service unusable while a reference is held: %s\n",
			ctx, strerror(-ret));
		atomic_fetch_add(&stats->ref_errors, 1);
		return;
	}

	esdm_rpcc_put_unpriv_service(rpc_conn);
}

/*
 * Churn thread: takes and drops references on both services as fast as it can,
 * so the other threads race against the allocation and the teardown of the
 * connection arrays rather than against a steady state.
 */
static void *init_fini_churn(void *arg)
{
	struct init_fini_thread_arg *a = arg;
	struct init_fini_stats *stats = a->stats;

	while (!deadline_passed(&a->deadline)) {
		if (esdm_rpcc_init_unpriv_service(NULL)) {
			atomic_fetch_add(&stats->ref_errors, 1);
			continue;
		}

		/* Our own reference is held here, so this has to work. */
		check_service_usable(stats, "churn");

		if (a->do_rpc) {
			uint8_t buf[16];

			if (esdm_rpcc_get_random_bytes(buf, sizeof(buf)) !=
			    (ssize_t)sizeof(buf))
				atomic_fetch_add(&stats->rpc_errors, 1);
			else
				atomic_fetch_add(&stats->rpc_calls, 1);
		}

		esdm_rpcc_fini_unpriv_service();
		atomic_fetch_add(&stats->unpriv_cycles, 1);

		/*
		 * The privileged service has its own reference count and is
		 * not held by anybody else here, so this drives it through the
		 * whole 0 -> n -> 0 range as well. No RPC is attempted on it,
		 * as that would require root.
		 */
		if (esdm_rpcc_init_priv_service(NULL)) {
			atomic_fetch_add(&stats->ref_errors, 1);
			continue;
		}
		esdm_rpcc_fini_priv_service();
		atomic_fetch_add(&stats->priv_cycles, 1);
	}

	return NULL;
}

/*
 * Holder thread: takes one reference up front and keeps it for the whole run.
 * Every check below must succeed - this is what catches a reference count that
 * drops to zero too early.
 */
static void *init_fini_holder(void *arg)
{
	struct init_fini_thread_arg *a = arg;
	struct init_fini_stats *stats = a->stats;

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		atomic_fetch_add(&stats->ref_errors, 1);
		return NULL;
	}

	while (!deadline_passed(&a->deadline)) {
		check_service_usable(stats, "holder");

		if (a->do_rpc) {
			uint8_t buf[16];

			if (esdm_rpcc_get_random_bytes(buf, sizeof(buf)) !=
			    (ssize_t)sizeof(buf))
				atomic_fetch_add(&stats->rpc_errors, 1);
			else
				atomic_fetch_add(&stats->rpc_calls, 1);
		}
	}

	esdm_rpcc_fini_unpriv_service();

	return NULL;
}

/*
 * Single-threaded check of the counting itself, which the threaded phase can
 * only ever check indirectly.
 *
 * The caller (tool_main) holds exactly one reference when this runs, and this
 * function gives it back in the same state.
 */
static int check_ref_count_semantics(void)
{
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	int errors = 0;
	int ret;

	/* A nested init must not be torn down by its own fini. */
	if (esdm_rpcc_init_unpriv_service(NULL)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "nested init of the unprivileged service failed\n");
		return 1;
	}
	esdm_rpcc_fini_unpriv_service();

	ret = esdm_rpcc_get_unpriv_service(&rpc_conn, NULL);
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_TOOL,
			"service released although a reference is outstanding: %s\n",
			strerror(-ret));
		errors++;
	} else {
		esdm_rpcc_put_unpriv_service(rpc_conn);
	}

	/*
	 * Drop the caller's reference as well: with none left the connections
	 * must be gone, which is what makes the count observably reach zero
	 * rather than just never being used again.
	 */
	esdm_rpcc_fini_unpriv_service();

	rpc_conn = NULL;
	ret = esdm_rpcc_get_unpriv_service(&rpc_conn, NULL);
	if (ret != -EFAULT) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_TOOL,
			"service still available after the last reference was dropped (%d)\n",
			ret);
		if (!ret)
			esdm_rpcc_put_unpriv_service(rpc_conn);
		errors++;
	}

	/* Restore the state the caller handed us. */
	if (esdm_rpcc_init_unpriv_service(NULL)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "re-init of the unprivileged service failed\n");
		return errors + 1;
	}

	rpc_conn = NULL;
	ret = esdm_rpcc_get_unpriv_service(&rpc_conn, NULL);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "service not usable after re-init: %s\n",
			    strerror(-ret));
		errors++;
	} else {
		esdm_rpcc_put_unpriv_service(rpc_conn);
	}

	return errors;
}

/* Is an ESDM server reachable? Decides whether RPC failures count as errors. */
static bool server_reachable(void)
{
	uint8_t buf[16];

	return esdm_rpcc_get_random_bytes(buf, sizeof(buf)) ==
	       (ssize_t)sizeof(buf);
}

int handle_stress_init_fini(double timeout_sec, int num_threads)
{
	struct init_fini_stats stats = { 0 };
	struct init_fini_thread_arg arg = { 0 };
	long cores = sysconf(_SC_NPROCESSORS_ONLN);
	pthread_t *threads;
	long nthreads, i, started = 0;
	int errors;

	if (num_threads > 0)
		cores = num_threads;
	if (cores < 2)
		cores = 2;

	/* One of them is the holder, the rest churn. */
	nthreads = cores;

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "Checking reference counting semantics\n");
	errors = check_ref_count_semantics();
	if (errors) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Reference counting semantics check failed\n");
		return EXIT_FAILURE;
	}

	arg.stats = &stats;
	arg.do_rpc = server_reachable();
	if (!arg.do_rpc) {
		esdm_logger(
			LOGGER_STATUS, LOGGER_C_TOOL,
			"No ESDM server reachable - exercising init/fini only\n");
	}

	clock_gettime(CLOCK_MONOTONIC, &arg.deadline);
	arg.deadline.tv_sec += (time_t)timeout_sec;

	threads = calloc((size_t)nthreads, sizeof(pthread_t));
	if (!threads)
		return EXIT_FAILURE;

	/*
	 * Hand the caller's reference over to the threads for the duration of
	 * the run: with it held, the count could never reach zero and the
	 * allocation and teardown paths would not be raced at all.
	 */
	esdm_rpcc_fini_unpriv_service();

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "Starting %ld threads for %.0f seconds\n", nthreads,
		    timeout_sec);

	for (i = 0; i < nthreads; ++i) {
		void *(*fn)(void *) =
			(i == 0) ? init_fini_holder : init_fini_churn;

		if (pthread_create(&threads[i], NULL, fn, &arg))
			break;
		started++;
	}

	for (i = 0; i < started; ++i)
		pthread_join(threads[i], NULL);

	free(threads);

	/* Take the caller's reference back, so its fini stays balanced. */
	if (esdm_rpcc_init_unpriv_service(NULL)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Failed to re-init the service after the run\n");
		return EXIT_FAILURE;
	}

	if (started != nthreads) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Only %ld of %ld threads could be started\n",
			    started, nthreads);
		return EXIT_FAILURE;
	}

	/* Everything must be balanced again - a last check of the invariant. */
	check_service_usable(&stats, "final");

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "unprivileged init/fini cycles: %" PRIu64 "\n",
		    (uint64_t)atomic_load(&stats.unpriv_cycles));
	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "privileged init/fini cycles:   %" PRIu64 "\n",
		    (uint64_t)atomic_load(&stats.priv_cycles));
	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "RPC calls:                     %" PRIu64 "\n",
		    (uint64_t)atomic_load(&stats.rpc_calls));

	if (atomic_load(&stats.rpc_errors)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "RPC failures:                  %" PRIu64 "\n",
			    (uint64_t)atomic_load(&stats.rpc_errors));
	}

	if (atomic_load(&stats.ref_errors)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_TOOL,
			    "Reference counting violations: %" PRIu64
			    " - TEST FAILED\n",
			    (uint64_t)atomic_load(&stats.ref_errors));
		return EXIT_FAILURE;
	}

	if (atomic_load(&stats.rpc_errors))
		return EXIT_FAILURE;

	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL,
		    "Reference counting stress test passed\n");

	return EXIT_SUCCESS;
}
