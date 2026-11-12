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
 * Latency of esdm_rpcc_get_random_bytes_full() as concurrent callers see it,
 * the maximum first: N threads issue requests of -s bytes back to back for -d
 * seconds, every latency kept for exact percentiles. DRNG reseeds are counted
 * from their seed generation: a request may wait behind one, and an SP800-90C
 * or AIS 20/31 DRG.4 build reseeds every few thousand requests.
 *
 * The server is a child set up as esdm-server sets itself up (the ESDM, its
 * monitor with the reseed worker, the unprivileged RPC worker loop), but
 * unprivileged, in namespaces of its own. Run by meson test --benchmark; by
 * hand, -x measures the server already serving the RPC socket.
 *
 *	rpc_latency_bench [-x] [-t threads] [-d seconds] [-r runs] [-s bytes]
 *			  [-o us] [-j collectors]
 *
 * -o prints every request slower than that, with its time into the run, to
 * line the outliers up with what the server did then. -j sets the number of
 * Jitter RNG collectors of the server, see esdm_config_es_jent_instances_set().
 */

#define _GNU_SOURCE
#include <errno.h>
#include <json-c/json.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "test_pertubation.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"
#include "../test_namespace.h"
#include "../test_wait.h"

/* From esdm.h, whose definitions clash with those of esdm_rpc_client.h */
int esdm_init(void);
int esdm_init_monitor(void (*priv_init_completion)(void));
/* From esdm_config.h */
void esdm_config_es_jent_instances_set(uint32_t instances);

#define BENCH_MAX_LIST 16

static unsigned int bench_threads[BENCH_MAX_LIST] = { 1, 4, 8 };
static unsigned int bench_nthreads = 3;
static unsigned int bench_seconds = 10;
static unsigned int bench_runs = 3;
static size_t bench_size = 32;
/* Jitter RNG collectors of the server, 0 for its default */
static unsigned int bench_jent_instances;
/* Print every request slower than this, 0 for none */
static uint64_t bench_outlier_ns;
static uint64_t bench_run_start;

static pthread_barrier_t bench_start;
static atomic_bool bench_stop;

struct bench_thread {
	pthread_t tid;
	unsigned int id;
	uint64_t *lat;
	size_t n, cap;
	unsigned long failures;
};

static uint64_t bench_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void *bench_thread_main(void *arg)
{
	struct bench_thread *t = arg;
	uint8_t buf[65536];

	/* One request first, so the connection is set up before the run */
	esdm_rpcc_get_random_bytes_full(buf, bench_size);
	pthread_barrier_wait(&bench_start);

	while (!atomic_load_explicit(&bench_stop, memory_order_relaxed)) {
		uint64_t start = bench_now_ns(), end;
		ssize_t ret = esdm_rpcc_get_random_bytes_full(buf, bench_size);

		end = bench_now_ns();
		if (ret != (ssize_t)bench_size)
			t->failures++;
		if (bench_outlier_ns && end - start > bench_outlier_ns)
			printf("  outlier %8.1f us at %9.3f ms in thread %u\n",
			       (double)(end - start) / 1000.0,
			       (double)(start - bench_run_start) / 1e6,
			       (unsigned int)(t->id));

		if (t->n == t->cap) {
			size_t cap = t->cap ? t->cap * 2 : 1 << 16;
			uint64_t *lat = realloc(t->lat, cap * sizeof(*lat));

			if (!lat)
				break;
			t->lat = lat;
			t->cap = cap;
		}
		t->lat[t->n++] = end - start;
	}

	return NULL;
}

/* Sum of the seed generations of all DRNG instances, or -1 */
static long long bench_seed_generations(void)
{
	long long sum = 0;
	char buf[4096];
	uint32_t node;

	for (node = 0;; node++) {
		struct json_object *obj, *gen;
		int ret = esdm_rpcc_drng_status_json(node, buf, sizeof(buf));

		if (ret == -ENODEV)
			break;
		if (ret)
			return -1;

		obj = json_tokener_parse(buf);
		if (json_object_object_get_ex(obj, "seed_generation", &gen))
			sum += json_object_get_int64(gen);
		json_object_put(obj);
	}

	return sum;
}

/* Are all DRNG instances fully seeded? */
static bool bench_all_seeded(void)
{
	char buf[4096];
	uint32_t node;

	for (node = 0;; node++) {
		struct json_object *obj, *seeded;
		bool ok;
		int ret = esdm_rpcc_drng_status_json(node, buf, sizeof(buf));

		if (ret == -ENODEV)
			return node > 0;
		if (ret)
			return false;

		obj = json_tokener_parse(buf);
		ok = json_object_object_get_ex(obj, "fully_seeded", &seeded) &&
		     json_object_get_boolean(seeded);
		json_object_put(obj);
		if (!ok)
			return false;
	}
}

static int bench_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

static double bench_us(const uint64_t *lat, size_t n, double q)
{
	return n ? (double)lat[(size_t)(q * (double)(n - 1))] / 1000.0 : 0;
}

static int bench_run(unsigned int nthreads, unsigned int run)
{
	struct timespec dur = { .tv_sec = bench_seconds };
	struct bench_thread *t = calloc(nthreads, sizeof(*t));
	long long gen_before, gen_after;
	unsigned long failures = 0;
	uint64_t *all, start, elapsed;
	size_t n = 0, i;
	int ret = 0;

	if (!t)
		return -ENOMEM;

	atomic_store(&bench_stop, false);
	pthread_barrier_init(&bench_start, NULL, nthreads + 1);
	bench_run_start = bench_now_ns();
	for (i = 0; i < nthreads; i++) {
		t[i].id = (unsigned int)i;
		pthread_create(&t[i].tid, NULL, bench_thread_main, &t[i]);
	}

	pthread_barrier_wait(&bench_start);
	gen_before = bench_seed_generations();
	start = bench_now_ns();
	nanosleep(&dur, NULL);
	atomic_store(&bench_stop, true);
	for (i = 0; i < nthreads; i++)
		pthread_join(t[i].tid, NULL);
	elapsed = bench_now_ns() - start;
	gen_after = bench_seed_generations();
	pthread_barrier_destroy(&bench_start);

	for (i = 0; i < nthreads; i++) {
		n += t[i].n;
		failures += t[i].failures;
	}

	all = malloc((n ? n : 1) * sizeof(*all));
	if (!all) {
		ret = -ENOMEM;
		goto out;
	}
	for (n = 0, i = 0; i < nthreads; i++) {
		memcpy(all + n, t[i].lat, t[i].n * sizeof(*all));
		n += t[i].n;
	}
	qsort(all, n, sizeof(*all), bench_cmp);

	printf("%2u threads run %u: %8.0f req/s %6lld reseeds %lu failed | "
	       "us p50 %7.1f p99 %7.1f p99.9 %7.1f p99.99 %8.1f max %8.1f\n",
	       nthreads, run, (double)n * 1e9 / (double)elapsed,
	       (gen_before < 0 || gen_after < 0) ? -1 :
						   gen_after - gen_before,
	       failures, bench_us(all, n, 0.5), bench_us(all, n, 0.99),
	       bench_us(all, n, 0.999), bench_us(all, n, 0.9999),
	       bench_us(all, n, 1.0));
	fflush(stdout);
	if (failures)
		ret = 1;
	free(all);

out:
	for (i = 0; i < nthreads; i++)
		free(t[i].lat);
	free(t);
	return ret;
}

static void *bench_monitor(void *unused)
{
	(void)unused;
	esdm_init_monitor(NULL);
	return NULL;
}

/* The child serving the RPC socket, as the esdm-server does */
static int bench_serve(void)
{
	pthread_t monitor;

	esdm_logger_set_verbosity(LOGGER_NONE);

	if (bench_jent_instances)
		esdm_config_es_jent_instances_set(bench_jent_instances);

	if (esdm_init() || esdm_test_shm_status_init() || thread_init(1) ||
	    pthread_create(&monitor, NULL, bench_monitor, NULL))
		return 1;

	return esdm_rpcs_serve_in_process(
		ESDM_RPC_UNPRIV_SOCKET,
		(ProtobufCService *)&unpriv_access_service, false) ?
		       1 :
		       0;
}

static pid_t bench_server_start(void)
{
	pid_t pid;
	int ret;

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return -77;
	}

	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid)
		_exit(bench_serve());

	if (!test_wait_for_type(ESDM_RPC_UNPRIV_SOCKET, S_IFSOCK,
				TEST_WAIT_TIMEOUT_MS)) {
		printf("The server did not start\n");
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
		return -ETIMEDOUT;
	}

	return pid;
}

static int bench_parse_list(const char *arg, unsigned int *list,
			    unsigned int *n)
{
	char *copy = strdup(arg), *tok, *save = NULL;

	if (!copy)
		return -ENOMEM;

	*n = 0;
	for (tok = strtok_r(copy, ",", &save); tok && *n < BENCH_MAX_LIST;
	     tok = strtok_r(NULL, ",", &save)) {
		unsigned long v = strtoul(tok, NULL, 10);

		if (!v || v > 1024) {
			free(copy);
			return -EINVAL;
		}
		list[(*n)++] = (unsigned int)v;
	}
	free(copy);

	return *n ? 0 : -EINVAL;
}

int main(int argc, char *argv[])
{
	struct timespec pause = { .tv_nsec = 100000000L };
	bool external = false;
	pid_t server = 0;
	unsigned int i, r, waited;
	int c, ret = 0;

	while ((c = getopt(argc, argv, "xt:d:r:s:o:j:")) != -1) {
		switch (c) {
		case 'x':
			external = true;
			break;
		case 't':
			if (bench_parse_list(optarg, bench_threads,
					     &bench_nthreads))
				return 2;
			break;
		case 'd':
			bench_seconds = (unsigned int)strtoul(optarg, NULL, 10);
			break;
		case 'r':
			bench_runs = (unsigned int)strtoul(optarg, NULL, 10);
			break;
		case 'o':
			bench_outlier_ns = strtoull(optarg, NULL, 10) * 1000;
			break;
		case 'j':
			bench_jent_instances =
				(unsigned int)strtoul(optarg, NULL, 10);
			break;
		case 's':
			bench_size = strtoul(optarg, NULL, 10);
			if (!bench_size || bench_size > 65536)
				return 2;
			break;
		default:
			printf("Usage: %s [-x] [-t threads,...] [-d seconds] [-r runs] [-s bytes] [-o outlier us] [-j jent collectors]\n",
			       argv[0]);
			return 2;
		}
	}

	if (!external) {
		server = bench_server_start();
		if (server < 0)
			return server == -77 ? 77 : 1;
	}

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("Cannot initialize the RPC client\n");
		ret = 1;
		goto out;
	}

	/*
	 * What is measured before every node DRNG is fully seeded is a server
	 * seeding them, not one serving requests.
	 */
	for (waited = 0; !bench_all_seeded(); waited++) {
		if (waited > 3000) {
			printf("The DRNG instances did not become fully seeded\n");
			ret = 1;
			goto fini;
		}
		nanosleep(&pause, NULL);
	}

	printf("%zu byte requests, %u s per run\n", bench_size, bench_seconds);
	for (i = 0; i < bench_nthreads; i++) {
		for (r = 0; r < bench_runs; r++)
			ret |= bench_run(bench_threads[i], r);
	}

fini:
	esdm_rpcc_fini_unpriv_service();
out:
	if (server > 0) {
		kill(server, SIGTERM);
		waitpid(server, NULL, 0);
	}
	return ret;
}
