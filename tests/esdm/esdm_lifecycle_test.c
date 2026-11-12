/*
 * Test of what the ESDM library does around its normal operation
 *
 *   - The non-blocking getters do not wait for the entropy pool: with its lock
 *     held by another thread they answer at once - with the bytes while the
 *     ESDM is operational, with -EAGAIN where only a seeding could help.
 *   - A node count raised after esdm_init() is not followed past the DRNG
 *     array allocated then.
 *   - esdm_init() after esdm_fini() is refused.
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

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "esdm_selftest.h"

#ifdef ESDM_TESTMODE

/* Seconds the ESDM is given to reach the fully seeded state */
#define TEST_SEED_WAIT_SECONDS 30

/* How long the helper holds the entropy pool at most */
#define TEST_POOL_HOLD_SECONDS 10

/* A getter that waited for the pool took the hold time, one that did not none */
#define TEST_NOBLOCK_MAX_MS 2000

/* Large enough for esdm_get_seed(), which answers -EMSGSIZE otherwise */
#define TEST_SEED_WORDS 1024

static atomic_bool pool_held;
static atomic_bool pool_release;

static long long test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void test_sleep_ms(long ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

/* Hold the entropy pool as a seeding in progress does */
static void *test_pool_holder(void *unused)
{
	long long until = test_now_ms() + TEST_POOL_HOLD_SECONDS * 1000;

	(void)unused;

	esdm_pool_lock();
	atomic_store(&pool_held, true);
	while (!atomic_load(&pool_release) && test_now_ms() < until)
		test_sleep_ms(10);
	esdm_pool_unlock();

	return NULL;
}

static int test_noblock_one(const char *name, ssize_t rc, ssize_t want,
			    long long start)
{
	long long elapsed = test_now_ms() - start;

	if (elapsed > TEST_NOBLOCK_MAX_MS) {
		printf("%s waited %lld ms for the entropy pool\n", name,
		       elapsed);
		return 1;
	}

	if (rc != want) {
		printf("%s returned %zd instead of %zd with the pool busy\n",
		       name, rc, want);
		return 1;
	}

	printf("%s returned %zd after %lld ms with the pool busy\n", name, rc,
	       elapsed);
	return 0;
}

static int test_noblock(void)
{
	uint64_t seed[TEST_SEED_WORDS];
	uint8_t buf[32];
	pthread_t holder;
	long long start;
	ssize_t rc;
	int ret = 0;

	atomic_store(&pool_held, false);
	atomic_store(&pool_release, false);
	if (pthread_create(&holder, NULL, test_pool_holder, NULL)) {
		printf("cannot start the pool holder\n");
		return 1;
	}
	while (!atomic_load(&pool_held))
		test_sleep_ms(1);

	/* A DRNG wanting a seeding sends the getters to the pool */
	esdm_pool_all_nodes_seeded(false);
	start = test_now_ms();
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	ret |= test_noblock_one("esdm_get_random_bytes_full_noblock", rc,
				sizeof(buf), start);

	/* So does a reseed of the initial DRNG falling due */
	esdm_drng_force_reseed();
	start = test_now_ms();
	rc = esdm_get_random_bytes(buf, sizeof(buf));
	ret |= test_noblock_one("esdm_get_random_bytes", rc, sizeof(buf),
				start);

	/* The PR DRNG has to seed from the pool for every output */
	start = test_now_ms();
	rc = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
	ret |= test_noblock_one("esdm_get_random_bytes_pr_noblock", rc, -EAGAIN,
				start);

	start = test_now_ms();
	rc = esdm_get_seed(seed, sizeof(seed), ESDM_GET_SEED_NONBLOCK);
	ret |= test_noblock_one("esdm_get_seed", rc, -EAGAIN, start);

	atomic_store(&pool_release, true);
	pthread_join(holder, NULL);

	return ret;
}

/* Indexing by a node count raised after the DRNG array was allocated */
static int test_nodes_raised(void)
{
	uint8_t buf[32];
	ssize_t rc;

	printf("%u DRNG node instance(s), raising the node count to the maximum\n",
	       esdm_drng_node_count_get());
	esdm_config_max_nodes_set(UINT32_MAX);

	esdm_drng_force_reseed();
	esdm_force_fully_seeded();
	esdm_selftest_run();

	rc = esdm_get_random_bytes_full(buf, sizeof(buf));
	if (rc != (ssize_t)sizeof(buf)) {
		printf("%zd bytes generated after raising the node count\n",
		       rc);
		return 1;
	}

	return 0;
}

static int esdm_lifecycle_test(void)
{
	uint8_t buf[32];
	unsigned int i;
	ssize_t rc;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* One DRNG instance allocated, so raising the count goes past it */
	esdm_config_max_nodes_set(1);
	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	ret = esdm_init();
	if (ret) {
		printf("esdm_init() failed: %d\n", ret);
		return 1;
	}

	esdm_get_random_bytes(buf, sizeof(buf));
	for (i = 0;
	     i < TEST_SEED_WAIT_SECONDS * 10 && !esdm_state_operational(); i++)
		test_sleep_ms(100);
	if (!esdm_state_operational()) {
		printf("the ESDM did not become operational, skipping\n");
		ret = 77;
		goto out;
	}

	ret = test_noblock();
	ret |= test_nodes_raised();

out:
	esdm_fini();

	if (ret)
		return ret;

	rc = esdm_init();
	if (rc != -ESHUTDOWN) {
		printf("esdm_init() after esdm_fini() returned %zd\n", rc);
		return 1;
	}

	printf("esdm_init() after esdm_fini() is refused\n");
	return 0;
}
#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_lifecycle_test();
#else
	return 77;
#endif
}
