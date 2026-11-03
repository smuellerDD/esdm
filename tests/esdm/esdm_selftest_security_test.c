/*
 * The self tests at start up, on demand and by the periodic worker
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_selftest.h"
#include "threading_support.h"
#include "../test_plan.h"

#ifdef ESDM_TESTMODE

/* Wait for @cond for at most this many 100ms slices */
#define ESDM_SEC_WAIT_SLICES 200

static void esdm_sec_sleep(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

#define ESDM_SEC_WAIT_FOR(cond)                                                \
	do {                                                                   \
		unsigned int __i;                                              \
                                                                               \
		for (__i = 0; __i < ESDM_SEC_WAIT_SLICES && !(cond); __i++)    \
			esdm_sec_sleep();                                      \
	} while (0)

/* esdm_get_seed() with a buffer of the size it asks for */
static ssize_t esdm_sec_get_seed(void)
{
	uint64_t probe[2] = { 0, 0 };
	uint64_t *buf;
	ssize_t ret;

	/* A too small buffer is answered with the needed size in word 0 */
	if (esdm_get_seed(probe, sizeof(probe), ESDM_GET_SEED_NONBLOCK) !=
		    -EMSGSIZE ||
	    !probe[0])
		return -EFAULT;

	buf = calloc(1, (size_t)probe[0]);
	if (!buf)
		return -ENOMEM;

	ret = esdm_get_seed(buf, (size_t)probe[0], ESDM_GET_SEED_NONBLOCK);
	free(buf);

	return ret;
}

static int esdm_selftest_test(void)
{
	uint8_t buf[64];
	long long passes, now;
	ssize_t rc;
	int ret = 0;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	TEST_STEP("initialize the ESDM");
	TEST_REQUIRE("the ESDM initializes");
	ret = esdm_init();
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto out;

	TEST_REQUIRE("the crypto self tests passed at start up");
	if (!TEST_CHECK(esdm_selftest_crypto_passed(), "%d",
			esdm_selftest_crypto_passed()) ||
	    !TEST_CHECK(!strcmp(esdm_selftest_crypto_state_name(), "passed"),
			"%s", esdm_selftest_crypto_state_name()))
		goto err;

	/* Known at start up, not only once the periodic worker ran */
	TEST_REQUIRE("the entropy source self tests passed at start up");
	if (!TEST_CHECK(esdm_selftest_es_state() == esdm_selftest_passed, "%d",
			(int)esdm_selftest_es_state()) ||
	    !TEST_CHECK(!strcmp(esdm_selftest_es_state_name(), "passed"), "%s",
			esdm_selftest_es_state_name()))
		goto err;

	TEST_REQUIRE(
		"at least one entropy source was tested at start up, none failed");
	if (!TEST_CHECK(esdm_selftest_es_sources() > 0, "%u",
			esdm_selftest_es_sources()) ||
	    !TEST_CHECK(esdm_selftest_es_failures() == 0, "%u",
			esdm_selftest_es_failures()))
		goto err;

	TEST_STEP("read the number of self test passes");
	passes = esdm_selftest_passes();
	TEST_REQUIRE("the pass at start up is counted");
	if (!TEST_CHECK(passes >= 1, "%lld", passes))
		goto err;

	TEST_STEP("request %zu bytes from esdm_get_random_bytes_full",
		  sizeof(buf));
	rc = esdm_get_random_bytes_full(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc))
		goto err;

	/*
	 * What the privileged RPC endpoint offers - before the periodic worker
	 * starts, so that no other pass is counted with it.
	 */
	TEST_STEP("run the self tests on demand");
	rc = esdm_selftest_run();
	TEST_REQUIRE("the on-demand self test passes");
	if (!TEST_CHECK(rc == 0, "%zd", rc))
		goto err;

	TEST_REQUIRE("the crypto and entropy source self tests still pass");
	if (!TEST_CHECK(esdm_selftest_crypto_passed(), "%s",
			esdm_selftest_crypto_state_name()) ||
	    !TEST_CHECK(esdm_selftest_es_state() == esdm_selftest_passed, "%s",
			esdm_selftest_es_state_name()))
		goto err;

	TEST_STEP("read the number of self test passes");
	now = esdm_selftest_passes();
	TEST_REQUIRE("the on-demand self test is counted as one pass");
	if (!TEST_CHECK(now == passes + 1, "%lld, %lld before", now, passes))
		goto err;
	passes = now;

	/* The worker needs a thread pool */
	TEST_STEP("initialize threading support");
	TEST_REQUIRE("threading support initializes");
	ret = thread_init(1);
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto err;

	TEST_STEP("start the periodic self test worker");
	esdm_selftest_periodic_start();
	TEST_REQUIRE("the periodic self test worker is on duty");
	if (!TEST_CHECK(esdm_selftest_periodic_running(), "%d",
			esdm_selftest_periodic_running()))
		goto err;

	/* The interval is one second in a test mode build */
	TEST_RUNUNTIL(
		"wait 100 ms until two more self test passes ran, at most %u times",
		ESDM_SEC_WAIT_SLICES);
	ESDM_SEC_WAIT_FOR(esdm_selftest_passes() >= passes + 2);
	TEST_STEP("read the number of self test passes");
	now = esdm_selftest_passes();
	TEST_REQUIRE("the self tests were repeated at least twice");
	if (!TEST_CHECK(now >= passes + 2, "%lld, %lld before", now, passes))
		goto err;

	TEST_REQUIRE("the crypto and entropy source self tests still pass");
	if (!TEST_CHECK(esdm_selftest_crypto_passed(), "%s",
			esdm_selftest_crypto_state_name()) ||
	    !TEST_CHECK(esdm_selftest_es_state() == esdm_selftest_passed, "%s",
			esdm_selftest_es_state_name()))
		goto err;

	TEST_STEP("mark the crypto self test as failed");
	esdm_test_selftest_set_failed();

	TEST_REQUIRE("the crypto self test is reported as failed");
	if (!TEST_CHECK(!esdm_selftest_crypto_passed(), "%d",
			!esdm_selftest_crypto_passed()) ||
	    !TEST_CHECK(!strcmp(esdm_selftest_crypto_state_name(), "failed"),
			"%s", esdm_selftest_crypto_state_name()))
		goto err;

	TEST_STEP("request %zu bytes from esdm_get_random_bytes_full",
		  sizeof(buf));
	rc = esdm_get_random_bytes_full(buf, sizeof(buf));
	TEST_REQUIRE("the request is refused with -EOPNOTSUPP");
	if (!TEST_CHECK(rc == -EOPNOTSUPP, "%zd", rc))
		goto err;

	TEST_STEP("request seed data from esdm_get_seed");
	rc = esdm_sec_get_seed();
	TEST_REQUIRE("the request is refused with -EOPNOTSUPP");
	if (!TEST_CHECK(rc == -EOPNOTSUPP, "%zd", rc))
		goto err;

	/* A later pass succeeds - the crypto works - but keeps the failure */
	TEST_STEP("run the self tests on demand");
	rc = esdm_selftest_run();
	TEST_REQUIRE("the on-demand self test passes");
	if (!TEST_CHECK(rc == 0, "%zd", rc))
		goto err;

	TEST_REQUIRE("the crypto self test is still reported as failed");
	if (!TEST_CHECK(!esdm_selftest_crypto_passed(), "%s",
			esdm_selftest_crypto_state_name()))
		goto err;

	/* A failure is not recovered from, so the worker leaves */
	TEST_RUNUNTIL(
		"wait 100 ms until the periodic self test worker left, at most %u times",
		ESDM_SEC_WAIT_SLICES);
	ESDM_SEC_WAIT_FOR(!esdm_selftest_periodic_running());
	TEST_REQUIRE("the periodic self test worker left");
	if (!TEST_CHECK(!esdm_selftest_periodic_running(), "%d",
			!esdm_selftest_periodic_running()))
		goto err;

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif /* ESDM_TESTMODE */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_selftest_test();
#else
	printf("test mode not compiled in\n");
	return 77;
#endif
}
