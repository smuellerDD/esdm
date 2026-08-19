/*
 * Test of the self tests: the pass the ESDM runs when it comes up, the same
 * pass on demand, and the same pass repeated by the periodic worker
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

#ifdef ESDM_TESTMODE

/* Wait for @cond for at most this many 100ms slices */
#define ESDM_SELFTEST_TEST_SLICES 200

static void esdm_selftest_test_sleep(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

#define WAIT_FOR(cond)                                                         \
	do {                                                                   \
		unsigned int __i;                                              \
                                                                               \
		for (__i = 0; __i < ESDM_SELFTEST_TEST_SLICES && !(cond);      \
		     __i++)                                                    \
			esdm_selftest_test_sleep();                            \
	} while (0)

/*
 * Ask esdm_get_seed() for seed material with a buffer of the size it asks for.
 */
static ssize_t esdm_selftest_test_get_seed(void)
{
	uint64_t probe[2] = { 0, 0 };
	uint64_t *buf;
	ssize_t ret;

	/*
	 * A buffer that is too small is answered with the required size in its
	 * first word - which is how the caller learns how much to provide.
	 */
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
	long long passes;
	ssize_t rc;
	int ret = 0;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ret = esdm_init();
	if (ret)
		return ret;

	/* A full pass runs when the ESDM comes up */
	if (!esdm_selftest_crypto_passed() ||
	    strcmp(esdm_selftest_crypto_state_name(), "passed")) {
		printf("self tests did not pass at start up: %s\n",
		       esdm_selftest_crypto_state_name());
		goto err;
	}

	/*
	 * Including the entropy sources - their state is established at start
	 * up and not only once the periodic worker got around to it.
	 */
	if (esdm_selftest_es_state() != esdm_selftest_passed ||
	    strcmp(esdm_selftest_es_state_name(), "passed")) {
		printf("entropy source self tests did not pass at start up: %s\n",
		       esdm_selftest_es_state_name());
		goto err;
	}

	if (!esdm_selftest_es_sources() || esdm_selftest_es_failures()) {
		printf("start up pass tested %u entropy sources, %u failed\n",
		       esdm_selftest_es_sources(), esdm_selftest_es_failures());
		goto err;
	}

	/* The pass at start up is counted like every other one */
	passes = esdm_selftest_passes();
	if (passes < 1) {
		printf("the pass at start up was not counted: %lld\n", passes);
		goto err;
	}

	/* Random bits are handed out while the self tests pass */
	if (esdm_get_random_bytes_full(buf, sizeof(buf)) != sizeof(buf)) {
		printf("cannot obtain random data\n");
		goto err;
	}

	/* The worker needs a thread pool to be taken from */
	if (thread_init(1)) {
		printf("cannot initialize threading support\n");
		goto err;
	}

	if (!esdm_selftest_periodic_start() ||
	    !esdm_selftest_periodic_running()) {
		printf("periodic self test worker is not on duty\n");
		goto err;
	}

	/*
	 * The pass is repeated on its interval - one second in a test mode
	 * build, so two more of them are seen without a long wait.
	 */
	WAIT_FOR(esdm_selftest_passes() >= passes + 2);
	if (esdm_selftest_passes() < passes + 2) {
		printf("self tests are not repeated: %lld passes after %lld\n",
		       esdm_selftest_passes(), passes);
		goto err;
	}

	if (!esdm_selftest_crypto_passed() ||
	    esdm_selftest_es_state() != esdm_selftest_passed) {
		printf("periodic self test failed unexpectedly: %s / %s\n",
		       esdm_selftest_crypto_state_name(),
		       esdm_selftest_es_state_name());
		goto err;
	}

	/* The same pass on demand - what the privileged RPC endpoint offers */
	passes = esdm_selftest_passes();
	rc = esdm_selftest_run();
	if (rc) {
		printf("the on-demand self test failed: %zd\n", rc);
		goto err;
	}

	if (!esdm_selftest_crypto_passed() ||
	    esdm_selftest_es_state() != esdm_selftest_passed) {
		printf("the on-demand self test left an unexpected state: %s / %s\n",
		       esdm_selftest_crypto_state_name(),
		       esdm_selftest_es_state_name());
		goto err;
	}

	/* On demand or not, it is the same pass and is counted as one */
	if (esdm_selftest_passes() <= passes) {
		printf("the on-demand self test was not counted: %lld\n",
		       esdm_selftest_passes());
		goto err;
	}

	/* Now the same with a self test that failed */
	esdm_test_selftest_set_failed();

	if (esdm_selftest_crypto_passed() ||
	    strcmp(esdm_selftest_crypto_state_name(), "failed")) {
		printf("failed self test is not reported: %s\n",
		       esdm_selftest_crypto_state_name());
		goto err;
	}

	rc = esdm_get_random_bytes_full(buf, sizeof(buf));
	if (rc != -EOPNOTSUPP) {
		printf("random data is handed out after a failed self test: %zd\n",
		       rc);
		goto err;
	}

	rc = esdm_selftest_test_get_seed();
	if (rc != -EOPNOTSUPP) {
		printf("seed data is handed out after a failed self test: %zd\n",
		       rc);
		goto err;
	}

	/*
	 * A pass that runs after a failure passes on its own - the crypto is
	 * not broken, the state is - and does not clear it.
	 */
	rc = esdm_selftest_run();
	if (rc) {
		printf("the on-demand self test failed: %zd\n", rc);
		goto err;
	}

	if (esdm_selftest_crypto_passed()) {
		printf("an on-demand self test cleared a failed self test\n");
		goto err;
	}

	/* The worker leaves, as the state it reports cannot be recovered */
	WAIT_FOR(!esdm_selftest_periodic_running());
	if (esdm_selftest_periodic_running()) {
		printf("periodic self test worker stays on duty after a failure\n");
		goto err;
	}

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
	return 77;
#endif
}
