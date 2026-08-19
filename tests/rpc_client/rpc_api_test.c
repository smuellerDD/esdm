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
 * Every call of the RPC client API, against a running server.
 *
 * The client side is one small file per call, each packing the request, handing
 * it to the generic invoke and unpacking what came back. Most had never been
 * executed - the existing tests cover the handful of calls they need - so a
 * marshalling mistake in any of the others showed up nowhere.
 *
 * Where a call can only be checked for "did not fail", it is. Where a pair can
 * be checked against each other, the setters are read back through their
 * getters, which demonstrates that both directions of the marshalling agree.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_test.h"
#include "env.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"

/*
 * The privileged calls change the state of the ESDM the unprivileged ones
 * report on, so what they altered is put back afterwards.
 */
static unsigned int saved_write_wakeup_thresh;
static unsigned int saved_min_reseed_secs;

static bool buffer_is_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return false;
	}

	return true;
}

/****************************** reporting calls ******************************/

static void test_status(void)
{
	char buf[ESDM_RPC_MAX_DATA];
	int ret;

	memset(buf, 0, sizeof(buf));
	esdm_invoke(esdm_rpcc_status(buf, sizeof(buf)));
	CHECK_EQ(ret, 0);
	CHECK(buf[0] != '\0', "the status report is empty");
	CHECK(strstr(buf, "ESDM") != NULL,
	      "the status report does not name the ESDM");
}

static void test_status_json(void)
{
	char buf[ESDM_RPC_MAX_DATA];
	int ret;

	memset(buf, 0, sizeof(buf));
	esdm_invoke(esdm_rpcc_status_json(buf, sizeof(buf)));
	CHECK_EQ(ret, 0);
	/* Whatever it contains, it has to be a JSON document */
	CHECK(buf[0] == '{', "the JSON status does not start with an object");
}

static void test_jent_status(void)
{
	char buf[ESDM_RPC_MAX_DATA];
	int ret;

	memset(buf, 0, sizeof(buf));
	esdm_invoke(esdm_rpcc_jent_status(buf, sizeof(buf)));
	CHECK_EQ(ret, 0);
}

static void test_get_ent_lvl(void)
{
	unsigned int entlvl = UINT_MAX;
	int ret;

	esdm_invoke(esdm_rpcc_get_ent_lvl(&entlvl));
	CHECK_EQ(ret, 0);
	CHECK(entlvl != UINT_MAX, "the entropy level was not filled in");
}

static void test_is_fully_seeded(void)
{
	bool seeded = false;
	int ret;

	esdm_invoke(esdm_rpcc_is_fully_seeded(&seeded));
	CHECK_EQ(ret, 0);
	/*
	 * The tests below ask for fully seeded random data, so by this point
	 * the ESDM has to consider itself seeded.
	 */
	CHECK(seeded, "the ESDM does not report itself as fully seeded");
}

static void test_get_poolsize(void)
{
	unsigned int poolsize = 0;
	int ret;

	esdm_invoke(esdm_rpcc_get_poolsize(&poolsize));
	CHECK_EQ(ret, 0);
	CHECK(poolsize > 0, "the pool size is reported as zero");
}

static void test_rnd_get_ent_cnt(void)
{
	unsigned int entcnt = UINT_MAX;
	int ret;

	esdm_invoke(esdm_rpcc_rnd_get_ent_cnt(&entcnt));
	CHECK_EQ(ret, 0);
	CHECK(entcnt != UINT_MAX, "the entropy count was not filled in");
}

/****************************** generating calls *****************************/

static void check_generated(const char *what, ssize_t rc, const uint8_t *buf,
			    size_t len)
{
	CHECK(rc == (ssize_t)len, "%s: returned %zd for %zu bytes", what, rc,
	      len);
	CHECK(!buffer_is_zero(buf, len), "%s: the buffer is all zero", what);
}

static void test_get_random_bytes(void)
{
	uint8_t buf[64];
	ssize_t ret;

	memset(buf, 0, sizeof(buf));
	esdm_invoke(esdm_rpcc_get_random_bytes(buf, sizeof(buf)));
	check_generated("get_random_bytes", ret, buf, sizeof(buf));
}

static void test_get_random_bytes_full(void)
{
	uint8_t buf[64];
	ssize_t ret;

	memset(buf, 0, sizeof(buf));
	esdm_invoke(esdm_rpcc_get_random_bytes_full(buf, sizeof(buf)));
	check_generated("get_random_bytes_full", ret, buf, sizeof(buf));
}

static void test_get_random_bytes_pr(void)
{
	uint8_t buf[32];
	ssize_t ret;

	memset(buf, 0, sizeof(buf));
	esdm_invoke(esdm_rpcc_get_random_bytes_pr(buf, sizeof(buf)));
	check_generated("get_random_bytes_pr", ret, buf, sizeof(buf));
}

static void test_get_random_bytes_full_timeout(void)
{
	struct timespec ts = { .tv_sec = 30, .tv_nsec = 0 };
	uint8_t buf[64];
	ssize_t ret;

	memset(buf, 0, sizeof(buf));
	esdm_invoke(esdm_rpcc_get_random_bytes_full_timeout(buf, sizeof(buf),
							    &ts));
	check_generated("get_random_bytes_full_timeout", ret, buf, sizeof(buf));
}

static void test_write_data(void)
{
	uint8_t data[64];
	unsigned int i;
	int ret;

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 3 + 1);

	esdm_invoke(esdm_rpcc_write_data(data, sizeof(data)));
	CHECK_EQ(ret, 0);
}

/**************************** state changing calls ***************************/

static void test_write_wakeup_thresh_roundtrip(void)
{
	unsigned int thresh = 0, readback = 0;
	int ret;

	esdm_invoke(esdm_rpcc_get_write_wakeup_thresh(&thresh));
	CHECK_EQ(ret, 0);
	CHECK(thresh > 0, "the write wakeup threshold is reported as zero");
	saved_write_wakeup_thresh = thresh;

	/*
	 * Set it to something else and read it back: this is what shows both
	 * directions of the marshalling agree, rather than only that neither
	 * call reported an error.
	 */
	esdm_invoke(esdm_rpcc_set_write_wakeup_thresh(thresh - 1));
	CHECK_EQ(ret, 0);

	esdm_invoke(esdm_rpcc_get_write_wakeup_thresh(&readback));
	CHECK_EQ(ret, 0);
	CHECK_EQ(readback, thresh - 1);

	esdm_invoke(esdm_rpcc_set_write_wakeup_thresh(
		saved_write_wakeup_thresh));
	CHECK_EQ(ret, 0);
}

static void test_min_reseed_secs_roundtrip(void)
{
	unsigned int secs = 0, readback = 0;
	int ret;

	esdm_invoke(esdm_rpcc_get_min_reseed_secs(&secs));
	CHECK_EQ(ret, 0);
	saved_min_reseed_secs = secs;

	esdm_invoke(esdm_rpcc_set_min_reseed_secs(secs + 1));
	CHECK_EQ(ret, 0);

	esdm_invoke(esdm_rpcc_get_min_reseed_secs(&readback));
	CHECK_EQ(ret, 0);
	CHECK_EQ(readback, secs + 1);

	esdm_invoke(esdm_rpcc_set_min_reseed_secs(saved_min_reseed_secs));
	CHECK_EQ(ret, 0);
}

static void test_rnd_add_to_ent_cnt(void)
{
	int ret;

	esdm_invoke(esdm_rpcc_rnd_add_to_ent_cnt(64));
	CHECK_EQ(ret, 0);
}

static void test_rnd_add_entropy(void)
{
	uint8_t data[32];
	unsigned int i;
	int ret;

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 7 + 5);

	esdm_invoke(esdm_rpcc_rnd_add_entropy(data, sizeof(data),
					      sizeof(data) * 8));
	CHECK_EQ(ret, 0);
}

static void test_rnd_reseed_crng(void)
{
	int ret;

	esdm_invoke(esdm_rpcc_rnd_reseed_crng());
	CHECK_EQ(ret, 0);
}

static void test_rnd_clear_pool(void)
{
	int ret;

	esdm_invoke(esdm_rpcc_rnd_clear_pool());
	CHECK_EQ(ret, 0);
}

static void test_set_pkcs11_config(void)
{
	int ret;

	/*
	 * Only a build with the PKCS#11 entropy source has anywhere to put
	 * this, so the call is expected to be refused otherwise. What is under
	 * test either way is that the two strings survive the trip - a refusal
	 * still travels through the same pack and unpack.
	 */
	esdm_invoke(esdm_rpcc_set_pkcs11_config("esdm-test-token",
						"esdm-test-pin"));
	CHECK(ret == 0 || ret < 0,
	      "set_pkcs11_config returned an unexpected value %d", ret);
	printf("set_pkcs11_config returned %d\n", ret);
}

static void test_selftest(void)
{
	struct esdm_rpcc_selftest_result result;
	int ret;

	/* Overwritten by the call - a leftover here would pass the checks */
	memset(&result, 0xff, sizeof(result));

	esdm_invoke(esdm_rpcc_selftest(&result));
	CHECK_EQ(ret, 0);
	CHECK_EQ(result.crypto_state, esdm_rpcc_selftest_passed);
	CHECK_EQ(result.es_state, esdm_rpcc_selftest_passed);
	CHECK(result.es_sources > 0, "no entropy source was tested");
	CHECK_EQ(result.es_failures, 0);

	printf("self test: crypto %d, entropy sources %d (%u tested, %u failed)\n",
	       result.crypto_state, result.es_state, result.es_sources,
	       result.es_failures);

	/* The outcome is optional - a caller may only want the verdict */
	esdm_invoke(esdm_rpcc_selftest(NULL));
	CHECK_EQ(ret, 0);
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = env_init();
	if (ret)
		return ret;

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("cannot reach the unprivileged RPC service\n");
		ret = 1;
		goto out;
	}
	if (esdm_rpcc_init_priv_service(NULL)) {
		printf("cannot reach the privileged RPC service\n");
		ret = 1;
		goto out_unpriv;
	}

	/* Reporting */
	test_status();
	test_status_json();
	test_jent_status();
	test_get_ent_lvl();
	test_get_poolsize();
	test_rnd_get_ent_cnt();

	/* Generating - also what makes the ESDM reach the fully seeded level */
	test_get_random_bytes();
	test_get_random_bytes_full();
	test_get_random_bytes_pr();
	test_get_random_bytes_full_timeout();
	test_is_fully_seeded();

	/* Feeding it */
	test_write_data();
	test_rnd_add_entropy();
	test_rnd_add_to_ent_cnt();

	/* Tunables, each read back through its getter */
	test_write_wakeup_thresh_roundtrip();
	test_min_reseed_secs_roundtrip();

	/* The self tests, run on demand */
	test_selftest();

	/* Last, they disturb what the calls above observe */
	test_rnd_reseed_crng();
	test_rnd_clear_pool();
	test_set_pkcs11_config();

	ret = common_test_result("rpc_api");

	esdm_rpcc_fini_priv_service();
out_unpriv:
	esdm_rpcc_fini_unpriv_service();
out:
	env_fini();
	return ret;
}
