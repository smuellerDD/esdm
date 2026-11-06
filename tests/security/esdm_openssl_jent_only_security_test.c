/*
 * OpenSSL with the Jitter RNG as the only credited entropy source, and what it
 * does when the ESDM loses that source
 *
 * The ESDM runs in this process and serves its unprivileged RPC interface from
 * a thread of it; OpenSSL reaches it through the ESDM RNG provider, the DRBGs
 * and the seed source of its library context. As in the Jitter RNG only test,
 * every other source is credited with zero bits, the loss is a Jitter RNG rate
 * of zero, and the budget of generate operations without a full reseed is
 * lowered so that the next reseed collecting nothing ends the output.
 *
 * The provider waits for the ESDM rather than failing, so OpenSSL handing out
 * nothing is a call that does not return. Each OpenSSL call therefore runs in
 * a child process, killed if it has not returned in time, and the bytes the
 * RPC server handed out meanwhile show whether the ESDM served it.
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
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_jent.h"
#include "esdm_logger.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "test_pertubation.h"
#include "threading_support.h"
#include "../esdm/es_rates.h"
#include "esdm_sec_jent_only.h"
#include "../test_namespace.h"
#include "../test_plan.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT)

/* Wait for the initial seeding at most this many 100ms slices */
#define ESDM_SEC_SEED_SLICES 900

/* Seconds an OpenSSL call is given to hand out what it was asked for */
#define ESDM_SEC_SERVED_SECS 60

/*
 * Seconds an OpenSSL call has to stay without an answer to count as held back.
 * The bytes the RPC server handed out, not this wait, tell whether the ESDM
 * served it.
 */
#define ESDM_SEC_HELD_SECS 3

/* Forced reseeds before the ESDM has to be out of operation */
#define ESDM_SEC_MAX_ROUNDS 2

/* The test plan states these values in its strings */
_Static_assert(ESDM_DRNG_SECURITY_STRENGTH_BITS == 256 &&
		       ESDM_SEC_SEED_SLICES == 900 &&
		       ESDM_SEC_SERVED_SECS == 60 && ESDM_SEC_HELD_SECS == 3 &&
		       ESDM_SEC_MAX_ROUNDS == 2,
	       "stated by the test plan");

/* Waits for the socket of the RPC server at most this many 10ms slices */
#define ESDM_SEC_SERVER_SLICES 500

enum esdm_sec_call { esdm_sec_rand, esdm_sec_ecdsa_key };

enum esdm_sec_result {
	esdm_sec_handed_out,
	esdm_sec_failed,
	esdm_sec_held_back,
	esdm_sec_error,
};

static const char *esdm_sec_result_name(enum esdm_sec_result res)
{
	switch (res) {
	case esdm_sec_handed_out:
		return "handed out";
	case esdm_sec_failed:
		return "failed";
	case esdm_sec_held_back:
		return "held back";
	case esdm_sec_error:
	default:
		return "error";
	}
}

/* The serve call only returns when it cannot start or is asked to exit */
static volatile bool esdm_sec_serve_returned;
static int esdm_sec_serve_ret;
static pthread_t esdm_sec_server;
static bool esdm_sec_server_started;

static void *esdm_sec_serve(void *unused)
{
	(void)unused;

	esdm_sec_serve_ret = esdm_rpcs_serve_in_process(
		ESDM_RPC_UNPRIV_SOCKET,
		(ProtobufCService *)&unpriv_access_service, false);
	esdm_sec_serve_returned = true;

	return NULL;
}

/* Serve the unprivileged RPC interface from a thread of this process */
static int esdm_sec_server_start(void)
{
	struct stat sb;
	unsigned int i;
	int ret;

	esdm_server_remove_stale_socket(ESDM_RPC_UNPRIV_SOCKET, SOCK_SEQPACKET);

	/* What esdm_rpc_server_init() sets up besides the ESDM */
	ret = esdm_test_shm_status_init();
	if (ret)
		return ret;
	ret = thread_init(1);
	if (ret)
		return ret;

	ret = -pthread_create(&esdm_sec_server, NULL, esdm_sec_serve, NULL);
	if (ret)
		return ret;
	esdm_sec_server_started = true;

	for (i = 0; i < ESDM_SEC_SERVER_SLICES; i++) {
		if (esdm_sec_serve_returned)
			return esdm_sec_serve_ret ? esdm_sec_serve_ret : -EIO;
		if (!stat(ESDM_RPC_UNPRIV_SOCKET, &sb) && S_ISSOCK(sb.st_mode))
			return 0;
		esdm_sec_sleep(0, 10 * 1000 * 1000);
	}

	return -ETIMEDOUT;
}

static void esdm_sec_server_stop(void)
{
	if (!esdm_sec_server_started)
		return;

	esdm_rpc_server_signal_exit_safe();
	pthread_join(esdm_sec_server, NULL);
	esdm_test_shm_status_fini();
}

/*
 * An OpenSSL library context taking all its random bits from the ESDM: the
 * ESDM RNG provider is its DRBG and its seed source, the default provider does
 * the rest, e.g. the key generation.
 */
static OSSL_LIB_CTX *esdm_sec_openssl(const char *provider_dir)
{
	OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

	if (!libctx)
		return NULL;

	if (OSSL_PROVIDER_set_default_search_path(libctx, provider_dir) != 1 ||
	    !OSSL_PROVIDER_load(libctx, "libesdm-rng-provider") ||
	    !OSSL_PROVIDER_load(libctx, "default") ||
	    RAND_set_DRBG_type(libctx, "CTR-DRBG", "provider=esdm", NULL,
			       NULL) != 1 ||
	    RAND_set_seed_source_type(libctx, "SEED-SRC", "provider=esdm") !=
		    1) {
		ERR_print_errors_fp(stdout);
		OSSL_LIB_CTX_free(libctx);
		return NULL;
	}

	return libctx;
}

/* The OpenSSL call itself: did it hand out what it was asked for? */
static bool esdm_sec_call_run(OSSL_LIB_CTX *libctx, enum esdm_sec_call call)
{
	uint8_t buf[32] = { 0 };
	EVP_PKEY *pkey;

	if (call == esdm_sec_rand)
		return RAND_bytes_ex(libctx, buf, sizeof(buf), 0) == 1 &&
		       !esdm_sec_buf_is_zero(buf, sizeof(buf));

	pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", "P-256");
	if (!pkey)
		return false;
	EVP_PKEY_free(pkey);

	return true;
}

/*
 * Run @call in a child process, given @secs seconds: a call still without an
 * answer by then is killed and held back.
 */
static enum esdm_sec_result esdm_sec_call(OSSL_LIB_CTX *libctx,
					  enum esdm_sec_call call, int secs)
{
	enum esdm_sec_result res = esdm_sec_error;
	struct pollfd pfd;
	int pipefd[2], rc;
	uint8_t handed_out;
	pid_t pid;

	if (pipe2(pipefd, O_CLOEXEC))
		return esdm_sec_error;

	/* What was printed so far is not printed again by the child */
	fflush(stdout);
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return esdm_sec_error;
	}

	if (!pid) {
		close(pipefd[0]);
		handed_out = esdm_sec_call_run(libctx, call);
		_exit(write(pipefd[1], &handed_out, 1) == 1 ? 0 : 1);
	}

	close(pipefd[1]);
	pfd.fd = pipefd[0];
	pfd.events = POLLIN;
	do {
		rc = poll(&pfd, 1, secs * 1000);
	} while (rc < 0 && errno == EINTR);

	if (!rc) {
		res = esdm_sec_held_back;
		kill(pid, SIGKILL);
	} else if (rc > 0 && read(pipefd[0], &handed_out, 1) == 1) {
		res = handed_out ? esdm_sec_handed_out : esdm_sec_failed;
	}
	close(pipefd[0]);

	while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
		;

	return res;
}

/*
 * Run @call and tell in @served whether the RPC server handed out bytes
 * meanwhile - the DRNG statistics cannot, as every refused request is a
 * reseed attempt.
 */
static enum esdm_sec_result esdm_sec_call_served(OSSL_LIB_CTX *libctx,
						 enum esdm_sec_call call,
						 int secs, bool *served)
{
	size_t written = esdm_test_shm_status_get_rpc_server_written();
	enum esdm_sec_result res = esdm_sec_call(libctx, call, secs);

	*served = esdm_test_shm_status_get_rpc_server_written() > written;

	return res;
}

static int esdm_openssl_jent_only_security_test(const char *provider_dir)
{
	struct esdm_sec_counters counters;
	enum esdm_sec_result res;
	OSSL_LIB_CTX *libctx = NULL;
	bool jent_active, served;
	unsigned int i;
	uint32_t budget;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* One DRNG instance, so that every request spends the same budget */
	TEST_STEP("use a single DRNG instance");
	esdm_config_max_nodes_set(1);

	TEST_STEP(
		"credit the Jitter RNG with 256 bits, every other entropy source with 0 bits");
	esdm_test_es_rates_zero();
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	TEST_STEP("initialize the ESDM");
	TEST_REQUIRE("the ESDM initializes");
	ret = esdm_init();
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto out;

	TEST_REQUIRE(
		"the Jitter RNG works on this machine (test skipped otherwise)");
	jent_active = esdm_es_jent.active && esdm_es_jent.active();
	if (!TEST_CHECK(jent_active, "%d", jent_active)) {
		printf("the Jitter RNG is not usable on this machine, skipping test\n");
		ret = 77;
		goto out;
	}

	if (esdm_sec_needs_second_source()) {
		TEST_RUNUNTIL(
			"credit the auxiliary pool with 256 bits plus the oversampling of the conditioning whenever it is empty and wait 100 ms until the ESDM is fully seeded, at most 900 times");
	} else {
		TEST_RUNUNTIL(
			"wait 100 ms until the ESDM is fully seeded, at most 900 times");
	}
	for (i = 0; i < ESDM_SEC_SEED_SLICES && !esdm_state_fully_seeded();
	     i++) {
		if (esdm_sec_needs_second_source())
			esdm_sec_feed_aux();
		esdm_sec_sleep(0, 100 * 1000 * 1000);
	}

	TEST_REQUIRE("the ESDM is fully seeded with the Jitter RNG credited");
	if (!TEST_CHECK(esdm_state_fully_seeded(), "%d",
			esdm_state_fully_seeded()))
		goto err;

	/* That would be a second source once the Jitter RNG is gone */
	TEST_REQUIRE("no entropy is left in the auxiliary pool");
	if (!TEST_CHECK(!esdm_avail_entropy_aux(), "%u",
			esdm_avail_entropy_aux()))
		goto err;

	TEST_STEP("serve the unprivileged RPC interface from a thread");
	ret = esdm_sec_server_start();
	TEST_REQUIRE("the RPC server listens on its socket");
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto err;

	TEST_STEP(
		"create an OpenSSL library context with the ESDM RNG provider as its DRBG and seed source, the default provider for the rest");
	libctx = esdm_sec_openssl(provider_dir);
	TEST_REQUIRE("the library context is created");
	if (!TEST_CHECK(libctx != NULL, "%s", libctx ? "created" : "none"))
		goto err;

	/* The Jitter RNG on its own carries OpenSSL */
	TEST_STEP(
		"request 32 bytes from RAND_bytes_ex in a child process, given 60 seconds");
	res = esdm_sec_call_served(libctx, esdm_sec_rand, ESDM_SEC_SERVED_SECS,
				   &served);
	TEST_REQUIRE("32 bytes, not all zero, are handed out by the ESDM");
	if (!TEST_CHECK(res == esdm_sec_handed_out, "%s",
			esdm_sec_result_name(res)) ||
	    !TEST_CHECK(served, "%d", served))
		goto err;

	TEST_STEP(
		"create an ECDSA P-256 key with EVP_PKEY_Q_keygen in a child process, given 60 seconds");
	res = esdm_sec_call_served(libctx, esdm_sec_ecdsa_key,
				   ESDM_SEC_SERVED_SECS, &served);
	TEST_REQUIRE("the key is created from random bits of the ESDM");
	if (!TEST_CHECK(res == esdm_sec_handed_out, "%s",
			esdm_sec_result_name(res)) ||
	    !TEST_CHECK(served, "%d", served))
		goto err;

	TEST_STEP("fail the Jitter RNG by crediting it with 0 bits");
	esdm_config_es_jent_entropy_rate_set(0);

	TEST_STEP(
		"read the generate operations since the last full reseed from the DRNG statistics");
	counters = esdm_sec_counters_get();
	TEST_REQUIRE("exactly one DRNG instance serves ordinary requests");
	if (!TEST_CHECK(counters.instances == 1, "%u", counters.instances))
		goto err;
	budget = counters.requests_since_fully_seeded + 1;
	TEST_STEP(
		"limit the generate operations without a full reseed to those spent plus one");
	esdm_config_drng_max_wo_reseed_set(budget);

	/* Each forced reseed collects nothing and adds up the spent requests */
	TEST_RUNUNTIL(
		"force a reseed of the DRNGs and request 32 bytes from RAND_bytes_ex in a child process, given 3 seconds, until the ESDM is not operational, at most 2 times");
	for (i = 0; i < ESDM_SEC_MAX_ROUNDS && esdm_state_operational(); i++) {
		esdm_drng_force_reseed();
		esdm_sec_call(libctx, esdm_sec_rand, ESDM_SEC_HELD_SECS);
	}

	TEST_REQUIRE("the ESDM is not operational");
	if (!TEST_CHECK(!esdm_state_operational(), "%d",
			!esdm_state_operational()))
		goto err;

	/* Now OpenSSL hands out nothing */
	TEST_STEP(
		"request 32 bytes from RAND_bytes_ex in a child process, given 3 seconds");
	res = esdm_sec_call_served(libctx, esdm_sec_rand, ESDM_SEC_HELD_SECS,
				   &served);
	TEST_REQUIRE(
		"RAND_bytes_ex hands out no bytes, the ESDM serves nothing");
	if (!TEST_CHECK(res == esdm_sec_held_back || res == esdm_sec_failed,
			"%s", esdm_sec_result_name(res)) ||
	    !TEST_CHECK(!served, "%d", !served))
		goto err;

	TEST_STEP(
		"create an ECDSA P-256 key with EVP_PKEY_Q_keygen in a child process, given 3 seconds");
	res = esdm_sec_call_served(libctx, esdm_sec_ecdsa_key,
				   ESDM_SEC_HELD_SECS, &served);
	TEST_REQUIRE("no key is created, the ESDM serves nothing");
	if (!TEST_CHECK(res == esdm_sec_held_back || res == esdm_sec_failed,
			"%s", esdm_sec_result_name(res)) ||
	    !TEST_CHECK(!served, "%d", !served))
		goto err;

	ret = 0;

out:
	OSSL_LIB_CTX_free(libctx);
	esdm_sec_server_stop();
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}

/*
 * The RPC sockets are fixed names in /tmp: a private /tmp keeps them from
 * meeting those of another test, in the mount namespace tests/test_ipc_ns.c
 * created. Never in the namespace of the machine, and without one the shared
 * /tmp has to do.
 */
static void esdm_sec_private_tmp(const char *provider_dir)
{
	struct test_ns_keep keep[TEST_NS_KEEP_MAX];
	char self[4096], ns[64], init_ns[64];
	unsigned int nkeep = 0, i;
	ssize_t len, ns_len, init_len;

	ns_len = readlink("/proc/self/ns/mnt", ns, sizeof(ns));
	init_len = readlink("/proc/1/ns/mnt", init_ns, sizeof(init_ns));
	if (ns_len > 0 && ns_len == init_len &&
	    !memcmp(ns, init_ns, (size_t)ns_len)) {
		printf("not in a mount namespace of its own, sharing /tmp\n");
		return;
	}

	/* The build tree may be below /tmp - see tests/test_namespace.h */
	len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (len > 0) {
		self[len] = '\0';
		test_ns_pin(keep, &nkeep, self);
	}
	test_ns_pin(keep, &nkeep, provider_dir);

	if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0) {
		printf("no private /tmp, sharing it: %s\n", strerror(errno));
		for (i = 0; i < nkeep; i++)
			close(keep[i].fd);
		return;
	}

	if (test_ns_restore(keep, nkeep))
		printf("cannot keep the build tree below /tmp visible\n");
}
#endif /* ESDM_TESTMODE && ESDM_ES_JENT */

int main(int argc, char *argv[])
{
#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT)
	if (argc != 2) {
		printf("usage: %s <directory of the ESDM OpenSSL providers>\n",
		       argv[0]);
		return 1;
	}

	esdm_sec_private_tmp(argv[1]);

	return esdm_openssl_jent_only_security_test(argv[1]);
#else
	(void)argc;
	(void)argv;

	printf("test mode or the Jitter RNG entropy source not compiled in\n");
	return 77;
#endif
}
