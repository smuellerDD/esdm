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
 * The external entropy source of the esdm-server, configured with --es_ext:
 * connected to, shown with the name and the status of its provider, and
 * connected to again - by the daemon, its privileges dropped by then - once
 * the provider was restarted.
 *
 * Skipped (77) unless run as root, as the esdm-server refuses to start
 * otherwise. The daemon claims the fixed socket, semaphore and IPC names, so
 * the test puts itself in namespaces of its own.
 *
 * Usage: es_ext_server_test <esdm-server> <test provider>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../test_env.h"
#include "../test_namespace.h"
#include "common_test.h"
#include "es_ext_test_plugin.h"
#include "es_ext_test_util.h"
#include "esdm_rpc_client.h"

/* How long the daemon is given to come up */
#define TEST_START_SEC 30
/* Longer than the retry and the status interval of the source */
#define TEST_INTERVAL_MS 6000

static char test_dir[] = "/tmp/esdm-es-ext-server-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];
static char *test_envp[TEST_ENV_MAX_VARS + 1];

/* The section of the text status about the source, NULL for none */
static const char *test_es(void)
{
	static char status[65536];
	unsigned int i;

	for (i = 0; i < TEST_START_SEC * 10; i++) {
		memset(status, 0, sizeof(status));
		if (!esdm_rpcc_status(status, sizeof(status)))
			return strstr(status, "\n Name: ExternalSocket\n");
		es_ext_test_sleep_ms(100);
	}
	return NULL;
}

static void test_server(const char *server, const char *serve)
{
	char *const argv[] = { (char *)server, "-f", "--es_ext", test_socket,
			       NULL };
	static uint8_t seed[8192];
	pid_t provider, pid;
	const char *es;

	provider = es_ext_test_serve(serve, test_socket, NULL, NULL);
	CHECK(provider > 0, "the provider did not come up");
	pid = es_ext_test_spawn(argv, test_envp);
	CHECK(pid > 0, "cannot start %s", server);
	if (pid <= 0)
		goto out;

	es = test_es();
	CHECK(es && strstr(es, " Status: connected (uid 0)\n") &&
		      strstr(es, " Declared name: es-ext-test\n") &&
		      strstr(es, "\n Provider status: {\"server\":{") &&
		      strstr(es, "\"plugin\":" ES_EXT_TEST_STATUS "}\n"),
	      "the provider is not connected and shown (%.800s)", es ? es : "");

	es_ext_test_terminate(provider);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the provider gone");
	es_ext_test_sleep_ms(TEST_INTERVAL_MS);
	es = test_es();
	CHECK(es && strstr(es, " Status: not connected\n"),
	      "a provider gone is still connected (%.400s)", es ? es : "");

	provider = es_ext_test_serve(serve, test_socket, NULL, NULL);
	CHECK(provider > 0, "the provider did not come up again");
	es_ext_test_sleep_ms(TEST_INTERVAL_MS);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the provider back");
	es = test_es();
	CHECK(es && strstr(es, " Status: connected (uid 0)\n"),
	      "the provider back was not connected to again (%.400s)",
	      es ? es : "");

	es_ext_test_terminate(pid);
out:
	es_ext_test_terminate(provider);
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 3) {
		printf("usage: %s <esdm-server> <test provider>\n", argv[0]);
		return 1;
	}
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	/* Traversable for the daemon once it dropped its privileges */
	if (!mkdtemp(test_dir) || chmod(test_dir, 0755)) {
		printf("Cannot create the directory: %s\n", strerror(errno));
		return 1;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);
	test_env_daemon_envp(test_envp, TEST_ENV_MAX_VARS + 1);
	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("Cannot set up the RPC client\n");
		return 1;
	}

	test_server(argv[1], argv[2]);

	esdm_rpcc_fini_unpriv_service();
	unlink(test_socket);
	rmdir(test_dir);
	return common_test_result("es_ext_server");
}
