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
#include <json-c/json.h>
#include <stdbool.h>
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

static bool test_str_is(struct json_object *obj, const char *key,
			const char *expected)
{
	struct json_object *val;

	return json_object_object_get_ex(obj, key, &val) &&
	       json_object_is_type(val, json_type_string) &&
	       !strcmp(json_object_get_string(val), expected);
}

/*
 * The entry of the source in the JSON status, NULL for none. The JSON rather
 * than the text, whose labels and nesting follow the member names.
 */
static struct json_object *test_es(void)
{
	static char status[65536];
	struct json_object *doc, *sources, *es = NULL;
	size_t i, n = 0;

	memset(status, 0, sizeof(status));
	if (esdm_rpcc_status_json(status, sizeof(status)))
		return NULL;

	doc = json_tokener_parse(status);
	if (json_object_object_get_ex(doc, "entropy_sources", &sources) &&
	    json_object_is_type(sources, json_type_array))
		n = json_object_array_length(sources);
	for (i = 0; i < n && !es; i++) {
		struct json_object *src = json_object_array_get_idx(sources, i);

		if (test_str_is(src, "instance", "ExternalSocket"))
			es = json_object_get(src);
	}
	json_object_put(doc);
	return es;
}

static bool test_connected(struct json_object *es)
{
	return test_str_is(es, "status", "connected (uid 0)");
}

/* Connected, with the name and the status the test provider declares */
static bool test_shown(struct json_object *es)
{
	struct json_object *provider, *server, *plugin;
	struct json_object *expected = json_tokener_parse(ES_EXT_TEST_STATUS);
	bool ret;

	ret = test_connected(es) && test_str_is(es, "name", "es-ext-test") &&
	      json_object_object_get_ex(es, "provider", &provider) &&
	      json_object_object_get_ex(provider, "server", &server) &&
	      json_object_is_type(server, json_type_object) &&
	      json_object_object_get_ex(provider, "plugin", &plugin) &&
	      json_object_equal(plugin, expected);
	json_object_put(expected);
	return ret;
}

static bool test_not_connected(struct json_object *es)
{
	return test_str_is(es, "status", "not connected");
}

/*
 * The entry of the source once @done accepts it, else the last one seen after
 * TEST_START_SEC: the daemon has to come up, and a busy source says only that.
 */
static struct json_object *test_es_until(bool (*done)(struct json_object *))
{
	struct json_object *es = NULL;
	unsigned int i;

	for (i = 0; i < TEST_START_SEC * 10; i++) {
		json_object_put(es);
		es = test_es();
		if (es && done(es))
			break;
		es_ext_test_sleep_ms(100);
	}
	return es;
}

static const char *test_es_print(struct json_object *es)
{
	return es ? json_object_to_json_string_ext(
			    es, JSON_C_TO_STRING_PLAIN |
					JSON_C_TO_STRING_NOSLASHESCAPE) :
		    "";
}

static void test_server(const char *server, const char *serve)
{
	char *const argv[] = { (char *)server, "-f", "--es_ext", test_socket,
			       NULL };
	static uint8_t seed[8192];
	struct json_object *es;
	pid_t provider, pid;

	provider = es_ext_test_serve(serve, test_socket, NULL, NULL);
	CHECK(provider > 0, "the provider did not come up");
	pid = es_ext_test_spawn(argv, test_envp);
	CHECK(pid > 0, "cannot start %s", server);
	if (pid <= 0)
		goto out;

	es = test_es_until(test_shown);
	CHECK(es && test_shown(es),
	      "the provider is not connected and shown (%.800s)",
	      test_es_print(es));
	json_object_put(es);

	es_ext_test_terminate(provider);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the provider gone");
	es_ext_test_sleep_ms(TEST_INTERVAL_MS);
	es = test_es_until(test_not_connected);
	CHECK(es && test_not_connected(es),
	      "a provider gone is still connected (%.400s)", test_es_print(es));
	json_object_put(es);

	provider = es_ext_test_serve(serve, test_socket, NULL, NULL);
	CHECK(provider > 0, "the provider did not come up again");
	es_ext_test_sleep_ms(TEST_INTERVAL_MS);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the provider back");
	es = test_es_until(test_connected);
	CHECK(es && test_connected(es),
	      "the provider back was not connected to again (%.400s)",
	      test_es_print(es));
	json_object_put(es);

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
