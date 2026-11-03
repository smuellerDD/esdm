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
 * The external entropy source of a provider process, compiled in with a short
 * retry interval and timeouts. Its provider is the test source served by
 * libesdm_es_ext in a thread ("good"), or one of the test answering as
 * scripted ("evil").
 */

#include "config.h"

#define ESDM_EXT_RETRY_INTERVAL_SEC 1
#define ESDM_EXT_TIMEOUT_MS 1000
#define ESDM_EXT_STATUS_TIMEOUT_MS 250

/* The unit under test */
#include "esdm_es_extsock.c"

#include "common_test.h"
#include "../es_state_check.h"
#include "es_ext_test_plugin.h"
#include "es_ext_test_util.h"

#define ES (&esdm_es_extsock)
#define BITS ESDM_DRNG_SECURITY_STRENGTH_BITS
#define MS 1000000ULL

static struct esdm_es_ext_test_control *ctl = &esdm_es_ext_test_control;

static char test_dir[] = "/tmp/esdm-es-extsock-test-XXXXXX";
static char test_good[sizeof(test_dir) + 16];
static char test_evil[sizeof(test_dir) + 16];

static struct esdm_es_ext_server *good;
static pthread_t good_thread;

static void *good_run(void *arg)
{
	return (void *)(intptr_t)esdm_es_ext_server_run(arg);
}

static int good_start(void)
{
	int ret = esdm_es_ext_server_alloc(&es_ext_test_plugin, test_good, 0600,
					   &good);

	return ret ? ret : -pthread_create(&good_thread, NULL, good_run, good);
}

static void good_stop(void)
{
	esdm_es_ext_server_stop(good);
	pthread_join(good_thread, NULL);
	esdm_es_ext_server_free(good);
}

/* How the evil provider answers GET_ENTROPY and STATUS */
enum evil_mode {
	EVIL_GOOD,
	EVIL_UNCLEAN,
	EVIL_VERSION,
	EVIL_TOO_LONG,
	EVIL_TOO_MUCH_ENTROPY,
	EVIL_SILENT,
	EVIL_ERRNO,
};

static atomic_int evil_get, evil_status;
/* What INFO declares - the name set while no request is in progress */
static atomic_uint evil_rate = ESDM_ES_EXT_PROTO_RATE_NONE;
static char evil_name[ESDM_ES_EXT_NAME_MAX + 2] = "evil";
static atomic_uint evil_conns;
static atomic_bool evil_stop;
static int evil_fd = -1;
static pthread_t evil_thread;

/* The answer to a request into @rsp: its size, 0 for none */
static size_t evil_answer(uint16_t type, uint32_t length, uint8_t *rsp)
{
	uint8_t data[ESDM_ES_EXT_PROTO_MAX_RSP_DATA + 1];
	EsExtResponse msg = ES_EXT_RESPONSE__INIT;
	int mode = type == ESDM_ES_EXT_PROTO_GET_ENTROPY ? evil_get :
		   type == ESDM_ES_EXT_PROTO_STATUS	 ? evil_status :
							   EVIL_GOOD;

	memset(data, 0xee, sizeof(data));
	msg.version = ESDM_ES_EXT_PROTO_VERSION;
	msg.type = (EsExtType)type;
	if (type == ESDM_ES_EXT_PROTO_GET_ENTROPY)
		msg.entropy_bits = 8;
	if (type == ESDM_ES_EXT_PROTO_INFO) {
		msg.rate = evil_rate;
		msg.name.data = (uint8_t *)evil_name;
		msg.name.len = strlen(evil_name);
		length = 0;
	} else if (type == ESDM_ES_EXT_PROTO_SELFTEST) {
		length = 0;
	} else if (type == ESDM_ES_EXT_PROTO_STATUS && mode <= EVIL_UNCLEAN) {
		/* json-c takes the bidi override, the ESDM does not */
		length = (uint32_t)sprintf((char *)data, "{\"evil\":%s}",
					   mode ? "\"\\u202e\"" : "1");
	}

	if (mode == EVIL_SILENT)
		return 0;
	if (mode == EVIL_TOO_LONG)
		length++;
	if (mode == EVIL_TOO_MUCH_ENTROPY)
		msg.entropy_bits = length * 8 + 1;
	if (mode == EVIL_VERSION)
		msg.version++;
	if (mode == EVIL_ERRNO) {
		msg.status = -EOPNOTSUPP;
		msg.entropy_bits = length = 0;
	}
	msg.data.data = data;
	msg.data.len = length;
	return es_ext_response__pack(&msg, rsp);
}

/* One connection at a time, the next one waiting in the backlog */
static void *evil_run(void *arg)
{
	(void)arg;
	while (!evil_stop) {
		struct pollfd pfd = { .fd = evil_fd, .events = POLLIN };
		int fd;

		if (poll(&pfd, 1, 50) <= 0 ||
		    (fd = accept4(evil_fd, NULL, NULL, SOCK_CLOEXEC)) < 0)
			continue;
		evil_conns++;
		pfd.fd = fd;
		while (!evil_stop) {
			uint8_t req[ESDM_ES_EXT_PROTO_REQ_MAX];
			uint8_t rsp[ESDM_ES_EXT_PROTO_MSG_MAX + 1];
			uint32_t length;
			uint16_t type;
			ssize_t n;

			if (poll(&pfd, 1, 50) <= 0)
				continue;
			n = recv(fd, req, sizeof(req), 0);
			if (n <= 0 || esdm_es_ext_proto_req_unpack(
					      req, (size_t)n, &type, &length))
				break;
			n = (ssize_t)evil_answer(type, length, rsp);
			if (n && send(fd, rsp, (size_t)n, MSG_NOSIGNAL) != n)
				break;
		}
		close(fd);
	}
	return NULL;
}

static int evil_start(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };

	evil_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_evil);
	if (evil_fd < 0 ||
	    bind(evil_fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(evil_fd, 4))
		return -1;
	return pthread_create(&evil_thread, NULL, evil_run, NULL);
}

/* A block of @bits: the bits credited, its first byte into *@first */
static uint32_t test_get(uint32_t bits, uint8_t *first)
{
	struct entropy_es eb_es = { 0 };

	ES->get_ent(&eb_es, bits, true);
	if (first)
		*first = eb_es.e[0];
	return eb_es.e_bits;
}

/* The monitor, leaving the block cache empty for the tests but its own */
static void test_monitor(void)
{
	ES->monitor_es();
#if (ESDM_EXT_ENTROPY_BLOCKS != 0)
	ES->reset();
#endif
}

/* The provider of @path, connected to by the monitor */
static void test_connect(const char *path)
{
	CHECK_EQ(esdm_es_ext_set_path(path), 0);
	test_monitor();
}

/* Does the string member @key of the state contain @what? */
static bool test_state_has(const char *key, const char *what)
{
	struct json_object *state = es_state_get(ES);
	bool ret = es_state_str_has(state, key, what);

	if (!ret)
		printf("no %s \"%s\" in %s\n", key, what,
		       es_state_print(state));
	json_object_put(state);
	return ret;
}

/* The "provider" member of the state, the provider asked anew */
static struct json_object *test_provider(struct json_object **state)
{
	extsock.status_at = 0;
	*state = es_state_get(ES);
	return es_state_member(*state, "provider", json_type_object);
}

/* Sleep past the end of the retry interval the source recorded */
static void test_wait_retry(void)
{
	uint64_t now = esdm_monotonic_now_ns();

	if (extsock.retry_at > now)
		es_ext_test_sleep_ms((long)((extsock.retry_at - now) / MS + 1));
}

static bool test_rate_is(uint32_t rate, const char *source)
{
	struct json_object *state = es_state_get(ES);
	uint32_t configured =
		strcmp(source, "config") ? ESDM_ES_EXT_ENTROPY_RATE_AUTO : rate;
	bool ret = es_state_int(state, "assessed_rate", -1) == rate &&
		   es_state_str_is(state, "assessed_rate_source", source) &&
		   esdm_config_es_ext_entropy_rate() == configured;

	if (!ret)
		printf("not rate %u of the %s: %s\n", rate, source,
		       es_state_print(state));
	json_object_put(state);
	return ret;
}

static void test_arguments(void)
{
	char too_long[sizeof(((struct sockaddr_un *)0)->sun_path) + 1];

	memset(too_long, 'x', sizeof(too_long) - 1);
	too_long[sizeof(too_long) - 1] = '\0';
	CHECK_EQ(esdm_es_ext_set_path(NULL), -EINVAL);
	CHECK_EQ(esdm_es_ext_set_path(too_long), -EINVAL);
	CHECK_EQ(esdm_es_ext_set_peer_uid(-2), -EINVAL);
	/* (uid_t)-1 is no uid */
	CHECK_EQ(esdm_es_ext_set_peer_uid((int64_t)UINT32_MAX), -EINVAL);
	CHECK_EQ(esdm_es_ext_set_peer_uid((int64_t)UINT32_MAX - 1), 0);
	CHECK_EQ(esdm_es_ext_set_peer_uid(-1), 0);
}

static void test_unconfigured(void)
{
	CHECK_EQ(ES->init(), 0);
	CHECK(!ES->active(), "the source is active without a provider");
	CHECK_EQ(ES->max_entropy(), 0);
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK_EQ(ES->selftest(), 0);
	CHECK(test_state_has("provider_socket", "(unset)"),
	      "the state names a socket");

	/* "" restores the default of the build, none */
	CHECK_EQ(esdm_es_ext_set_path("/nonexistent/es.socket"), 0);
	CHECK(test_state_has("provider_socket", "/nonexistent/es.socket"),
	      "the path is not taken");
	CHECK_EQ(esdm_es_ext_set_path(""), 0);
	CHECK(test_state_has("provider_socket", "(unset)"),
	      "the default is not restored");
	ES->fini();
}

static void test_credit(void)
{
	unsigned int calls = ctl->selftest_calls;
	uint8_t first;

	CHECK_EQ(esdm_es_ext_set_path(test_good), 0);
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the source is not active with a provider");
	/* Tested on connecting, before it is credited */
	CHECK_EQ(ctl->selftest_calls, calls + 1);
	CHECK_EQ(ES->max_entropy(), esdm_security_strength());
	CHECK_EQ(test_get(BITS, &first), BITS);
	CHECK_EQ(first, ctl->get_calls & 0xff);
	CHECK_EQ(test_get(ESDM_DRNG_INIT_SEED_SIZE_BITS, NULL),
		 ESDM_DRNG_INIT_SEED_SIZE_BITS);
	CHECK_EQ(ctl->last_buflen, ESDM_DRNG_INIT_SEED_SIZE_BYTES);

	/* The rate caps the claim, a smaller claim stands */
	esdm_config_es_ext_entropy_rate_set(64);
	CHECK_EQ(test_get(BITS, NULL), 64);
	esdm_config_es_ext_entropy_rate_set(256);
	ctl->claim_bits = 10;
	CHECK_EQ(test_get(BITS, NULL), 10);
	/* A claim beyond the data is refused by the provider already */
	ctl->claim_bits = BITS + 1;
	CHECK_EQ(test_get(BITS, &first), 0);
	CHECK_EQ(first, 0);
	ctl->claim_bits = UINT32_MAX;

	/*
	 * Failing: nothing until it delivers again, which the monitor probes -
	 * a seeding does not ask it
	 */
	ctl->get_ret = -EIO;
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK(test_state_has("status", ", failing"), "not failing");
	ctl->get_ret = 0;
	calls = ctl->get_calls;
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK_EQ(ctl->get_calls, calls);
	CHECK_EQ(ES->curr_entropy(BITS), 0);
	test_monitor();
	CHECK_EQ(ES->curr_entropy(BITS), BITS);
	calls = ctl->get_calls;
	test_monitor();
	CHECK_EQ(ctl->get_calls, calls);

	/* A failed self test: not asked until one passes */
	ctl->selftest_ret = -ENODEV;
	CHECK_EQ(ES->selftest(), -EFAULT);
	CHECK(test_state_has("status", "failing its self test"),
	      "not failing its self test");
	calls = ctl->get_calls;
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK_EQ(ctl->get_calls, calls);
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(test_get(BITS, NULL), BITS);
}

static void test_peer_uid(void)
{
	/* As root, the provider is root's and accepted anyway */
	if (!getuid())
		return;

	CHECK_EQ(esdm_es_ext_set_peer_uid(-1), 0);
	test_connect(test_good);
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK(test_state_has("status", "not connected"),
	      "a provider of another user was connected to");
	CHECK_EQ(esdm_es_ext_set_peer_uid(getuid()), 0);
	test_wait_retry();
	test_monitor();
	CHECK_EQ(test_get(BITS, NULL), BITS);
}

/*
 * A provider restarted is another process: tested on the new connection
 * before it is credited - made by the next monitor pass when the connection
 * was idle, as the one closed to make room for another client is
 */
static void test_restart(void)
{
	unsigned int calls = ctl->selftest_calls;

	good_stop();
	ctl->selftest_ret = -ENODEV;
	CHECK_EQ(good_start(), 0);
	/* A seeding finds the connection closed, and makes no other */
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK_EQ(ctl->selftest_calls, calls);
	test_monitor();
	CHECK_EQ(ctl->selftest_calls, calls + 1);
	CHECK(test_state_has("status", "failing its self test"),
	      "a restarted provider was not tested");
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(test_get(BITS, NULL), BITS);

	/* Passing it, credited once connected - and not tested again */
	good_stop();
	CHECK_EQ(good_start(), 0);
	test_monitor();
	CHECK_EQ(test_get(BITS, NULL), BITS);
	CHECK_EQ(test_get(BITS, NULL), BITS);
	CHECK_EQ(ctl->selftest_calls, calls + 3);
}

/* A provider away is connected to again after the retry interval */
static void test_reconnect(void)
{
	good_stop();
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK(ES->active(), "a provider away switched the source off");
	/* Not connected is no failure: it is tested once connected to */
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(good_start(), 0);
	test_wait_retry();
	test_monitor();
	CHECK_EQ(test_get(BITS, NULL), BITS);

	/* Tested on connecting */
	good_stop();
	CHECK_EQ(test_get(BITS, NULL), 0);
	ctl->selftest_ret = -ENODEV;
	CHECK_EQ(good_start(), 0);
	test_wait_retry();
	test_monitor();
	CHECK(test_state_has("status", "failing its self test"),
	      "the monitor did not connect and test the provider");
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(ES->curr_entropy(BITS), BITS);
}

/*
 * Breaking the protocol drops the connection, handing on nothing, and it is
 * made again after the retry interval, not before
 */
static void test_breaches(void)
{
	static const int modes[] = { EVIL_VERSION, EVIL_TOO_LONG,
				     EVIL_TOO_MUCH_ENTROPY, EVIL_SILENT };
	unsigned int i;

	test_connect(test_evil);
	CHECK_EQ(test_get(BITS, NULL), 8);
	for (i = 0; i < ARRAY_SIZE(modes); i++) {
		unsigned int conns = evil_conns;
		uint64_t start = esdm_monotonic_now_ns(), dropped;
		uint8_t first;

		evil_get = modes[i];
		CHECK_EQ(test_get(BITS, &first), 0);
		dropped = esdm_monotonic_now_ns();
		evil_get = EVIL_GOOD;
		CHECK(!first && dropped - start < 2 * ESDM_EXT_TIMEOUT_MS * MS,
		      "mode %d: data handed on, or waited for too long",
		      modes[i]);
		CHECK(test_state_has("status", "not connected"),
		      "mode %d: still connected", modes[i]);

		do {
			es_ext_test_sleep_ms(10);
			test_monitor();
		} while (!test_get(BITS, NULL) &&
			 esdm_monotonic_now_ns() - dropped < 3 * EXTSOCK_NSEC);
		CHECK(esdm_monotonic_now_ns() - dropped >=
			      ESDM_EXT_RETRY_INTERVAL_SEC * EXTSOCK_NSEC -
				      20 * MS,
		      "mode %d: connected again too early", modes[i]);
		CHECK_EQ(evil_conns, conns + 1);
	}
}

/*
 * Shown under the name declared, the instance kept; one that is invalid, or
 * of another entropy source, is not taken, one too long breaks the protocol
 */
static void test_names(void)
{
	static const char *const bad[] = {
		"tab\there",
		"\xff\xfe",
		"esc\x1b[31m",
		"c1\xc2\x9b",
		"rlo\xe2\x80\xae",
		"",
		NULL /* of another source */,
	};
	struct json_object *state;
	unsigned int i;
	char txt[4096];

	test_connect(test_good);
	CHECK_EQ(test_get(BITS, NULL), BITS);
	state = es_state_get(ES);
	CHECK(es_state_str_is(state, "name", ES_EXT_TEST_NAME) &&
		      es_state_str_is(state, "instance", EXTSOCK_NAME),
	      "not shown under the name declared: %s", es_state_print(state));
	json_object_put(state);
	ES->state(txt, sizeof(txt));
	CHECK(strstr(txt, " Declared name: " ES_EXT_TEST_NAME "\n"),
	      "the text has no declared name: %s", txt);

	test_connect(test_evil);
	CHECK_EQ(test_get(BITS, NULL), 8);
	CHECK(test_state_has("name", "evil"), "the name is not taken");

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		snprintf(evil_name, sizeof(evil_name), "%s",
			 bad[i] ? bad[i] : esdm_es[esdm_ext_es_aux]->name);
		test_connect(test_evil);
		CHECK_EQ(test_get(BITS, NULL), 8);
		CHECK(test_state_has("name", EXTSOCK_NAME), "name %u is taken",
		      i);
	}

	snprintf(evil_name, sizeof(evil_name), "%0*d", ESDM_ES_EXT_NAME_MAX + 1,
		 0);
	test_connect(test_evil);
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK(test_state_has("status", "not connected"),
	      "a name too long is accepted");
	snprintf(evil_name, sizeof(evil_name), "evil");
}

/* The rate configured, else the one declared on this connection, else 0 */
static void test_rates(void)
{
	esdm_config_es_ext_entropy_rate_set(ESDM_ES_EXT_ENTROPY_RATE_AUTO);
	test_connect(test_good);
	CHECK_EQ(test_get(BITS, NULL), 0);
	CHECK(test_rate_is(0, "default"), "a provider without a rate has one");

	evil_rate = 4;
	test_connect(test_evil);
	CHECK_EQ(test_get(BITS, NULL), 4);
	CHECK(test_rate_is(4, "provider"), "the declared rate is not taken");
	evil_rate = 1000;
	CHECK_EQ(test_get(BITS, NULL), 4);
	test_connect(test_evil);
	CHECK_EQ(test_get(BITS, NULL), 8);
	CHECK(test_rate_is(256, "provider"), "a rate beyond 256 is not capped");

	esdm_config_es_ext_entropy_rate_set(2);
	CHECK_EQ(test_get(BITS, NULL), 2);
	CHECK(test_rate_is(2, "config"), "the rate configured is not taken");
	evil_rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	esdm_config_es_ext_entropy_rate_set(256);
}

/*
 * The status of the provider, asked once per interval; one that is no clean
 * JSON object or an error is left out, the connection kept, one breaking the
 * protocol or not answered in time drops it
 */
static void test_status(void)
{
	static const int kept[] = { EVIL_UNCLEAN, EVIL_ERRNO };
	static const int dropping[] = { EVIL_TOO_LONG, EVIL_SILENT };
	struct json_object *state, *provider;
	unsigned int calls, i;
	char txt[4096];

	test_connect(test_good);
	CHECK_EQ(test_get(BITS, NULL), BITS);
	calls = ctl->status_calls;
	provider = test_provider(&state);
	CHECK(es_state_member(provider, "server", json_type_object) &&
		      es_state_member(provider, "plugin", json_type_object),
	      "no status of the provider: %s", es_state_print(state));
	json_object_put(state);
	ES->state(txt, sizeof(txt));
	CHECK_EQ(ctl->status_calls, calls + 1);
	CHECK(strstr(txt, "\n Provider status: {\"server\":{") &&
		      strstr(txt, "\"plugin\":" ES_EXT_TEST_STATUS "}\n"),
	      "the text has no status of the provider: %s", txt);

	test_connect(test_evil);
	CHECK_EQ(test_get(BITS, NULL), 8);
	provider = test_provider(&state);
	CHECK(es_state_int(provider, "evil", 0) == 1,
	      "the status is not taken: %s", es_state_print(state));
	json_object_put(state);

	for (i = 0; i < ARRAY_SIZE(kept); i++) {
		evil_status = kept[i];
		provider = test_provider(&state);
		CHECK(!provider &&
			      es_state_str_has(state, "status", "connected ("),
		      "mode %d: %s", kept[i], es_state_print(state));
		json_object_put(state);
	}

	for (i = 0; i < ARRAY_SIZE(dropping); i++) {
		unsigned int conns = evil_conns;
		uint64_t start = esdm_monotonic_now_ns();

		evil_status = dropping[i];
		provider = test_provider(&state);
		CHECK(!provider &&
			      es_state_str_has(state, "status",
					       "not connected") &&
			      esdm_monotonic_now_ns() - start <
				      ESDM_EXT_TIMEOUT_MS * MS,
		      "mode %d: %s", dropping[i], es_state_print(state));
		json_object_put(state);
		evil_status = EVIL_GOOD;
		test_monitor();
		CHECK_EQ(test_get(BITS, NULL), 0);
		test_wait_retry();
		test_monitor();
		CHECK_EQ(test_get(BITS, NULL), 8);
		CHECK_EQ(evil_conns, conns + 1);
	}
}

#if (ESDM_EXT_ENTROPY_BLOCKS != 0)
/*
 * Filled by the monitor, for one request timeout per pass; a block served at
 * the rate now, blocks of a failed request passed; the cache passed while the
 * provider is not credited, and discarded by a failed self test and with a
 * new path
 */
static void test_cache(void)
{
	unsigned int calls;

	test_connect(test_good);
	CHECK_EQ(test_get(BITS, NULL), BITS);
	/* The first round after a reset fills nothing, see esdm_es_buf.c */
	ES->monitor_es();
	calls = ctl->get_calls;
	ES->monitor_es();
	CHECK_EQ(ctl->get_calls, calls + ESDM_EXT_ENTROPY_BLOCKS);
	calls = ctl->get_calls;
	CHECK_EQ(test_get(BITS, NULL), BITS);
	esdm_config_es_ext_entropy_rate_set(64);
	CHECK_EQ(test_get(BITS, NULL), 64);
	esdm_config_es_ext_entropy_rate_set(256);
	CHECK_EQ(ctl->get_calls, calls);

	ctl->selftest_ret = -ENODEV;
	CHECK_EQ(ES->selftest(), -EFAULT);
	CHECK_EQ(test_get(BITS, NULL), 0);
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(test_get(BITS, NULL), BITS);
	CHECK_EQ(ctl->get_calls, calls + 1);

	ES->monitor_es();
	ES->monitor_es();
	calls = ctl->get_calls;
	test_connect(test_good);
	CHECK_EQ(test_get(BITS, NULL), BITS);
	CHECK_EQ(ctl->get_calls, calls + 1);

	/* A slow provider: no request begun after the timeout */
	ES->monitor_es();
	ctl->get_delay_ms = ESDM_EXT_TIMEOUT_MS / 4;
	calls = ctl->get_calls;
	ES->monitor_es();
	ctl->get_delay_ms = 0;
	CHECK(ctl->get_calls - calls <= 5, "%u requests in one pass",
	      ctl->get_calls - calls);

	/* The first block fails: the rest is passed once the probe succeeds */
	ES->reset();
	ES->monitor_es();
	ctl->get_ret = -EIO;
	ES->monitor_es();
	ctl->get_ret = 0;
	CHECK_EQ(test_get(BITS, NULL), 0);
	ES->monitor_es();
	calls = ctl->get_calls;
	CHECK_EQ(test_get(BITS, NULL), BITS);
	CHECK_EQ(ctl->get_calls, calls + 1);
	ES->reset();
}
#else
static void test_cache(void)
{
}
#endif

int main(void)
{
	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory\n");
		return 1;
	}
	snprintf(test_good, sizeof(test_good), "%s/good.socket", test_dir);
	snprintf(test_evil, sizeof(test_evil), "%s/evil.socket", test_dir);

	test_arguments();
	test_unconfigured();

	CHECK_EQ(esdm_es_ext_set_peer_uid(getuid()), 0);
	esdm_config_es_ext_entropy_rate_set(256);
	if (good_start() || evil_start()) {
		printf("cannot start the providers\n");
		return 1;
	}

	test_credit();
	test_peer_uid();
	test_restart();
	test_reconnect();
	test_breaches();
	test_names();
	test_rates();
	test_status();
	test_cache();

	ES->fini();
	good_stop();
	evil_stop = true;
	pthread_join(evil_thread, NULL);
	close(evil_fd);
	unlink(test_evil);
	rmdir(test_dir);

	return common_test_result("es_extsock");
}
