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
 * libesdm_es_ext: the provider server serving the test source, compiled in,
 * against a client speaking the protocol - correctly and not; the callbacks
 * it refuses to serve, and what of theirs it does not pass on; and the check
 * of the status of a source, esdm_es_ext_json_object().
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "es_ext_test_client.h"
#include "es_ext_test_plugin.h"
#include "es_ext_test_util.h"
#include "esdm_es_ext.h"

#define GET ESDM_ES_EXT_PROTO_GET_ENTROPY
#define SELF ESDM_ES_EXT_PROTO_SELFTEST
#define STAT ESDM_ES_EXT_PROTO_STATUS
#define INFO ESDM_ES_EXT_PROTO_INFO
#define MAX ESDM_ES_EXT_PROTO_STATUS_MAX
#define TEST_NAME "\"" ES_EXT_TEST_NAME "\""

/* The fields of the server in STATUS but the uptime, as JSON text */
static const char *test_fields(const char *name, unsigned int clients,
			       unsigned int requests, const char *selftest)
{
	static char buf[300];

	snprintf(buf, sizeof(buf),
		 "{\"version\":\"%s\",\"plugin_api\":%u,\"name\":%s,"
		 "\"entropy_rate\":null,\"clients\":%u,\"client_slots\":8,"
		 "\"requests\":%u,\"selftest\":\"%s\"}",
		 VERSION, ESDM_ES_EXT_PLUGIN_VERSION, name, clients, requests,
		 selftest);
	return buf;
}

static char test_dir[] = "/tmp/esdm-es-ext-lib-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];
static struct esdm_es_ext_server *server;
static pthread_t thread;
static struct esdm_es_ext_test_control *ctl = &esdm_es_ext_test_control;

/* The test source as it is before a test sets anything */
static void test_reset(void)
{
	memset(ctl, 0, sizeof(*ctl));
	ctl->claim_bits = UINT32_MAX;
	snprintf(ctl->name, sizeof(ctl->name), "%s", ES_EXT_TEST_NAME);
	ctl->entropy_rate = ES_EXT_TEST_RATE_NONE;
	es_ext_test_plugin.name = ctl->name;
}

static int test_alloc(const struct esdm_es_ext_plugin *plugin, mode_t mode)
{
	return esdm_es_ext_server_alloc(plugin, test_socket, mode, &server);
}

static void *test_thread(void *arg)
{
	return (void *)(intptr_t)esdm_es_ext_server_run(arg);
}

/* Serve in a thread, @c connected */
static void test_run(struct es_ext_test_client *c)
{
	CHECK_EQ(pthread_create(&thread, NULL, test_thread, server), 0);
	CHECK_EQ(es_ext_test_client_open(c, test_socket), 0);
}

static void test_stop(struct es_ext_test_client *c)
{
	void *ret = NULL;

	es_ext_test_client_close(c);
	esdm_es_ext_server_stop(server);
	pthread_join(thread, &ret);
	CHECK(!ret, "serving failed");
}

/* Serve @plugin, @c connected: false if it is not served */
static bool test_start(const struct esdm_es_ext_plugin *plugin,
		       struct es_ext_test_client *c)
{
	CHECK_EQ(test_alloc(plugin, 0600), 0);
	if (server)
		test_run(c);
	return server != NULL;
}

static void test_end(struct es_ext_test_client *c)
{
	test_stop(c);
	esdm_es_ext_server_free(server);
}

/*
 * Callbacks the server cannot serve, refused before any of them is called;
 * an init failing; the socket: a file that is no socket is kept, one left
 * behind replaced, the mode as asked whatever the umask, removed at the end.
 */
static void test_server_alloc(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct esdm_es_ext_plugin bad = es_ext_test_plugin;
	struct stat sb;
	int fd;

	test_reset();
	CHECK_EQ(test_alloc(NULL, 0600), -EPROTO);
	bad.version = 0;
	CHECK_EQ(test_alloc(&bad, 0600), -EPROTO);
	bad.version = ESDM_ES_EXT_PLUGIN_VERSION + 1;
	CHECK_EQ(test_alloc(&bad, 0600), -EPROTO);
	bad.version = ESDM_ES_EXT_PLUGIN_VERSION;
	bad.get_entropy = NULL;
	CHECK_EQ(test_alloc(&bad, 0600), -EPROTO);
	CHECK_EQ(ctl->init_calls, 0);

	ctl->init_ret = -ENODEV;
	CHECK_EQ(test_alloc(&es_ext_test_plugin, 0600), -ENODEV);
	ctl->init_ret = 1;
	CHECK_EQ(test_alloc(&es_ext_test_plugin, 0600), -EIO);
	ctl->init_ret = 0;
	CHECK(!server && lstat(test_socket, &sb) < 0,
	      "a source refused left a server or a socket");

	fd = open(test_socket, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
	close(fd);
	CHECK_EQ(test_alloc(&es_ext_test_plugin, 0600), -EEXIST);
	unlink(test_socket);

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_socket);
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	CHECK_EQ(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
	close(fd);
	CHECK_EQ(test_alloc(&es_ext_test_plugin, 0640), 0);
	CHECK(!lstat(test_socket, &sb) && S_ISSOCK(sb.st_mode) &&
		      (sb.st_mode & 0777) == 0640,
	      "no socket of mode 0640");
	esdm_es_ext_server_free(server);
	CHECK_EQ(ctl->fini_calls, 1);
	CHECK(lstat(test_socket, &sb) < 0, "the socket was not removed");
}

/* A request followed by 4 zero bytes, which are no field of it */
#define TEST_LONGER ((size_t)-1)

/*
 * Is a request of @type for @length refused, sent in @len bytes - 0 for its
 * size?
 */
static bool test_refused(uint16_t type, uint32_t length, size_t len)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_MAX + 4] = { 0 }, b;
	size_t reqlen = esdm_es_ext_proto_req_pack(
		req, ESDM_ES_EXT_PROTO_REQ_MAX, type, length);
	struct es_ext_test_client c;
	bool ret;

	if (es_ext_test_client_open(&c, test_socket))
		return false;
	len = !len ? reqlen : len == TEST_LONGER ? reqlen + 4 : len;
	ret = send(c.fd, req, len, MSG_NOSIGNAL) == (ssize_t)len &&
	      !recv(c.fd, &b, 1, 0);
	es_ext_test_client_close(&c);
	return ret;
}

/*
 * GET_ENTROPY and SELFTEST, also of a second client: what the source returns
 * is passed on as an errno or -EIO, and a claim beyond its data is -EINVAL. A
 * message breaking the protocol closes the connection.
 */
static void test_server_requests(void)
{
	/* What the source returns, and the status of the answer */
	static const struct {
		uint16_t type;
		uint32_t claim;
		int ret, status;
	} rets[] = {
		{ GET, 48 * 8 + 1, 0, -EINVAL },
		{ GET, UINT32_MAX, -ENODEV, -ENODEV },
		{ GET, UINT32_MAX, 1, -EIO },
		{ GET, UINT32_MAX, INT32_MIN, -EIO },
		{ SELF, 0, 0, 0 },
		{ SELF, 0, -EFAULT, -EFAULT },
		{ SELF, 0, 1, -EIO },
	};
	/* A request of @len bytes, 0 for the size of one */
	static const struct {
		uint16_t type;
		uint32_t length;
		size_t len;
	} bad[] = {
		{ GET, 16, 1 },
		{ GET, 16, TEST_LONGER },
		{ GET, ESDM_ES_EXT_PROTO_MAX_DATA + 1, 0 },
		{ STAT, 0, 0 },
		{ STAT, MAX + 1, 0 },
		{ INFO, 1, 0 },
		{ INFO + 1, 0, 0 },
	};
	struct es_ext_test_client c, c2;
	unsigned int i;

	test_reset();
	if (!test_start(&es_ext_test_plugin, &c))
		return;

	ctl->claim_bits = 300;
	CHECK_EQ(es_ext_test_client_ask(&c, GET, 48), 0);
	CHECK(c.bits == 300 && c.datalen == 48 && ctl->last_buflen == 48 &&
		      c.data[0] == (ctl->get_calls & 0xff),
	      "the data and the claim of the source are not passed on");
	ctl->claim_bits = UINT32_MAX;
	CHECK_EQ(es_ext_test_client_ask(&c, GET, ESDM_ES_EXT_PROTO_MAX_DATA),
		 0);
	CHECK_EQ(c.bits, ESDM_ES_EXT_PROTO_MAX_DATA * 8);

	for (i = 0; i < sizeof(rets) / sizeof(rets[0]); i++) {
		ctl->claim_bits = rets[i].claim;
		ctl->get_ret = ctl->selftest_ret = rets[i].ret;
		CHECK(es_ext_test_client_ask(&c, rets[i].type,
					     rets[i].type == GET ? 48 : 0) ==
			      rets[i].status,
		      "request %u", i);
	}
	ctl->get_ret = ctl->selftest_ret = 0;
	ctl->claim_bits = UINT32_MAX;
	CHECK_EQ(ctl->selftest_calls, 3);

	CHECK_EQ(es_ext_test_client_open(&c2, test_socket), 0);
	CHECK_EQ(es_ext_test_client_ask(&c2, GET, 16), 0);
	es_ext_test_client_close(&c2);

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		CHECK(test_refused(bad[i].type, bad[i].length, bad[i].len),
		      "message %u is not refused", i);
	CHECK_EQ(es_ext_test_client_ask(&c, GET, 16), 0);

	test_end(&c);
}

static bool test_info_is(struct es_ext_test_client *c, const char *want,
			 uint32_t want_rate)
{
	char name[ESDM_ES_EXT_NAME_MAX + 1];
	uint32_t rate;

	return !es_ext_test_client_info(c, name, sizeof(name), &rate) &&
	       !strcmp(name, want) && rate == want_rate;
}

/*
 * INFO: the name of the source if it is valid, the rate it declares capped -
 * or those set, invalid ones refused
 */
static void test_server_info(void)
{
	struct es_ext_test_client c;

	test_reset();
	ctl->entropy_rate = 300;
	es_ext_test_plugin.name = "x\ny";
	if (!test_start(&es_ext_test_plugin, &c))
		return;
	CHECK(test_info_is(&c, "", ESDM_ES_EXT_ENTROPY_RATE_MAX),
	      "an invalid name declared, or a rate not capped");
	test_stop(&c);

	CHECK_EQ(esdm_es_ext_server_set_name(server, "x\ny"), -EINVAL);
	CHECK_EQ(esdm_es_ext_server_set_name(server, ""), -EINVAL);
	CHECK_EQ(esdm_es_ext_server_set_name(server, "Quelle \xc3\xa4"), 0);
	CHECK_EQ(esdm_es_ext_server_set_entropy_rate(server, 257), -EINVAL);
	CHECK_EQ(esdm_es_ext_server_set_entropy_rate(server, 0), 0);
	test_run(&c);
	CHECK(test_info_is(&c, "Quelle \xc3\xa4", 0),
	      "the name and the rate set are not declared");
	test_stop(&c);

	es_ext_test_plugin.name = ctl->name;
	CHECK_EQ(esdm_es_ext_server_set_name(server, NULL), 0);
	CHECK_EQ(esdm_es_ext_server_set_entropy_rate(
			 server, ESDM_ES_EXT_PROTO_RATE_NONE),
		 0);
	test_run(&c);
	CHECK(test_info_is(&c, ES_EXT_TEST_NAME, ESDM_ES_EXT_ENTROPY_RATE_MAX),
	      "the name and the rate of the source are not declared again");
	test_end(&c);
}

static const char *test_text(struct json_object *obj)
{
	return json_object_to_json_string_ext(
		obj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
}

/*
 * The uptime of the answer to STATUS for @length bytes, -1 unless it holds
 * the fields of the server @fields - NULL for any - and the status of the
 * source @source as JSON text
 */
static int64_t test_status(struct es_ext_test_client *c, uint32_t length,
			   const char *fields, const char *source)
{
	struct json_object *obj = es_ext_test_client_status(c, length);
	struct json_object *srv, *val;
	int64_t uptime = -1;

	if (json_object_object_get_ex(obj, "server", &srv) &&
	    json_object_object_get_ex(srv, "uptime_seconds", &val)) {
		uptime = json_object_get_int64(val);
		json_object_object_del(srv, "uptime_seconds");
		if ((fields && strcmp(test_text(srv), fields)) ||
		    !json_object_object_get_ex(obj, "plugin", &val) ||
		    strcmp(test_text(val), source))
			uptime = -1;
	}
	if (uptime < 0)
		printf("status: %s\n", obj ? test_text(obj) : "(none)");
	json_object_put(obj);
	return uptime;
}

/*
 * STATUS: the fields of the server and the status of the source - null for
 * none, an error, one unterminated or no valid status, and left out where
 * both do not fit; the same of callbacks that leave out all they may.
 */
static void test_server_status(void)
{
	static const struct {
		const char *text;
		int ret, unterminated;
	} none[] = {
		{ .text = "" }, { .text = "{\"a\":NaN}" }, { .ret = -ENODEV },
		{ .ret = 1 },	{ .unterminated = 1 },
	};
	struct esdm_es_ext_plugin bare = {
		.version = ESDM_ES_EXT_PLUGIN_VERSION,
		.get_entropy = es_ext_test_plugin.get_entropy,
	};
	char big[ESDM_ES_EXT_STATUS_MAX + 1];
	struct es_ext_test_client c, c2;
	unsigned int i;
	int64_t uptime;
	size_t len;

	test_reset();
	if (!test_start(&es_ext_test_plugin, &c))
		return;
	uptime = test_status(&c, MAX, test_fields(TEST_NAME, 1, 0, "none"),
			     ES_EXT_TEST_STATUS);
	CHECK(uptime >= 0, "unexpected status");
	CHECK_EQ(ctl->last_status_buflen, ESDM_ES_EXT_STATUS_MAX + 1);

	CHECK_EQ(es_ext_test_client_ask(&c, GET, 16), 0);
	CHECK_EQ(es_ext_test_client_ask(&c, SELF, 0), 0);
	CHECK_EQ(es_ext_test_client_open(&c2, test_socket), 0);
	CHECK_EQ(es_ext_test_client_ask(&c2, SELF, 0), 0);
	CHECK(test_status(&c, MAX, test_fields(TEST_NAME, 2, 4, "passed"),
			  ES_EXT_TEST_STATUS) >= 0,
	      "requests, a client or a self test passed not reported");
	es_ext_test_client_close(&c2);
	ctl->selftest_ret = -ENODEV;
	CHECK_EQ(es_ext_test_client_ask(&c, SELF, 0), -ENODEV);
	es_ext_test_sleep_ms(1100);
	CHECK(test_status(&c, MAX, test_fields(TEST_NAME, 1, 6, "failed"),
			  ES_EXT_TEST_STATUS) > uptime,
	      "a self test failed or the uptime not reported");

	for (i = 0; i < sizeof(none) / sizeof(none[0]); i++) {
		ctl->status_text = none[i].text;
		ctl->status_ret = none[i].ret;
		ctl->status_unterminated = none[i].unterminated;
		CHECK(test_status(&c, MAX, NULL, "null") >= 0,
		      "status %u of the source taken", i);
	}
	len = c.datalen;
	ctl->status_ret = ctl->status_unterminated = 0;

	memset(big, 'a', sizeof(big));
	memcpy(big, "{\"x\":\"", 6);
	memcpy(big + ESDM_ES_EXT_STATUS_MAX - 2, "\"}", 3);
	ctl->status_text = big;
	CHECK(test_status(&c, MAX, NULL, big) >= 0,
	      "the largest status of the source is not taken");
	CHECK(test_status(&c, (uint32_t)len + 2, NULL, "null") >= 0,
	      "the status of the source is not left out");
	CHECK_EQ(es_ext_test_client_ask(&c, STAT, 8), -EMSGSIZE);
	test_end(&c);

	if (!test_start(&bare, &c))
		return;
	CHECK_EQ(es_ext_test_client_ask(&c, SELF, 0), 0);
	CHECK(test_info_is(&c, "", ESDM_ES_EXT_PROTO_RATE_NONE),
	      "callbacks without name or rate declare one");
	/* No self test, no verdict: the SELFTEST answered 0 all the same */
	CHECK(test_status(&c, MAX, test_fields("null", 1, 2, "none"), "null") >=
		      0,
	      "unexpected status of callbacks without status");
	test_end(&c);
}

/* With uids allowed, only those and root are served */
static void test_server_allow(void)
{
	struct es_ext_test_client c;
	unsigned int i;

	test_reset();
	CHECK_EQ(test_alloc(&es_ext_test_plugin, 0666), 0);
	if (!server)
		return;
	CHECK_EQ(esdm_es_ext_server_allow_uid(server, (uid_t)-1), -EINVAL);
	CHECK_EQ(esdm_es_ext_server_allow_uid(server, getuid() + 1), 0);
	test_run(&c);
	CHECK(es_ext_test_client_ask(&c, GET, 16) == (getuid() ? 1 : 0),
	      "a client of a user not allowed is served");
	test_stop(&c);
	CHECK_EQ(esdm_es_ext_server_allow_uid(server, getuid()), 0);
	test_run(&c);
	CHECK_EQ(es_ext_test_client_ask(&c, GET, 16), 0);
	test_stop(&c);

	/* Up to 8, one allowed twice taking no room */
	for (i = 0; i < 6; i++)
		CHECK_EQ(esdm_es_ext_server_allow_uid(server, 5000 + i), 0);
	CHECK_EQ(esdm_es_ext_server_allow_uid(server, 5000), 0);
	CHECK_EQ(esdm_es_ext_server_allow_uid(server, 6000), -ENOSPC);
	esdm_es_ext_server_free(server);
}

/*
 * With all 8 slots taken, a client connecting takes the slot of the one idle
 * the longest: clients holding slots do not lock the ESDM out
 */
static void test_server_slots(void)
{
	struct es_ext_test_client c[9];
	unsigned int i;

	test_reset();
	if (!test_start(&es_ext_test_plugin, &c[0]))
		return;
	/* Used one after the other, the first again before the last connects */
	for (i = 0; i < 9; i++) {
		if (i == 8)
			CHECK_EQ(es_ext_test_client_ask(&c[0], GET, 16), 0);
		CHECK(!i || !es_ext_test_client_open(&c[i], test_socket),
		      "client %u cannot connect", i);
		CHECK(!es_ext_test_client_ask(&c[i], GET, 16),
		      "client %u is not served", i);
		es_ext_test_sleep_ms(5);
	}
	/* The second one, idle the longest, lost its slot */
	for (i = 0; i < 9; i++) {
		CHECK(es_ext_test_client_ask(&c[i], GET, 16) == (i == 1),
		      "client %u", i);
		es_ext_test_client_close(&c[i]);
	}
	test_end(&c[0]);
}

#define J(text, ok) { text, sizeof(text) - 1, ok }
#define UTF8_NAME "\x7f\xc3\xa4\xe2\x82\xac\xf0\x9f\x98\x80"

/* The status of a source as the ESDM and the server take it, or do not */
static void test_json(void)
{
	static const struct {
		const char *text;
		size_t len;
		bool ok;
	} cases[] = {
		J("{}", true),
		J("{\"s\":\"x\",\"i\":-3,\"b\":false,\"n\":null,\"a\":[1,2],"
		  "\"o\":{\"d\":1.5}}",
		  true),
		/* UTF-8 of every length, in a member name: json-c 0.18 takes
		 * none in strings in its strict mode */
		J("{\"" UTF8_NAME "\":null}", true),
		J("{\"a\":1.7976931348623157e308,\"b\":-0.0}", true),
		J("{\"a\":1}\n", true),
		/* C0 controls, which the text of the status escapes */
		J("{\"a\":\"\\u0001\\u001b\\n\\u00a0\"}", true),
		J("", false),
		J("[1]", false),
		J("null", false),
		J("{", false),
		J("{\"a\":1} x", false),
		J("{\"a\":1}{}", false),
		J("{\"a\":1,}", false),
		J("{a:1}", false),
		J("{\"a\":01}", false),
		/* Numbers JSON has none for, which json-c takes */
		J("{\"a\":NaN}", false),
		J("{\"a\":-Infinity}", false),
		J("{\"o\":{\"p\":[1,Infinity]}}", false),
		J("{\"a\":1e999}", false),
		/* No UTF-8, in a member name - taken by json-c - or a string */
		J("{\"\xff\":1}", false),
		J("{\"\xed\xa0\x80\":1}", false),
		J("{\"a\":\"\xfe\"}", false),
		/* What steers a terminal, escaped or not, nested */
		J("{\"a\":\"\\u009b2J\"}", false),
		J("{\"\xc2\x9b\":1}", false),
		J("{\"\\u202e\":1}", false),
		J("{\"o\":{\"p\":[1,\"\\u2066\"]}}", false),
		J("{\"a\":\"\0\"}", false),
		J("{\"a\":1}\0", false),
	};
	char buf[ESDM_ES_EXT_STATUS_MAX + 1];
	struct json_object *obj;
	unsigned int i, depth;
	size_t len;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		obj = esdm_es_ext_json_object(cases[i].text, cases[i].len,
					      ESDM_ES_EXT_STATUS_MAX,
					      ESDM_ES_EXT_STATUS_MAX_DEPTH);
		CHECK(!obj == !cases[i].ok, "status %u", i);
		CHECK(i != 2 || json_object_object_get_ex(obj, UTF8_NAME, NULL),
		      "the UTF-8 of the status changed");
		json_object_put(obj);
	}

	/* As deep and as long as allowed, and beyond */
	for (depth = ESDM_ES_EXT_STATUS_MAX_DEPTH;
	     depth <= ESDM_ES_EXT_STATUS_MAX_DEPTH + 1; depth++) {
		for (len = i = 0; i < depth; i++, len += 5)
			memcpy(buf + len, "{\"a\":", 5);
		buf[len++] = '1';
		memset(buf + len, '}', depth);
		obj = esdm_es_ext_json_object(buf, len + depth,
					      ESDM_ES_EXT_STATUS_MAX,
					      ESDM_ES_EXT_STATUS_MAX_DEPTH);
		CHECK(!obj == (depth > ESDM_ES_EXT_STATUS_MAX_DEPTH),
		      "depth %u", depth);
		json_object_put(obj);
	}
	memset(buf, ' ', sizeof(buf));
	memcpy(buf, "{}", 2);
	for (len = ESDM_ES_EXT_STATUS_MAX; len <= sizeof(buf); len++) {
		obj = esdm_es_ext_json_object(buf, len, ESDM_ES_EXT_STATUS_MAX,
					      ESDM_ES_EXT_STATUS_MAX_DEPTH);
		CHECK(!obj == (len > ESDM_ES_EXT_STATUS_MAX), "%zu bytes", len);
		json_object_put(obj);
	}
}

int main(void)
{
	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory\n");
		return 1;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);

	/* The mode is set by the library, not left to the umask */
	umask(0077);

	test_server_alloc();
	test_server_requests();
	test_server_info();
	test_server_status();
	test_server_allow();
	test_server_slots();
	test_json();

	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_lib");
}
