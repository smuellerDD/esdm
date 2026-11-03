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
 * The provider programs: esdm_es_ext_provider_main() serving the test source
 * - its command line, the clients it serves by default, what it declares, its
 * end on SIGTERM - and the example of es-ext/example, reading a device that
 * delivers and one that stalls. The server behind is tested by
 * es_ext_lib_test.c.
 *
 * Usage: es_ext_provider_test <test provider> <example>
 *			       <example reading a FIFO> <the FIFO>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common_test.h"
#include "es_ext_test_client.h"
#include "es_ext_test_plugin.h"
#include "es_ext_test_util.h"

#define GET ESDM_ES_EXT_PROTO_GET_ENTROPY

static char test_dir[] = "/tmp/esdm-es-ext-provider-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];

/*
 * What the provider cannot serve, it refuses to start with - exit status 1,
 * and no socket left behind
 */
static void test_refusals(const char *serve)
{
	static const char *const bad[][2] = {
		{ "--mode", "0999" },
		{ "--client_uid", "no-such-user-esdm-test" },
		{ "stray", NULL },
		{ "--name", "" },
		{ "--name", "0123456789abcdef0123456789abcdef0" },
		{ "--name", "esc\x1b[0m" },
		{ "--entropy_rate", "257" },
		{ "--entropy_rate", "-1" },
		{ "--entropy_rate", "12x" },
		{ "--entropy_rate", "" },
	};
	char *argv[] = { (char *)serve, "--socket", test_socket,
			 NULL,		NULL,	    NULL };
	char *init_fails[] = { ES_EXT_TEST_PLUGIN_ENV "=init_ret=-19", NULL };
	struct stat sb;
	unsigned int i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		argv[3] = (char *)bad[i][0];
		argv[4] = (char *)bad[i][1];
		CHECK(es_ext_test_wait(es_ext_test_spawn(argv, NULL)) == 1,
		      "%s %s is not refused", bad[i][0],
		      argv[4] ? argv[4] : "");
	}
	argv[3] = NULL;
	CHECK_EQ(es_ext_test_wait(es_ext_test_spawn(argv, init_fails)), 1);
	argv[1] = NULL;
	CHECK_EQ(es_ext_test_wait(es_ext_test_spawn(argv, NULL)), 1);
	CHECK(lstat(test_socket, &sb) < 0,
	      "a refused start left a socket behind");

	argv[1] = "--version";
	CHECK_EQ(es_ext_test_wait(es_ext_test_spawn(argv, NULL)), 0);
	argv[1] = "--help";
	CHECK_EQ(es_ext_test_wait(es_ext_test_spawn(argv, NULL)), 0);
}

/*
 * The socket with the mode asked for, the source served, and on SIGTERM a
 * clean end, the socket removed
 */
static void test_serve(const char *serve)
{
	const char *const mode[] = { "--mode", "0640", NULL };
	struct es_ext_test_client c;
	struct stat sb;
	pid_t pid;

	pid = es_ext_test_serve(serve, test_socket, mode, NULL);
	CHECK(pid > 0, "the provider did not come up");
	if (pid <= 0)
		return;
	CHECK(!lstat(test_socket, &sb) && (sb.st_mode & 0777) == 0640,
	      "the socket is not of mode 0640");
	CHECK_EQ(es_ext_test_client_open(&c, test_socket), 0);
	CHECK(!es_ext_test_client_ask(&c, GET, 32) && c.bits == 256,
	      "the source is not served");
	CHECK_EQ(es_ext_test_client_ask(&c, ESDM_ES_EXT_PROTO_SELFTEST, 0), 0);
	es_ext_test_client_close(&c);

	CHECK_EQ(kill(pid, SIGTERM), 0);
	CHECK_EQ(es_ext_test_wait(pid), 0);
	CHECK(lstat(test_socket, &sb) < 0, "the socket was left behind");
}

/* Without --client_uid, root and nobody - the ESDM - and nobody else */
static void test_default_clients(const char *serve)
{
	char *const argv[] = { (char *)serve, "--socket", test_socket, NULL };
	struct passwd *pw = getpwnam("nobody");
	struct es_ext_test_client c;
	pid_t pid;

	if (!getuid() || (pw && pw->pw_uid == getuid())) {
		printf("root or nobody - skipping the client check\n");
		return;
	}

	pid = es_ext_test_spawn(argv, NULL);
	CHECK(pid > 0 && es_ext_test_wait_socket(test_socket),
	      "the provider did not come up");
	CHECK_EQ(es_ext_test_client_open(&c, test_socket), 0);
	CHECK(es_ext_test_client_ask(&c, GET, 16) == 1,
	      "a client of another user is served by default");
	es_ext_test_client_close(&c);
	es_ext_test_terminate(pid);
}

/*
 * INFO: the name and the rate of the source - by default none of the test
 * source - or those of --name and --entropy_rate
 */
static void test_info(const char *serve)
{
	static const struct {
		const char *settings;
		const char *args[5];
		const char *name;
		uint32_t rate;
	} rounds[] = {
		{ NULL,
		  { NULL },
		  ES_EXT_TEST_NAME,
		  ESDM_ES_EXT_PROTO_RATE_NONE },
		{ NULL,
		  { "--name", "Quelle \xc3\xa4", "--entropy_rate", "100",
		    NULL },
		  "Quelle \xc3\xa4",
		  100 },
		{ "rate=128;name=es-ext-rated", { NULL }, "es-ext-rated", 128 },
		{ "rate=128;name=es-ext-rated",
		  { "--name", "anders", "--entropy_rate", "0", NULL },
		  "anders",
		  0 },
	};
	char name[ESDM_ES_EXT_NAME_MAX + 1];
	struct es_ext_test_client c;
	unsigned int i;
	uint32_t rate;
	pid_t pid;

	for (i = 0; i < sizeof(rounds) / sizeof(rounds[0]); i++) {
		pid = es_ext_test_serve(serve, test_socket, rounds[i].args,
					rounds[i].settings);
		CHECK_EQ(es_ext_test_client_open(&c, test_socket), 0);
		CHECK(!es_ext_test_client_info(&c, name, sizeof(name), &rate) &&
			      !strcmp(name, rounds[i].name) &&
			      rate == rounds[i].rate,
		      "round %u: another name or rate declared", i);
		es_ext_test_client_close(&c);
		es_ext_test_terminate(pid);
	}
}

/*
 * The example built to read /dev/urandom: it declares its name and its rate,
 * delivers with one bit of entropy per byte, and reports its reads
 */
static void test_example(const char *example)
{
	char name[ESDM_ES_EXT_NAME_MAX + 1];
	struct es_ext_test_client c;
	struct json_object *obj, *val = NULL;
	uint32_t rate = 0;
	pid_t pid;

	pid = es_ext_test_serve(example, test_socket, NULL, NULL);
	CHECK_EQ(es_ext_test_client_open(&c, test_socket), 0);
	CHECK(!es_ext_test_client_info(&c, name, sizeof(name), &rate) &&
		      !strcmp(name, "example (/dev/urandom)") && rate == 32,
	      "the example declares another name or rate");
	CHECK_EQ(es_ext_test_client_ask(&c, ESDM_ES_EXT_PROTO_SELFTEST, 0), 0);
	CHECK(!es_ext_test_client_ask(&c, GET, 32) && c.bits == 32,
	      "the example does not deliver one bit per byte");

	obj = es_ext_test_client_status(&c, ESDM_ES_EXT_PROTO_STATUS_MAX);
	CHECK(json_object_object_get_ex(obj, "plugin", &val) &&
		      !strcmp(json_object_to_json_string_ext(
				      val,
				      JSON_C_TO_STRING_PLAIN |
					      JSON_C_TO_STRING_NOSLASHESCAPE),
			      "{\"device\":\"/dev/urandom\",\"reads\":1,"
			      "\"failures\":0}"),
	      "unexpected status of the example");
	json_object_put(obj);

	es_ext_test_client_close(&c);
	es_ext_test_terminate(pid);
}

/*
 * The example reading a device that stalls - a FIFO the test keeps open and
 * writes nothing to: a request gives up in time rather than block the DRNG
 * waiting for it, and is served once the device delivers again
 */
static void test_example_stalled(const char *example, const char *fifo)
{
	struct es_ext_test_client c;
	pid_t pid;
	int fd;

	unlink(fifo);
	CHECK(!mkfifo(fifo, 0600), "cannot create %s", fifo);
	/* Read and written: the example finds a writer that writes nothing */
	fd = open(fifo, O_RDWR | O_CLOEXEC);
	pid = es_ext_test_serve(example, test_socket, NULL, NULL);
	CHECK_EQ(es_ext_test_client_open(&c, test_socket), 0);
	CHECK_EQ(es_ext_test_client_ask(&c, GET, 32), -ETIMEDOUT);

	CHECK_EQ(write(fd, "0123456789abcdef0123456789abcdef", 32), 32);
	CHECK(!es_ext_test_client_ask(&c, GET, 32) && c.bits == 32 &&
		      !memcmp(c.data, "0123456789abcdef0123456789abcdef", 32),
	      "the example does not deliver what the device holds again");

	es_ext_test_client_close(&c);
	es_ext_test_terminate(pid);
	close(fd);
	unlink(fifo);
}

int main(int argc, char *argv[])
{
	if (argc < 5) {
		printf("usage: %s <test provider> <example> "
		       "<example reading a FIFO> <the FIFO>\n",
		       argv[0]);
		return 1;
	}

	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory\n");
		return 1;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);

	test_refusals(argv[1]);
	test_serve(argv[1]);
	test_default_clients(argv[1]);
	test_info(argv[1]);
	test_example(argv[2]);
	test_example_stalled(argv[3], argv[4]);

	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_provider");
}
