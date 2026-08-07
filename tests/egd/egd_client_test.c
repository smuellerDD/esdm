/*
 * Protocol level tests of the EGD client library
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

/*
 * These run against the test peer next to this file rather than against an
 * esdm-server: they are about the client's own behaviour - its framing of the
 * commands, what it makes of an answer no correct server would give, and how
 * it deals with a connection that is not there any more - none of which a
 * correct server can be made to produce on demand. No privileges are needed,
 * so this runs everywhere, and the esdm-server side of the protocol is covered
 * by egd_server_test.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "egd_peer.h"
#include "esdm_egd_client.h"
#include "esdm_egd_protocol.h"

/*
 * Bound on every wait of a client under test. Generous enough not to be hit by
 * a loaded machine, short enough that the deliberately unanswered requests do
 * not stretch the test run.
 */
#define TEST_TIMEOUT_MS 2000

/*
 * Backstop for a client that does not come back at all. Well above what the
 * deliberately unanswered requests add up to, and below the timeout the test
 * harness applies to the whole run.
 */
#define TEST_WATCHDOG_SEC 90

static char tmpdir[] = "/tmp/esdm-egd-test-XXXXXX";

/* Socket path of one test, in the temporary directory created by main(). */
static const char *test_socket(const char *name)
{
	static char path[sizeof(((struct sockaddr_un *)0)->sun_path)];

	snprintf(path, sizeof(path), "%s/%s.sock", tmpdir, name);

	return path;
}

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL: ");                                    \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			ret = 1;                                               \
		}                                                              \
	} while (0)

/*
 * A request longer than one protocol transfer has to be split by the client,
 * and the pieces have to arrive in order. The peer answers with a counter, so
 * the reassembled result says both.
 */
static int test_blocking_read_chunking(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	/* Two transfers: a full one of 255 bytes and a remainder of 45. */
	uint8_t buf[300];
	size_t i;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("chunk"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("chunk"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");

	for (i = 0; i < sizeof(buf); i++) {
		if (buf[i] != egd_peer_data_byte(i)) {
			CHECK(0, "byte %zu is 0x%02x, expected 0x%02x", i,
			      buf[i], egd_peer_data_byte(i));
			break;
		}
	}

	CHECK(egd_peer_requests(peer) == 2, "%u transfers, expected 2",
	      egd_peer_requests(peer));
	CHECK(egd_peer_connections(peer) == 1,
	      "%u connections, expected a single one",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The non-blocking read reports what it got, which may be less than asked. */
static int test_nonblocking_read(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[32];
	size_t generated = 0;
	size_t i;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("nonblock"), EGD_PEER_SHORT))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("nonblock"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_random_nonblock(client, buf, sizeof(buf),
						  &generated) == 0,
	      "the non-blocking read failed");
	CHECK(generated == sizeof(buf) / 2, "%zu bytes delivered, expected %zu",
	      generated, sizeof(buf) / 2);

	for (i = 0; i < generated; i++) {
		if (buf[i] != egd_peer_data_byte(i)) {
			CHECK(0, "byte %zu is 0x%02x, expected 0x%02x", i,
			      buf[i], egd_peer_data_byte(i));
			break;
		}
	}

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * A peer announcing more data than was asked for is not speaking this protocol.
 * Reading it would overrun the caller's buffer and desynchronize the stream, so
 * the client has to refuse on the length byte alone.
 */
static int test_nonblocking_overlong(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	size_t generated = 1;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("overlong"), EGD_PEER_OVERLONG))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("overlong"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_random_nonblock(client, buf, sizeof(buf),
						  &generated) == -EPROTO,
	      "an overlong answer was not rejected with -EPROTO");
	CHECK(generated == 0, "%zu bytes reported after the failure", generated);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The entropy count arrives as a big endian four byte number. */
static int test_entropy_count(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t bits = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("entcnt"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("entcnt"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");
	CHECK(bits == EGD_PEER_ENTROPY_BITS, "%u bits, expected %u", bits,
	      EGD_PEER_ENTROPY_BITS);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The PID arrives as a string, without a terminating NUL. */
static int test_get_pid(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	pid_t pid = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("getpid"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("getpid"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_pid(client, &pid) == 0,
	      "the PID request failed");
	CHECK(pid == EGD_PEER_PID, "PID %d, expected %d", (int)pid,
	      EGD_PEER_PID);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The write command carries its entropy claim and its length in the header. */
static int test_write_entropy(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	static const uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef,
					0x01, 0x02, 0x03, 0x04 };
	uint8_t received[sizeof(data)];
	uint32_t bits = 0;
	size_t len = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("write"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("write"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_write_entropy(client, data, sizeof(data), 64) == 0,
	      "the entropy insertion failed");

	/*
	 * The command has no answer, so the client is done before the peer has
	 * necessarily read it. One request that does get answered orders the
	 * two against each other.
	 */
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");

	CHECK(egd_peer_last_write(peer, received, sizeof(received), &len,
				  &bits) == 1,
	      "the peer did not receive exactly one write command");
	CHECK(len == sizeof(data), "%zu bytes written, expected %zu", len,
	      sizeof(data));
	CHECK(bits == 64, "%u bits claimed, expected 64", bits);
	CHECK(memcmp(received, data, sizeof(data)) == 0,
	      "the written data does not match");

	/*
	 * The claim is two bytes on the wire, so a larger one is capped rather
	 * than truncated into a small number.
	 */
	CHECK(esdm_egd_client_write_entropy(client, data, sizeof(data),
					    UINT32_MAX) == 0,
	      "the entropy insertion with a large claim failed");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");
	CHECK(egd_peer_last_write(peer, NULL, 0, NULL, &bits) == 2,
	      "the peer did not receive the second write command");
	CHECK(bits == UINT16_MAX, "%u bits claimed, expected %u", bits,
	      UINT16_MAX);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* Nothing here may reach the peer, and nothing may crash. */
static int test_arguments(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	size_t generated = 1;
	uint32_t bits;
	pid_t pid;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("args"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("args"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_alloc(NULL, test_socket("args"), 0) == -EINVAL,
	      "an allocation without a result pointer was accepted");

	CHECK(esdm_egd_client_get_random(client, NULL, 16) == -EINVAL,
	      "a blocking read without a buffer was accepted");
	CHECK(esdm_egd_client_get_random(NULL, buf, sizeof(buf)) == -EINVAL,
	      "a blocking read without a client was accepted");
	CHECK(esdm_egd_client_get_random(client, buf, 0) == 0,
	      "an empty blocking read is not a no-op");

	CHECK(esdm_egd_client_get_random_nonblock(client, buf, sizeof(buf),
						  NULL) == -EINVAL,
	      "a non-blocking read without a result pointer was accepted");
	/* The protocol cannot express more than one transfer here. */
	CHECK(esdm_egd_client_get_random_nonblock(client, buf,
						  ESDM_EGD_MAX_TRANSFER + 1,
						  &generated) == -EINVAL,
	      "an oversized non-blocking read was accepted");
	CHECK(esdm_egd_client_get_random_nonblock(client, buf, 0,
						  &generated) == 0,
	      "an empty non-blocking read is not a no-op");
	CHECK(generated == 0, "%zu bytes reported for an empty read",
	      generated);

	CHECK(esdm_egd_client_entropy_count(client, NULL) == -EINVAL,
	      "an entropy count without a result pointer was accepted");
	CHECK(esdm_egd_client_entropy_count(NULL, &bits) == -EINVAL,
	      "an entropy count without a client was accepted");

	CHECK(esdm_egd_client_get_pid(client, NULL) == -EINVAL,
	      "a PID request without a result pointer was accepted");
	CHECK(esdm_egd_client_get_pid(NULL, &pid) == -EINVAL,
	      "a PID request without a client was accepted");

	CHECK(esdm_egd_client_write_entropy(client, NULL, 16, 0) == -EINVAL,
	      "an insertion without data was accepted");
	CHECK(esdm_egd_client_write_entropy(client, buf,
					    ESDM_EGD_MAX_TRANSFER + 1,
					    0) == -EINVAL,
	      "an oversized insertion was accepted");
	CHECK(esdm_egd_client_write_entropy(client, buf, 0, 0) == 0,
	      "an empty insertion is not a no-op");

	CHECK(esdm_egd_client_socket_path(NULL) == NULL,
	      "a socket path was reported for no client");
	CHECK(esdm_egd_client_socket_path(client) != NULL &&
		      !strcmp(esdm_egd_client_socket_path(client),
			      test_socket("args")),
	      "the client reports the wrong socket path");

	CHECK(egd_peer_requests(peer) == 0,
	      "%u requests reached the peer, expected none",
	      egd_peer_requests(peer));

	/* Releasing no client at all is allowed. */
	esdm_egd_client_free(NULL);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* Without a path, the one from the environment is used. */
static int test_socket_path_from_env(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t bits = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("env"), EGD_PEER_NORMAL))
		return 1;

	setenv("ESDM_EGD_SOCKET", test_socket("env"), 1);

	if (esdm_egd_client_alloc(&client, NULL, TEST_TIMEOUT_MS)) {
		unsetenv("ESDM_EGD_SOCKET");
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(!strcmp(esdm_egd_client_socket_path(client), test_socket("env")),
	      "the environment socket path was not taken over");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the connection from the environment path does not work");

	/* An empty path is not a path either. */
	unsetenv("ESDM_EGD_SOCKET");
	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * The daemon is restarted between two requests: the first attempt fails on the
 * connection it had, and the retry on a fresh one succeeds - the caller sees
 * nothing but a successful request.
 */
static int test_reconnect(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("reconnect"), EGD_PEER_HANGUP))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("reconnect"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the request was not retried on a fresh connection");
	CHECK(egd_peer_connections(peer) == 2, "%u connections, expected 2",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * A failed request must not leave anything behind that could be mistaken for
 * random data.
 */
static int test_failure_wipes_buffer(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	uint8_t zero[sizeof(buf)];
	size_t generated = 1;
	int ret = 0;

	memset(zero, 0, sizeof(zero));

	if (egd_peer_start(&peer, test_socket("silent"), EGD_PEER_SILENT))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("silent"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	memset(buf, 0xff, sizeof(buf));
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) ==
		      -ETIMEDOUT,
	      "an unanswered blocking read did not time out");
	CHECK(memcmp(buf, zero, sizeof(buf)) == 0,
	      "the buffer was not cleansed after the failure");

	memset(buf, 0xff, sizeof(buf));
	CHECK(esdm_egd_client_get_random_nonblock(client, buf, sizeof(buf),
						  &generated) == -ETIMEDOUT,
	      "an unanswered non-blocking read did not time out");
	CHECK(memcmp(buf, zero, sizeof(buf)) == 0,
	      "the buffer was not cleansed after the failure");
	CHECK(generated == 0, "%zu bytes reported after the failure",
	      generated);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * An application may close descriptor ranges it did not open - OpenSSH does on
 * its way into the pre-authentication child - and the number is then free to
 * be reused for something else entirely. Reading "random" data out of whatever
 * took its place would be a silent and serious failure, so the client has to
 * notice that the descriptor is no longer its connection.
 *
 * The check needs to know which descriptor the client got, which is the lowest
 * free one at the time it connects. Nothing else in this process opens one in
 * between, but the assumption is verified rather than trusted.
 */
static int test_descriptor_identity(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);
	uint8_t buf[16];
	size_t i;
	int fd, zero_fd, ret = 0;

	if (egd_peer_start(&peer, test_socket("closefrom"), EGD_PEER_NORMAL))
		return 1;

	/* The number the client's socket is about to get. */
	fd = dup(0);
	if (fd < 0) {
		egd_peer_stop(peer);
		return 1;
	}
	close(fd);

	if (esdm_egd_client_alloc(&client, test_socket("closefrom"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	if (getpeername(fd, (struct sockaddr *)&addr, &addrlen) < 0 ||
	    strcmp(addr.sun_path, test_socket("closefrom"))) {
		printf("  SKIP: the client's descriptor could not be identified\n");
		esdm_egd_client_free(client);
		egd_peer_stop(peer);
		return 0;
	}

	/* Close it behind the client's back and let something else have it. */
	close(fd);
	zero_fd = open("/dev/zero", O_RDONLY);
	if (zero_fd != fd) {
		printf("  SKIP: the descriptor number was not reused\n");
		if (zero_fd >= 0)
			close(zero_fd);
		esdm_egd_client_free(client);
		egd_peer_stop(peer);
		return 0;
	}

	/*
	 * Reading from /dev/zero would succeed and deliver zeros. The client
	 * has to reconnect instead and come back with the peer's data.
	 */
	memset(buf, 0xff, sizeof(buf));
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");
	for (i = 0; i < sizeof(buf); i++) {
		if (buf[i] != egd_peer_data_byte(i)) {
			CHECK(0,
			      "byte %zu is 0x%02x, expected 0x%02x - the data does not come from the peer",
			      i, buf[i], egd_peer_data_byte(i));
			break;
		}
	}
	CHECK(egd_peer_connections(peer) == 2,
	      "%u connections, expected the client to have reconnected",
	      egd_peer_connections(peer));

	close(zero_fd);
	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * Two processes issuing commands on one connection would desynchronize the
 * stream, so a child must not inherit the parent's. It gets one of its own,
 * and the parent's keeps working.
 */
static int test_fork(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	int status = 0;
	pid_t pid;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("fork"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("fork"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	/* Establish the connection that the child must not use. */
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork failed");
		esdm_egd_client_free(client);
		egd_peer_stop(peer);
		return 1;
	}
	if (pid == 0) {
		uint8_t child_buf[16];

		/*
		 * The peer's threads do not exist here, so the client is all
		 * this child may touch of the test - and _exit() rather than
		 * exit() keeps it from running the parent's atexit handlers.
		 */
		_exit(esdm_egd_client_get_random(client, child_buf,
						 sizeof(child_buf)) ?
			      1 :
			      0);
	}

	waitpid(pid, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "the child could not use the client (status %#x)", status);

	/* The parent's connection survived the child. */
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the parent's connection stopped working");
	CHECK(egd_peer_connections(peer) == 2,
	      "%u connections, expected the child to have opened its own",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * A client whose peer is not there yet is handed back usable - a consumer set
 * up before the ESDM is running keeps working once it arrives.
 */
static int test_late_peer(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t bits = 0;
	int ret = 0;

	CHECK(esdm_egd_client_alloc(&client, test_socket("late"),
				    TEST_TIMEOUT_MS) == 0,
	      "the allocation without a peer failed");
	if (client == NULL)
		return 1;

	if (egd_peer_start(&peer, test_socket("late"), EGD_PEER_NORMAL)) {
		esdm_egd_client_free(client);
		return 1;
	}

	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the client did not connect once the peer arrived");
	CHECK(bits == EGD_PEER_ENTROPY_BITS, "%u bits, expected %u", bits,
	      EGD_PEER_ENTROPY_BITS);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

struct egd_test {
	const char *name;
	int (*run)(void);
};

int main(int argc, char *argv[])
{
	static const struct egd_test tests[] = {
		{ "blocking read chunking", test_blocking_read_chunking },
		{ "non-blocking read", test_nonblocking_read },
		{ "overlong answer", test_nonblocking_overlong },
		{ "entropy count", test_entropy_count },
		{ "PID request", test_get_pid },
		{ "entropy insertion", test_write_entropy },
		{ "argument checks", test_arguments },
		{ "socket path from the environment",
		  test_socket_path_from_env },
		{ "reconnect after a hangup", test_reconnect },
		{ "buffer cleansing on failure", test_failure_wipes_buffer },
		{ "descriptor identity", test_descriptor_identity },
		{ "fork", test_fork },
		{ "peer arriving late", test_late_peer },
	};
	unsigned int failed = 0;
	size_t i;

	(void)argc;
	(void)argv;

	/*
	 * Line buffered: should a client ever wedge, the test is killed by the
	 * watchdog below or by the harness, and what it printed until then is
	 * the only indication of where it got stuck.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/*
	 * Every wait in here is bounded, so the whole run is. Being killed here
	 * means a client did not come back at all, which has to be a failure
	 * rather than a test run that hangs until the harness gives up.
	 */
	alarm(TEST_WATCHDOG_SEC);

	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		return 1;
	}

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int ret;

		printf("EGD client: %s\n", tests[i].name);
		ret = tests[i].run();
		if (ret)
			failed++;
	}

	rmdir(tmpdir);

	printf("EGD client: %zu tests, %u failed\n",
	       sizeof(tests) / sizeof(tests[0]), failed);

	return failed ? 1 : 0;
}
