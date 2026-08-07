/*
 * Wire protocol and deferral tests of the EGD server
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
 * The third of the EGD tests, and the one that reaches what the other two
 * cannot:
 *
 * - It speaks the wire protocol byte by byte instead of going through the
 *   client library. Client and server were written against one description of
 *   the protocol, so a test that drives both through the library cannot tell
 *   whether that description was read correctly - only bytes on the socket can.
 *
 * - It runs the server in this process against an ESDM whose seeding it
 *   controls, which is what the blocking read command is about: the request is
 *   issued while the ESDM has no entropy to answer it with, the entropy arrives
 *   afterwards, and the answer has to arrive with it. Against the daemon of
 *   egd_server_test that moment has come and gone before a test can connect.
 *
 * The other property this checks is that waiting for entropy is not the same as
 * blocking: while one client's request waits, the server has to keep serving
 * everybody else.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_egd_protocol.h"
#include "esdm_egd_server.h"
#include "esdm_logger.h"
#include "threading_support.h"

/*
 * Two helpers the EGD server shares with the RPC server, which is not linked
 * here - it would pull the entire RPC machinery, protobuf definitions and all,
 * into a test that speaks a different protocol entirely.
 *
 * They are declared rather than taken from esdm_rpc_server.h and
 * esdm_rpc_protocol.h for the same reason, so nothing but review keeps the
 * signatures in step with those headers.
 */
void esdm_server_remove_stale_socket(const char *path, int socktype);
int set_fd_nonblocking(int fd);

/*
 * The socket of this test is created in a temporary directory of its own, where
 * a stale one cannot exist.
 */
void esdm_server_remove_stale_socket(const char *path, int socktype)
{
	(void)path;
	(void)socktype;
}

/*
 * Only reached on the systemd socket activation path, which this test does not
 * take. Implemented rather than stubbed anyway: a stub that silently succeeds
 * would leave a blocking descriptor behind should that ever change.
 */
int set_fd_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0)
		return -errno;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;

	return 0;
}

/*
 * Backstop for a request that never comes back. Below the timeout the harness
 * applies to the whole run, so such a failure is reported by this test rather
 * than by meson killing it.
 */
#define TEST_WATCHDOG_SEC 120

/*
 * How long a response is waited for. Generous: the answer to a deferred request
 * is produced by the server's own poll interval, and the machine running this
 * may be busy.
 */
#define TEST_RESPONSE_MS 10000

/*
 * How long the absence of a response is checked for. This is the window in
 * which a server that answers a blocking read without having the entropy for it
 * gives itself away, so it has to be well above the server's poll interval.
 */
#define TEST_SILENCE_MS 750

/* How long the ESDM is fed and given time to reach the operational state. */
#define TEST_SEED_ROUNDS 200
#define TEST_SEED_INTERVAL_MS 50

static char tmpdir[] = "/tmp/esdm-egd-raw-test-XXXXXX";
static char sockpath[sizeof(tmpdir) + 32];

static int ret = 0;

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
 * Was a SIGPIPE raised?
 *
 * The server is driven in this very process, so the signal a vanished client
 * provokes lands here - which is what makes it observable at all. The test's own
 * client side never raises one: it sends with MSG_NOSIGNAL throughout, so
 * anything recorded here came from the server.
 */
static volatile sig_atomic_t test_sigpipe;

static void test_sigpipe_handler(int sig)
{
	(void)sig;
	test_sigpipe = 1;
}

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/****************************
 * Raw protocol client
 ****************************/

static int test_connect(void)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * @return 0 when everything was written
 *
 * MSG_NOSIGNAL: writing to a peer the server has dropped is something several
 * of the tests below do on purpose, and it has to come back as an error to
 * check rather than as a signal - which would also be indistinguishable from
 * one the server raised, see test_sigpipe.
 */
static int test_send(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t written = 0;

	while (written < len) {
		ssize_t rc = send(fd, p + written, len - written, MSG_NOSIGNAL);

		if (rc > 0) {
			written += (size_t)rc;
			continue;
		}
		if (rc < 0 && errno == EINTR)
			continue;

		return -1;
	}

	return 0;
}

/*
 * Read exactly @len bytes.
 *
 * @return 0 on success, -ETIMEDOUT when the peer went quiet, -EPIPE when it
 *	   closed the connection, negative errno otherwise
 */
static int test_recv(int fd, void *buf, size_t len, int timeout_ms)
{
	uint8_t *p = buf;
	size_t received = 0;

	while (received < len) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t rc;
		int pret = poll(&pfd, 1, timeout_ms);

		if (pret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (pret == 0)
			return -ETIMEDOUT;

		rc = recv(fd, p + received, len - received, 0);
		if (rc > 0) {
			received += (size_t)rc;
			continue;
		}
		if (rc == 0)
			return -EPIPE;
		if (errno == EINTR)
			continue;

		return -errno;
	}

	return 0;
}

/* Did the peer stay quiet for @timeout_ms? A closed connection is not quiet. */
static bool test_quiet(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int pret;

	do {
		pret = poll(&pfd, 1, timeout_ms);
	} while (pret < 0 && errno == EINTR);

	return (pret == 0);
}

static bool test_all_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return false;
	}

	return true;
}

/****************************
 * Protocol exchanges
 ****************************/

/* Command 0x04: one length byte followed by the PID as a string. */
static int test_cmd_pid(int fd, pid_t *pid, int timeout_ms)
{
	const uint8_t cmd = ESDM_EGD_CMD_GET_PID;
	char resp[UINT8_MAX + 1];
	uint8_t len;
	int rc;

	if (test_send(fd, &cmd, sizeof(cmd)))
		return -EIO;

	rc = test_recv(fd, &len, sizeof(len), timeout_ms);
	if (rc)
		return rc;
	if (!len)
		return -EPROTO;

	rc = test_recv(fd, resp, len, timeout_ms);
	if (rc)
		return rc;
	resp[len] = '\0';

	*pid = (pid_t)strtol(resp, NULL, 10);

	return 0;
}

/* Command 0x00: the available entropy as a 4 byte big endian bit count. */
static int test_cmd_entropy_count(int fd, uint32_t *bits, int timeout_ms)
{
	const uint8_t cmd = ESDM_EGD_CMD_ENTROPY_COUNT;
	uint8_t resp[4];
	int rc;

	if (test_send(fd, &cmd, sizeof(cmd)))
		return -EIO;

	rc = test_recv(fd, resp, sizeof(resp), timeout_ms);
	if (rc)
		return rc;

	*bits = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
		((uint32_t)resp[2] << 8) | (uint32_t)resp[3];

	return 0;
}

/*
 * Command 0x01: one byte holding the number of delivered bytes, followed by
 * that many bytes.
 */
static int test_cmd_read_nonblock(int fd, uint8_t requested, uint8_t *buf,
				  uint8_t *delivered, int timeout_ms)
{
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_NONBLOCK, requested };
	int rc;

	if (test_send(fd, cmd, sizeof(cmd)))
		return -EIO;

	rc = test_recv(fd, delivered, sizeof(*delivered), timeout_ms);
	if (rc)
		return rc;

	if (*delivered > requested)
		return -EPROTO;

	if (!*delivered)
		return 0;

	return test_recv(fd, buf, *delivered, timeout_ms);
}

/* Command 0x02: exactly the requested number of bytes, and nothing else. */
static int test_send_read_block(int fd, uint8_t requested)
{
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_BLOCK, requested };

	return test_send(fd, cmd, sizeof(cmd)) ? -EIO : 0;
}

/* Command 0x03: an entropy claim, a length byte, the data - and no response. */
static int test_cmd_write_entropy(int fd, const uint8_t *buf, uint8_t len,
				  uint16_t entropy_bits)
{
	uint8_t header[4] = { ESDM_EGD_CMD_WRITE_ENTROPY,
			      (uint8_t)(entropy_bits >> 8),
			      (uint8_t)(entropy_bits & 0xff), len };

	if (test_send(fd, header, sizeof(header)))
		return -EIO;

	return test_send(fd, buf, len) ? -EIO : 0;
}

/****************************
 * ESDM state
 ****************************/

/*
 * Feed the auxiliary pool until the ESDM turns operational.
 *
 * Nothing here forces the seeding: the entropy is only made available, and
 * whoever asks the ESDM for random data next is what turns it into an
 * operational state. That is deliberate - the point of the test is that the
 * deferred request of the server is what picks the entropy up.
 */
static int test_esdm_seed(void)
{
	uint8_t seed[64];
	unsigned int i, round;

	for (round = 0; round < TEST_SEED_ROUNDS; round++) {
		if (esdm_state_operational())
			return 0;

		for (i = 0; i < sizeof(seed); i++)
			seed[i] = (uint8_t)(i + round);

		esdm_pool_insert_aux(seed, sizeof(seed), 8 * sizeof(seed));

		test_sleep_ms(TEST_SEED_INTERVAL_MS);
	}

	return esdm_state_operational() ? 0 : -1;
}

/*
 * Take every entropy source out of the picture, so that the ESDM cannot reach
 * the operational state on its own and the moment it does is the test's to
 * choose. The auxiliary pool is not among them: it holds what is inserted into
 * it, which is exactly the handle this needs.
 */
static void test_esdm_disable_es(void)
{
	esdm_config_es_cpu_entropy_rate_set(0);
	esdm_config_es_jent_entropy_rate_set(0);
	esdm_config_es_jent_kernel_entropy_rate_set(0);
	esdm_config_es_krng_entropy_rate_set(0);
	esdm_config_es_irq_entropy_rate_set(0);
	esdm_config_es_irq_ebpf_entropy_rate_set(0);
	esdm_config_es_sched_entropy_rate_set(0);
	esdm_config_es_sched_ebpf_entropy_rate_set(0);
	esdm_config_es_hwrand_entropy_rate_set(0);
	esdm_config_es_tpm2_entropy_rate_set(0);
	esdm_config_es_pkcs11_entropy_rate_set(0);
}

/****************************
 * Tests
 ****************************/

/* The commands that are answered no matter how much entropy there is. */
static void test_stateless_commands(void)
{
	uint32_t bits = 0;
	pid_t pid = 0;
	int fd;

	printf("EGD raw: PID and entropy count\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_pid(fd, &pid, TEST_RESPONSE_MS) == 0,
	      "the PID request was not answered");
	CHECK(pid == getpid(), "the server reports PID %d, this process is %d",
	      (int)pid, (int)getpid());

	CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
	      "the entropy count was not answered");
	printf("  PID %d, %u bits available\n", (int)pid, bits);

	close(fd);
}

/*
 * Several commands in one write, whose responses have to come back in the order
 * the commands were sent - the protocol has no request identifiers, so that
 * order is all a client has to match them by.
 */
static void test_pipelining(void)
{
	uint8_t cmds[4] = { ESDM_EGD_CMD_ENTROPY_COUNT, ESDM_EGD_CMD_GET_PID,
			    ESDM_EGD_CMD_READ_NONBLOCK, 8 };
	uint8_t buf[8], count[4], len, delivered;
	char pidstr[UINT8_MAX + 1];
	int fd;

	printf("EGD raw: pipelined commands\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_send(fd, cmds, sizeof(cmds)) == 0,
	      "the pipelined commands could not be sent");

	CHECK(test_recv(fd, count, sizeof(count), TEST_RESPONSE_MS) == 0,
	      "the entropy count of the pipeline was not answered");

	CHECK(test_recv(fd, &len, sizeof(len), TEST_RESPONSE_MS) == 0,
	      "the PID length of the pipeline was not answered");
	/* pidstr is sized for the longest length the byte can express. */
	CHECK(len > 0, "the PID was answered with an empty string");
	if (len > 0) {
		CHECK(test_recv(fd, pidstr, len, TEST_RESPONSE_MS) == 0,
		      "the PID of the pipeline was not answered");
		pidstr[len] = '\0';
		CHECK((pid_t)strtol(pidstr, NULL, 10) == getpid(),
		      "the pipelined PID request answered with %s", pidstr);
	}

	CHECK(test_recv(fd, &delivered, sizeof(delivered), TEST_RESPONSE_MS) ==
		      0,
	      "the non-blocking read of the pipeline was not answered");
	CHECK(delivered <= sizeof(buf), "%u bytes delivered, 8 were asked for",
	      delivered);
	if (delivered && delivered <= sizeof(buf)) {
		CHECK(test_recv(fd, buf, delivered, TEST_RESPONSE_MS) == 0,
		      "the data of the pipelined non-blocking read is missing");
	}

	close(fd);
}

/* A command that arrives in pieces is only acted on once it is complete. */
static void test_split_command(void)
{
	uint8_t cmd = ESDM_EGD_CMD_READ_BLOCK;
	uint8_t len = 16;
	uint8_t buf[16];
	int fd;

	printf("EGD raw: command split across two writes\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_send(fd, &cmd, sizeof(cmd)) == 0,
	      "the command byte could not be sent");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the server answered a command whose length byte it had not seen");

	CHECK(test_send(fd, &len, sizeof(len)) == 0,
	      "the length byte could not be sent");
	CHECK(test_recv(fd, buf, sizeof(buf), TEST_RESPONSE_MS) == 0,
	      "the completed command was not answered");
	CHECK(!test_all_zero(buf, sizeof(buf)),
	      "the answer is nothing but zeroes");

	close(fd);
}

/*
 * The protocol has no way to report an error, and an unknown command means the
 * stream is out of sync - the client has to be dropped rather than answered.
 */
static void test_unknown_command(void)
{
	uint8_t cmd = 0xff;
	uint8_t buf[1];
	int fd;

	printf("EGD raw: unknown command\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_send(fd, &cmd, sizeof(cmd)) == 0,
	      "the unknown command could not be sent");
	CHECK(test_recv(fd, buf, sizeof(buf), TEST_RESPONSE_MS) == -EPIPE,
	      "an unknown command did not close the connection");

	close(fd);
}

/*
 * A client that keeps asking without ever reading the answers.
 *
 * Its socket buffer fills up, and the responses the server has for it stop
 * going out. That must cost it nothing but its own progress: the server has to
 * keep the undelivered response, stop reading the commands behind it - the
 * backpressure that bounds what it holds per connection - and go on serving
 * everybody else without a pause.
 */
static void test_unread_responses(void)
{
	/*
	 * One command of two bytes is answered with up to 256, so a few
	 * thousand of them are far more than a socket buffer holds. The writes
	 * stop at the first that would block, which is where the client's own
	 * end is congested as well.
	 */
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_NONBLOCK, ESDM_EGD_MAX_TRANSFER };
	unsigned int sent = 0, i;
	uint32_t bits = 0;
	pid_t pid = 0;
	int slow, other;

	printf("EGD raw: a client that does not read its responses\n");

	slow = test_connect();
	if (slow < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	if (fcntl(slow, F_SETFL, fcntl(slow, F_GETFL) | O_NONBLOCK) < 0) {
		CHECK(0, "the client cannot be set non-blocking: %s",
		      strerror(errno));
		close(slow);
		return;
	}

	for (i = 0; i < 8192; i++) {
		ssize_t rc = send(slow, cmd, sizeof(cmd), MSG_NOSIGNAL);

		if (rc == (ssize_t)sizeof(cmd)) {
			sent++;
			continue;
		}
		if (rc < 0 && errno == EINTR)
			continue;

		/*
		 * Congested in both directions - which is the point. Anything
		 * else means the server gave up on a client that is merely
		 * slow, so do not let it pass silently.
		 */
		CHECK(rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
		      "the server dropped a client that does not read: %s",
		      (rc < 0) ? strerror(errno) : "short write");
		break;
	}
	printf("  %u requests sent without reading a single answer\n", sent);

	/* And now the client that behaves. */
	other = test_connect();
	CHECK(other >= 0, "a client was not accepted while another one is stuck");
	if (other >= 0) {
		CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) ==
			      0,
		      "the entropy count was not answered while a client is stuck");
		CHECK(test_cmd_pid(other, &pid, TEST_RESPONSE_MS) == 0,
		      "the PID request was not answered while a client is stuck");
		close(other);
	}

	/*
	 * The stuck client is still a client: once it reads, its answers are
	 * there, in the order it asked for them.
	 */
	{
		uint8_t delivered = 0;
		uint8_t buf[ESDM_EGD_MAX_TRANSFER];

		/*
		 * The length byte cannot exceed what was asked for: the request
		 * was for the largest transfer the byte can express.
		 */
		CHECK(test_recv(slow, &delivered, sizeof(delivered),
				TEST_RESPONSE_MS) == 0,
		      "the stuck client got nothing at all");
		if (delivered) {
			CHECK(test_recv(slow, buf, delivered,
					TEST_RESPONSE_MS) == 0,
			      "the answer of the stuck client is truncated");
		}
	}

	close(slow);
}

/*
 * A client that asks and is gone before it is answered.
 *
 * The request is in the server's socket buffer and is served, but the peer it
 * is served to no longer exists. Writing to it is an EPIPE the server has to
 * take as the end of that one connection - and nothing more. Raising SIGPIPE
 * over it would, with the disposition a daemon has unless it says otherwise,
 * terminate the entire ESDM: an interface no one is obliged to use would then
 * be able to take down the entropy supply of the whole system.
 */
static void test_vanishing_client(void)
{
	/*
	 * More connections than the server takes events for in one round, so
	 * that the ones it does not get an event for are the ones it retries the
	 * delivery of - into a peer that is gone by then. A client closing while
	 * a response is on its way to it is otherwise reported as a hangup and
	 * the connection is dropped before anything is written to it, which is
	 * exactly the ordering this has to get out of the way to reach the
	 * write.
	 */
#define TEST_VANISHING_CLIENTS 96
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_NONBLOCK, ESDM_EGD_MAX_TRANSFER };
	int fds[TEST_VANISHING_CLIENTS];
	uint32_t bits = 0;
	unsigned int i, j;
	int other;

	printf("EGD raw: clients that vanish before their answer\n");

	for (i = 0; i < TEST_VANISHING_CLIENTS; i++) {
		fds[i] = test_connect();
		if (fds[i] < 0) {
			CHECK(0, "cannot connect to %s: %s", sockpath,
			      strerror(errno));
			while (i--)
				close(fds[i]);
			return;
		}

		if (fcntl(fds[i], F_SETFL,
			  fcntl(fds[i], F_GETFL) | O_NONBLOCK) < 0) {
			CHECK(0, "a client cannot be set non-blocking: %s",
			      strerror(errno));
			do {
				close(fds[i]);
			} while (i--);
			return;
		}
	}

	/*
	 * Ask on every one of them without reading, until each has a response
	 * the server could not deliver. Round robin rather than one connection
	 * after the other: the server works on them in the same interleaved way,
	 * so this is over in a fraction of the rounds.
	 */
	for (j = 0; j < 4096; j++) {
		bool congested = true;

		for (i = 0; i < TEST_VANISHING_CLIENTS; i++) {
			if (send(fds[i], cmd, sizeof(cmd), MSG_NOSIGNAL) ==
			    (ssize_t)sizeof(cmd))
				congested = false;
		}

		if (congested)
			break;
	}

	/* And now they are all gone at once. */
	for (i = 0; i < TEST_VANISHING_CLIENTS; i++)
		close(fds[i]);

	/* Give the server the chance to write into every one of them. */
	test_sleep_ms(500);

	CHECK(!test_sigpipe,
	      "answering a client that went away raised SIGPIPE in the server");

	other = test_connect();
	CHECK(other >= 0, "the server stopped accepting clients");
	if (other >= 0) {
		CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) ==
			      0,
		      "the server stopped serving after its clients went away");
		close(other);
	}
#undef TEST_VANISHING_CLIENTS
}

/*
 * The insertion command has no response of its own, so what shows that the
 * server consumed exactly its bytes is the answer to the command behind it.
 */
static void test_write_entropy(void)
{
	uint8_t data[ESDM_EGD_MAX_TRANSFER];
	uint32_t bits = 0;
	unsigned int i;
	int fd;

	printf("EGD raw: entropy insertion\n");

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)i;

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_write_entropy(fd, data, sizeof(data),
				     8 * sizeof(data)) == 0,
	      "the insertion could not be sent");
	CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
	      "the server lost the stream over an insertion");

	/* A claim of zero bits is legitimate and equally answerless. */
	CHECK(test_cmd_write_entropy(fd, data, sizeof(data), 0) == 0,
	      "the insertion without a claim could not be sent");
	CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
	      "the server lost the stream over an insertion without a claim");

	close(fd);
}

/* Reads of the largest transfer the protocol can express. */
static void test_max_transfer(void)
{
	uint8_t buf[ESDM_EGD_MAX_TRANSFER];
	uint8_t delivered = 0;
	int fd;

	printf("EGD raw: maximum sized transfers\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	memset(buf, 0, sizeof(buf));
	CHECK(test_send_read_block(fd, ESDM_EGD_MAX_TRANSFER) == 0,
	      "the blocking read could not be sent");
	CHECK(test_recv(fd, buf, sizeof(buf), TEST_RESPONSE_MS) == 0,
	      "the blocking read of %u bytes was not answered",
	      ESDM_EGD_MAX_TRANSFER);
	CHECK(!test_all_zero(buf, sizeof(buf)),
	      "the blocking read delivered nothing but zeroes");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the blocking read delivered more than the requested bytes");

	memset(buf, 0, sizeof(buf));
	CHECK(test_cmd_read_nonblock(fd, ESDM_EGD_MAX_TRANSFER, buf, &delivered,
				     TEST_RESPONSE_MS) == 0,
	      "the non-blocking read of %u bytes was not answered",
	      ESDM_EGD_MAX_TRANSFER);
	printf("  %u of %u bytes delivered right away\n", delivered,
	       ESDM_EGD_MAX_TRANSFER);

	close(fd);
}

/*
 * The blocking read against an ESDM that has nothing to answer it with.
 *
 * This is the one exchange whose behaviour cannot be observed against a running
 * daemon: it has long been operational by the time anybody can connect to it.
 */
static void test_deferred_read(void)
{
	uint8_t buf[32];
	uint8_t delivered = 0;
	uint32_t bits = 0;
	pid_t pid = 0;
	int fd = -1, other = -1;

	printf("EGD raw: blocking read across the operational state\n");

	if (esdm_state_operational()) {
		printf("  SKIPPED: the ESDM is operational despite every entropy source being disabled\n");
		return;
	}

	fd = test_connect();
	other = test_connect();
	if (fd < 0 || other < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		goto out;
	}

	/*
	 * The non-blocking command is what a client uses to find out that there
	 * is nothing to be had - it says so with a delivery of zero bytes
	 * rather than by waiting.
	 */
	CHECK(test_cmd_read_nonblock(fd, sizeof(buf), buf, &delivered,
				     TEST_RESPONSE_MS) == 0,
	      "the non-blocking read was not answered while the ESDM had no entropy");
	CHECK(delivered == 0,
	      "%u bytes were delivered by an ESDM that is not operational",
	      delivered);

	/* Now the request that has to wait. */
	CHECK(test_send_read_block(fd, sizeof(buf)) == 0,
	      "the blocking read could not be sent");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the blocking read was answered by an ESDM that is not operational");

	/*
	 * A command sent behind the waiting one must not overtake it: its
	 * response would be read as the answer to the blocking read.
	 */
	CHECK(test_send(fd, &(uint8_t){ ESDM_EGD_CMD_GET_PID }, 1) == 0,
	      "the pipelined PID request could not be sent");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "a command behind the waiting one was answered first");

	/*
	 * Waiting for entropy must not be blocking: everybody else has to be
	 * served meanwhile, including on a connection that did not even exist
	 * when the waiting request arrived.
	 */
	CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) == 0,
	      "another client was not served while a request was waiting");
	CHECK(test_cmd_pid(other, &pid, TEST_RESPONSE_MS) == 0,
	      "another client was not served while a request was waiting");
	close(other);
	other = test_connect();
	CHECK(other >= 0,
	      "a new client was not accepted while a request was waiting");
	if (other >= 0) {
		CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) ==
			      0,
		      "a new client was not served while a request was waiting");
	}

	/* The entropy the waiting request is waiting for. */
	printf("  seeding the ESDM\n");
	if (test_esdm_seed()) {
		CHECK(0, "the ESDM did not become operational");
		goto out;
	}

	memset(buf, 0, sizeof(buf));
	CHECK(test_recv(fd, buf, sizeof(buf), TEST_RESPONSE_MS) == 0,
	      "the waiting request was not served after the ESDM became operational");
	CHECK(!test_all_zero(buf, sizeof(buf)),
	      "the waiting request was served with nothing but zeroes");

	/* And only now the command that was sent behind it. */
	{
		uint8_t len = 0;
		char pidstr[UINT8_MAX + 1];

		CHECK(test_recv(fd, &len, sizeof(len), TEST_RESPONSE_MS) == 0,
		      "the command behind the waiting one was never answered");
		/* pidstr is sized for the longest length the byte can express. */
		if (len > 0) {
			CHECK(test_recv(fd, pidstr, len, TEST_RESPONSE_MS) == 0,
			      "the answer behind the waiting one is truncated");
			pidstr[len] = '\0';
			CHECK((pid_t)strtol(pidstr, NULL, 10) == getpid(),
			      "the answer behind the waiting one is %s, not the PID",
			      pidstr);
		} else {
			CHECK(0, "the answer behind the waiting one is empty");
		}
	}

out:
	if (fd >= 0)
		close(fd);
	if (other >= 0)
		close(other);
}

int main(int argc, char *argv[])
{
	struct stat sb;
	int rc;

	(void)argc;
	(void)argv;

	/*
	 * Unbuffered: the watchdog and the harness timeout both kill this
	 * process outright, and how far it got must not die with it in a buffer.
	 */
	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	/*
	 * Record SIGPIPE rather than ignoring it: the server runs in this
	 * process, so one it raises is one this test has to report - see
	 * test_vanishing_client(). Handling it also keeps the signal from
	 * killing the run, which matters because the test's own client side
	 * talks to connections the server drops on purpose.
	 */
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = test_sigpipe_handler;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGPIPE, &sa, NULL) < 0) {
			printf("Cannot install the SIGPIPE handler: %s\n",
			       strerror(errno));
			return 1;
		}
	}

	esdm_logger_set_verbosity(LOGGER_WARN);

	/*
	 * Before esdm_init(): the rates decide what the initial seeding of the
	 * ESDM is allowed to collect.
	 */
	test_esdm_disable_es();

	rc = esdm_init();
	if (rc) {
		printf("esdm_init() failed: %d\n", rc);
		return 1;
	}

	/* Same setup as the RPC server, which is what starts the EGD worker. */
	rc = thread_init(1);
	if (rc) {
		printf("thread_init() failed: %d\n", rc);
		esdm_fini();
		return 1;
	}

	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		esdm_fini();
		return 1;
	}
	snprintf(sockpath, sizeof(sockpath), "%s/egd.sock", tmpdir);

	if (esdm_egd_server_enable(sockpath) ||
	    esdm_egd_server_socket_init() || esdm_egd_server_start()) {
		printf("Cannot serve the EGD socket %s\n", sockpath);
		ret = 1;
		goto out;
	}

	if (stat(sockpath, &sb) < 0 || !S_ISSOCK(sb.st_mode)) {
		printf("The EGD socket %s was not created\n", sockpath);
		ret = 1;
		goto out;
	}

	/*
	 * The deferral first: it is the only test that needs an ESDM without
	 * entropy, and it is what makes one available to those below.
	 */
	test_deferred_read();

	test_stateless_commands();
	test_pipelining();
	test_split_command();
	test_write_entropy();
	test_max_transfer();
	test_unread_responses();
	test_vanishing_client();
	test_unknown_command();

	/* Nothing anywhere above may have signalled the process. */
	CHECK(!test_sigpipe, "the server raised SIGPIPE");

out:
	esdm_egd_server_fini();
	esdm_egd_server_cleanup();
	esdm_fini();
	rmdir(tmpdir);

	printf("EGD raw protocol: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
