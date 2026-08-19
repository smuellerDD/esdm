/*
 * The peer of the OpenSSL EGD provider harness: an impostor on the socket
 *
 * The provider under test reaches the ESDM over the EGD protocol, which has no
 * request identifiers, no length prefix over a message and no error response.
 * What a request is answered with is therefore decided entirely by bytes
 * somebody else wrote - a length byte says how much random data follows, and
 * it is believed. Those bytes are the tail of the fuzzer's input here.
 *
 * The peer of tests/egd is not reused for this: it serves the protocol
 * correctly with a menu of canned deviations from it, which is what a test
 * wants and the opposite of what a fuzzer needs.
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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "esdm_egd_protocol.h"
#include "ossl_prov_fuzz.h"

/*
 * What one step of an exchange is given. The provider hands the client library
 * no timeout of its own, so the library's default - thirty seconds, generous
 * enough to wait for an ESDM that is still starting - is what a request that
 * goes unanswered would wait for. Nothing here ever leaves one hanging: the
 * impostor closes the connection as soon as it has nothing left to say, which
 * the client sees at once.
 */
#define FUZZ_TIMEOUT_MS 20

/* How long the impostor waits for a connection */
#define FUZZ_ACCEPT_POLL_MS 1

/* Bound on one write of the impostor, so a record is one read of the client */
#define FUZZ_RECORD_MAX ESDM_EGD_MAX_CMD_SIZE

/* The socket the provider connects to, and the impostor behind it */
static char fuzz_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static int fuzz_listen_fd = -1;
static pthread_t fuzz_impostor;
static bool fuzz_impostor_running;

/* The stream the impostor answers with, and how far it has been played out */
static const uint8_t *fuzz_stream;
static size_t fuzz_stream_len;
static size_t fuzz_stream_pos;

/* Set by the main thread when its calls are done, so the impostor may leave */
static volatile bool fuzz_impostor_stop;

/* Take the next record off the stream - a length byte and that many bytes */
static size_t fuzz_next_record(const uint8_t **rec)
{
	size_t len;

	if (fuzz_stream_pos >= fuzz_stream_len)
		return 0;

	len = fuzz_stream[fuzz_stream_pos++];
	if (len > fuzz_stream_len - fuzz_stream_pos)
		len = fuzz_stream_len - fuzz_stream_pos;
	if (len > FUZZ_RECORD_MAX)
		len = FUZZ_RECORD_MAX;

	*rec = fuzz_stream + fuzz_stream_pos;
	fuzz_stream_pos += len;

	return len;
}

/* Play the stream out on one connection */
static void fuzz_serve_conn(int fd)
{
	while (!fuzz_impostor_stop) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT };
		static uint8_t sink[FUZZ_RECORD_MAX];
		const uint8_t *rec = NULL;
		size_t len = fuzz_next_record(&rec);

		/* Nothing left to say - hang up, which the client can see */
		if (!len)
			return;

		if (poll(&pfd, 1, FUZZ_TIMEOUT_MS) <= 0)
			return;

		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			return;

		if (pfd.revents & POLLIN) {
			if (read(fd, sink, sizeof(sink)) <= 0)
				return;
		}

		if (!(pfd.revents & POLLOUT))
			continue;

		if (write(fd, rec, len) <= 0)
			return;
	}
}

static void *fuzz_serve(void *unused)
{
	(void)unused;

	while (!fuzz_impostor_stop) {
		struct pollfd pfd = { .fd = fuzz_listen_fd, .events = POLLIN };
		int fd;

		if (poll(&pfd, 1, FUZZ_ACCEPT_POLL_MS) <= 0)
			continue;

		fd = accept(fuzz_listen_fd, NULL, NULL);
		if (fd < 0)
			continue;

		fuzz_serve_conn(fd);
		close(fd);
	}

	return NULL;
}

/*
 * Connections the impostor never got to are still queued on the listening
 * socket. Left there they would fill the backlog, and a connect that finds it
 * full is retried by the client library until its timeout - thirty seconds of
 * an input that has nothing else to do.
 */
static void fuzz_drain_backlog(void)
{
	for (;;) {
		int fd = accept4(fuzz_listen_fd, NULL, NULL, SOCK_NONBLOCK);

		if (fd < 0)
			return;

		close(fd);
	}
}

/* The socket is this process', so it goes with it */
static void fuzz_cleanup_socket(void)
{
	if (fuzz_socket_path[0])
		unlink(fuzz_socket_path);
}

int fuzz_backend_init(void)
{
	struct sockaddr_un addr;
	const char *tmp = getenv("TMPDIR");

	/*
	 * A provider that gave up on an answer closes its end while the
	 * impostor still has records to write, and a write to a socket whose
	 * peer is gone raises SIGPIPE - which by default takes the process down
	 * with no message at all, looking exactly like a crash the harness
	 * found.
	 */
	signal(SIGPIPE, SIG_IGN);

	/*
	 * A path of this process, so several of these may run side by side -
	 * unlike the harnesses driving the RPC server, whose socket paths are
	 * fixed at build time.
	 */
	if (snprintf(fuzz_socket_path, sizeof(fuzz_socket_path),
		     "%s/esdm-ossl-egd-fuzz-%u.socket", tmp ? tmp : "/tmp",
		     (unsigned int)getpid()) >= (int)sizeof(fuzz_socket_path)) {
		fprintf(stderr, "the socket path does not fit\n");
		return 1;
	}

	unlink(fuzz_socket_path);

	fuzz_listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fuzz_listen_fd < 0) {
		fprintf(stderr, "cannot create the socket: %s\n",
			strerror(errno));
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, fuzz_socket_path, sizeof(addr.sun_path) - 1);

	if (bind(fuzz_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(fuzz_listen_fd, 64) < 0) {
		fprintf(stderr, "cannot listen on %s: %s\n", fuzz_socket_path,
			strerror(errno));
		return 1;
	}

	/*
	 * The provider takes the socket from its openssl.cnf section, and
	 * failing that from here - which is the only way into it that does not
	 * need a configuration file written next to the harness.
	 */
	if (setenv("ESDM_EGD_SOCKET", fuzz_socket_path, 1)) {
		fprintf(stderr, "cannot announce the socket: %s\n",
			strerror(errno));
		return 1;
	}

	/* The socket outlives the process only when it is killed */
	atexit(fuzz_cleanup_socket);

	return 0;
}

void fuzz_backend_begin(const uint8_t *data, size_t len)
{
	fuzz_stream = data;
	fuzz_stream_len = len;
	fuzz_stream_pos = 0;
	fuzz_impostor_stop = false;

	if (pthread_create(&fuzz_impostor, NULL, fuzz_serve, NULL)) {
		fprintf(stderr, "cannot start the impostor\n");
		exit(1);
	}

	fuzz_impostor_running = true;
}

void fuzz_backend_end(void)
{
	if (!fuzz_impostor_running)
		return;

	fuzz_impostor_stop = true;
	pthread_join(fuzz_impostor, NULL);
	fuzz_impostor_running = false;

	fuzz_drain_backlog();
}
