/*
 * Fuzz harness: the EGD client library
 *
 * The counterpart of egd_fuzz.c on the other side of the same socket. A
 * consumer linking libesdm_egd_client - libgcrypt's rndegd backend and
 * OpenSSL's RAND_egd() are served this way - hands its buffers to a library
 * that fills them from bytes it read off a Unix domain socket, and the
 * protocol carries no request identifiers, no length prefix over a message and
 * no error response. What a caller is given is therefore decided entirely by
 * bytes somebody else wrote: a length byte says how much random data follows,
 * another says how long the PID string is, and both are believed.
 *
 * Those bytes are the input here. The harness is the server the client
 * connects to, and it answers with whatever the fuzzer produced rather than
 * with the protocol: an input is a script of client calls followed by the
 * stream the impostor sends back, cut into the reads it arrives in. The peer
 * of tests/egd is not reused for this - it serves the protocol correctly with
 * a menu of canned deviations from it, which is what a test wants and the
 * opposite of what a fuzzer needs.
 *
 * Beyond crashes the harness holds the client to what its header promises:
 * nothing may be written behind the buffer a call was given, no call may
 * report more bytes than it was asked for, text handed back has to end inside
 * the buffer, and a failed transfer has to leave the buffer cleansed - a
 * partial answer that stays behind is one a caller cannot tell from a complete
 * one, which for a seed consumer is the whole difference.
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

#include <errno.h>
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

#include "esdm_egd_client.h"
#include "esdm_egd_protocol.h"
#include "esdm_logger.h"
#include "fuzz.h"

/* Largest buffer a call is given, and the guard behind it. */
#define FUZZ_BUF_MAX 1024
#define FUZZ_GUARD 64
#define FUZZ_GUARD_BYTE 0x5a

/* Calls of an input, so one input cannot run for arbitrarily long */
#define FUZZ_MAX_CALLS 16

/* What one step of a call is given: the connect, and every transfer. */
#define FUZZ_TIMEOUT_MS 20

/* How long the impostor waits for a connection. */
#define FUZZ_ACCEPT_POLL_MS 1

/* Bound on one write of the impostor, so a record is one read of the client */
#define FUZZ_RECORD_MAX ESDM_EGD_MAX_CMD_SIZE

static uint64_t fuzz_area[(FUZZ_BUF_MAX + FUZZ_GUARD) / sizeof(uint64_t)];

/* The socket the client connects to, and the impostor behind it */
static char fuzz_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static int fuzz_listen_fd = -1;
static pthread_t fuzz_impostor;
static bool fuzz_impostor_running;

/* The stream the impostor answers with, and how far it has been played out. */
static const uint8_t *fuzz_stream;
static size_t fuzz_stream_len;
static size_t fuzz_stream_pos;

/* Set by the main thread when its calls are done, so the impostor may leave */
static volatile bool fuzz_impostor_stop;

struct fuzz_input {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

static uint8_t fuzz_u8(struct fuzz_input *in)
{
	return (in->pos < in->len) ? in->data[in->pos++] : 0;
}

static uint32_t fuzz_u32(struct fuzz_input *in)
{
	uint32_t val = 0;
	unsigned int i;

	for (i = 0; i < 4; i++)
		val = (val << 8) | fuzz_u8(in);

	return val;
}

static size_t fuzz_len(struct fuzz_input *in, size_t max)
{
	size_t val = ((size_t)fuzz_u8(in) << 8) | fuzz_u8(in);

	return (val % (max + 1));
}

static uint8_t *fuzz_buf(size_t len)
{
	uint8_t *buf = (uint8_t *)fuzz_area;

	memset(buf, 0, len);
	memset(buf + len, FUZZ_GUARD_BYTE, FUZZ_GUARD);

	return buf;
}

/* Nothing may be written behind the buffer the call was given */
static void fuzz_check_guard(const char *call, size_t len)
{
	const uint8_t *buf = (const uint8_t *)fuzz_area;
	unsigned int i;

	for (i = 0; i < FUZZ_GUARD; i++) {
		if (buf[len + i] == FUZZ_GUARD_BYTE)
			continue;

		fprintf(stderr,
			"%s wrote %u byte(s) behind the buffer of %zu it was given\n",
			call, FUZZ_GUARD - i, len);
		abort();
	}
}

/*
 * A failed transfer has to leave nothing behind that could pass for the answer
 * it did not get.
 */
static void fuzz_check_cleansed(const char *call, size_t len, int ret)
{
	const uint8_t *buf = (const uint8_t *)fuzz_area;
	size_t i;

	fuzz_check_guard(call, len);

	if (!ret)
		return;

	for (i = 0; i < len; i++) {
		if (!buf[i])
			continue;

		fprintf(stderr,
			"%s failed with %d and left %zu byte(s) of a partial answer behind\n",
			call, ret, len - i);
		abort();
	}
}

/******************************************************************************
 * The impostor on the other end of the socket
 ******************************************************************************/

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

/* Play the stream out on one connection. */
static void fuzz_serve_conn(int fd)
{
	while (!fuzz_impostor_stop) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT };
		static uint8_t sink[FUZZ_RECORD_MAX];
		const uint8_t *rec = NULL;
		size_t len = fuzz_next_record(&rec);
		ssize_t written;

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

		written = write(fd, rec, len);
		if (written <= 0)
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

static void fuzz_impostor_start(const uint8_t *stream, size_t len)
{
	fuzz_stream = stream;
	fuzz_stream_len = len;
	fuzz_stream_pos = 0;
	fuzz_impostor_stop = false;

	if (pthread_create(&fuzz_impostor, NULL, fuzz_serve, NULL)) {
		fprintf(stderr, "cannot start the impostor\n");
		exit(1);
	}

	fuzz_impostor_running = true;
}

static void fuzz_impostor_join(void)
{
	if (!fuzz_impostor_running)
		return;

	fuzz_impostor_stop = true;
	pthread_join(fuzz_impostor, NULL);
	fuzz_impostor_running = false;
}

/******************************************************************************
 * The calls an input can pick from
 ******************************************************************************/

enum fuzz_call {
	fuzz_call_get_random,
	fuzz_call_get_random_nonblock,
	fuzz_call_entropy_count,
	fuzz_call_write_entropy,
	fuzz_call_get_pid,
	fuzz_call_socket_path,
	fuzz_calls
};

static void fuzz_one_call(struct esdm_egd_client *client,
			  struct fuzz_input *in)
{
	uint8_t *buf;
	size_t len;
	int ret;

	switch ((enum fuzz_call)(fuzz_u8(in) % fuzz_calls)) {
	case fuzz_call_get_random:
		/*
		 * The call splitting a request into protocol transfers: what
		 * it hands back is assembled from several answers, so a length
		 * the impostor made up is believed once per transfer.
		 */
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_egd_client_get_random(client, buf, len);
		fuzz_check_cleansed("esdm_egd_client_get_random", len, ret);
		break;

	case fuzz_call_get_random_nonblock: {
		size_t generated = SIZE_MAX;

		/*
		 * At most one transfer, and one byte beyond it - which the
		 * client has to refuse rather than send a length that does not
		 * fit into the byte carrying it.
		 */
		len = fuzz_len(in, ESDM_EGD_MAX_TRANSFER + 1);
		buf = fuzz_buf(len);
		ret = esdm_egd_client_get_random_nonblock(client, buf, len,
							  &generated);
		fuzz_check_cleansed("esdm_egd_client_get_random_nonblock", len,
				    ret);

		if (!ret && generated > len) {
			fprintf(stderr,
				"esdm_egd_client_get_random_nonblock reports %zu bytes in a buffer of %zu\n",
				generated, len);
			abort();
		}
		break;
	}

	case fuzz_call_entropy_count: {
		static volatile uint32_t sink;
		uint32_t bits = 0;

		esdm_egd_client_entropy_count(client, &bits);
		sink = bits;
		(void)sink;
		break;
	}

	case fuzz_call_write_entropy:
		/*
		 * The one call carrying bytes the fuzzer chose in the other
		 * direction.
		 */
		len = fuzz_len(in, ESDM_EGD_MAX_TRANSFER + 1);
		buf = fuzz_buf(len);
		if (len) {
			size_t avail = in->len - in->pos;
			size_t take = (avail < len) ? avail : len;

			memcpy(buf, in->data + in->pos, take);
			in->pos += take;
		}
		esdm_egd_client_write_entropy(client, buf, len, fuzz_u32(in));
		fuzz_check_guard("esdm_egd_client_write_entropy", len);
		break;

	case fuzz_call_get_pid: {
		/*
		 * The one answer that is text: a length byte and that many
		 * characters, which are not terminated on the wire and are run
		 * through strtol() once they are.
		 */
		pid_t pid = 0;

		ret = esdm_egd_client_get_pid(client, &pid);
		if (!ret && pid <= 0) {
			fprintf(stderr,
				"esdm_egd_client_get_pid succeeded with pid %lld\n",
				(long long)pid);
			abort();
		}
		break;
	}

	case fuzz_call_socket_path: {
		static volatile size_t sink;
		const char *path = esdm_egd_client_socket_path(client);

		/* Owned by the client, so it is there and it is a string */
		if (!path) {
			fprintf(stderr,
				"esdm_egd_client_socket_path returned nothing\n");
			abort();
		}
		sink = strlen(path);
		(void)sink;
		break;
	}

	case fuzz_calls:
	default:
		break;
	}
}

/******************************************************************************
 * Driver
 ******************************************************************************/

/* The socket is this process', so it goes with it */
static void fuzz_cleanup_socket(void)
{
	if (fuzz_socket_path[0])
		unlink(fuzz_socket_path);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct sockaddr_un addr;
	const char *tmp = getenv("TMPDIR");

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(getenv("ESDM_FUZZ_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	/*
	 * A client that gave up on an answer closes its end while the impostor
	 * still has records to write, and a write to a socket whose peer is
	 * gone raises SIGPIPE - which by default takes the process down with no
	 * message at all, looking exactly like a crash the harness found.
	 */
	signal(SIGPIPE, SIG_IGN);

	/*
	 * A path of this process, so several of these may run side by side -
	 * unlike the harness driving the RPC server, whose socket paths are
	 * fixed at build time.
	 */
	if (snprintf(fuzz_socket_path, sizeof(fuzz_socket_path),
		     "%s/esdm-egd-fuzz-%u.socket", tmp ? tmp : "/tmp",
		     (unsigned int)getpid()) >= (int)sizeof(fuzz_socket_path)) {
		fprintf(stderr, "the socket path does not fit\n");
		exit(1);
	}

	unlink(fuzz_socket_path);

	fuzz_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fuzz_listen_fd < 0) {
		fprintf(stderr, "cannot create the socket: %s\n",
			strerror(errno));
		exit(1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, fuzz_socket_path, sizeof(addr.sun_path) - 1);

	if (bind(fuzz_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(fuzz_listen_fd, 8) < 0) {
		fprintf(stderr, "cannot listen on %s: %s\n", fuzz_socket_path,
			strerror(errno));
		exit(1);
	}

	/* The socket outlives the process only when it is killed */
	atexit(fuzz_cleanup_socket);

	return 0;
}

/*
 * One input is a script of client calls and the stream the impostor answers
 * them with: byte 0 the number of script bytes that follow script the calls
 * with their arguments rest what the impostor sends back, as records - a length
 * byte and that many bytes, each record one write and thus one read the client
 * sees The script comes first and is bounded by a byte, so that a mutation of
 * the tail - which is where the answers are - leaves the calls it is answering
 * alone.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct esdm_egd_client *client = NULL;
	struct fuzz_input in;
	unsigned int calls = 0;
	size_t script_len;

	if (!size)
		return 0;

	script_len = data[0];
	if (script_len > size - 1)
		script_len = size - 1;

	in.data = data + 1;
	in.len = script_len;
	in.pos = 0;

	fuzz_impostor_start(data + 1 + script_len, size - 1 - script_len);

	/*
	 * A client per input: what it does with an answer depends on the
	 * connection it came in on, and a connection carried over from the
	 * input before it would answer this one with the tail of that one.
	 */
	if (!esdm_egd_client_alloc(&client, fuzz_socket_path,
				   FUZZ_TIMEOUT_MS)) {
		while (in.pos < in.len && calls++ < FUZZ_MAX_CALLS)
			fuzz_one_call(client, &in);

		esdm_egd_client_free(client);
	}

	fuzz_impostor_join();

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

/*
 * One well formed exchange per call, so the fuzzer starts from answers that
 * are parsed rather than rejected at their first byte, plus the answers whose
 * length byte is a lie - which is the whole of what this protocol lets a peer
 * lie about.
 */
#define FUZZ_MAX_SEEDS 13
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][512];
static size_t fuzz_num_seeds;

/* A seed: the script, then the records the impostor answers with */
static void fuzz_seed_add(const char *name, const uint8_t *script,
			  size_t script_len, const uint8_t *stream,
			  size_t stream_len)
{
	uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];

	if (fuzz_num_seeds >= FUZZ_MAX_SEEDS ||
	    1 + script_len + stream_len > sizeof(fuzz_seed_data[0]))
		return;

	seed[0] = (uint8_t)script_len;
	memcpy(seed + 1, script, script_len);
	if (stream_len)
		memcpy(seed + 1 + script_len, stream, stream_len);

	fuzz_seeds[fuzz_num_seeds].name = name;
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = 1 + script_len + stream_len;
	fuzz_num_seeds++;
}

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	/* Ask for 16 bytes: the call, then the length as two bytes */
	static const uint8_t script_read[] = { fuzz_call_get_random, 0, 16 };
	static const uint8_t script_read_split[] = { fuzz_call_get_random, 1,
						     0 };
	static const uint8_t script_nonblock[] = { fuzz_call_get_random_nonblock,
						   0, 16 };
	static const uint8_t script_count[] = { fuzz_call_entropy_count };
	static const uint8_t script_pid[] = { fuzz_call_get_pid };
	static const uint8_t script_write[] = { fuzz_call_write_entropy,
						0,
						8,
						1,
						2,
						3,
						4,
						5,
						6,
						7,
						8,
						0,
						0,
						0,
						64 };
	/* One record of 16 bytes, which is the whole of a blocking read */
	static const uint8_t stream_read[] = { 16, 0, 1, 2,  3,	 4,  5,	 6, 7,
					       8,  9, 10, 11, 12, 13, 14, 15 };
	/* The same bytes in four records, so the client reassembles them */
	static const uint8_t stream_read_split[] = { 4,	 0,  1,	 2,  3, 4, 4,
						     5,	 6,  7,	 4,  8, 9, 10,
						     11, 4,  12, 13, 14, 15 };
	/* A non-blocking read answered with a count and that many bytes */
	static const uint8_t stream_nonblock[] = { 5, 4, 0xaa, 0xbb, 0xcc,
						   0xdd };
	/* One that says it delivered more than was asked for */
	static const uint8_t stream_nonblock_overlong[] = { 1, 0xff };
	/* Four bytes of entropy count, big endian */
	static const uint8_t stream_count[] = { 4, 0x00, 0x00, 0x01, 0x00 };
	/* A PID: the length of the text, then the digits */
	static const uint8_t stream_pid[] = { 5, 4, '4', '7', '1', '1' };
	/* A PID that is not a number, which has to be refused */
	static const uint8_t stream_pid_text[] = { 5, 4, 'n', 'o', 'p', 'e' };
	/* A PID of more digits than a pid_t holds. */
	static const uint8_t stream_pid_overlong[] = {
		12, 11, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1'
	};
	/* A length announcing bytes that never come */
	static const uint8_t stream_pid_short[] = { 2, 200, 'x' };
	/* An answer that stops halfway through a transfer */
	static const uint8_t stream_read_short[] = { 8, 0, 1, 2, 3, 4, 5, 6, 7 };

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	fuzz_seed_add("read-block", script_read, sizeof(script_read),
		      stream_read, sizeof(stream_read));
	fuzz_seed_add("read-block-split", script_read, sizeof(script_read),
		      stream_read_split, sizeof(stream_read_split));
	/* A request of 256 bytes, which is two transfers of the protocol */
	fuzz_seed_add("read-block-two-transfers", script_read_split,
		      sizeof(script_read_split), stream_read,
		      sizeof(stream_read));
	fuzz_seed_add("read-block-short", script_read, sizeof(script_read),
		      stream_read_short, sizeof(stream_read_short));
	fuzz_seed_add("read-nonblock", script_nonblock, sizeof(script_nonblock),
		      stream_nonblock, sizeof(stream_nonblock));
	fuzz_seed_add("read-nonblock-overlong", script_nonblock,
		      sizeof(script_nonblock), stream_nonblock_overlong,
		      sizeof(stream_nonblock_overlong));
	fuzz_seed_add("entropy-count", script_count, sizeof(script_count),
		      stream_count, sizeof(stream_count));
	fuzz_seed_add("get-pid", script_pid, sizeof(script_pid), stream_pid,
		      sizeof(stream_pid));
	fuzz_seed_add("get-pid-not-a-number", script_pid, sizeof(script_pid),
		      stream_pid_text, sizeof(stream_pid_text));
	fuzz_seed_add("get-pid-length-beyond-answer", script_pid,
		      sizeof(script_pid), stream_pid_short,
		      sizeof(stream_pid_short));
	fuzz_seed_add("get-pid-beyond-pid-t", script_pid, sizeof(script_pid),
		      stream_pid_overlong, sizeof(stream_pid_overlong));
	fuzz_seed_add("write-entropy", script_write, sizeof(script_write), NULL,
		      0);

	*num = fuzz_num_seeds;

	return fuzz_seeds;
}
