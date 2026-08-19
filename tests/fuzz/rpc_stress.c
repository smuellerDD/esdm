/*
 * Stress test: the RPC request path under concurrent load
 *
 * The fuzz harnesses next to this file drive the server one request at a time.
 * A server does not work that way: its worker threads serve their connections
 * at the same time, through one request handling that keeps the request of the
 * thread running it in a buffer of its own, and hands whatever it decodes to
 * handlers that reach into the DRNGs and the entropy pool every other thread
 * is using as well.
 *
 * This runs that: several threads, each with its own response socket, each
 * sending requests across both interfaces and every call they offer, valid
 * messages interleaved with garbage. Every valid request carries a request ID
 * that belongs to the thread that sent it, and the answer has to carry it back
 * - the server echoes the ID of the request it served, so an answer arriving
 * with somebody else's is a request that got mixed up on the way, which is
 * what a buffer shared between the threads would look like.
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
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "conv_be_le.h"
#include "esdm.h"
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "math_helper.h"
#include "priv_access.pb-c.h"
#include "unpriv_access.pb-c.h"
#include "xoshiro_prng.h"

/* Threads sending at the same time, and requests each of them sends. */
#define STRESS_THREADS 8
#define STRESS_REQUESTS 20000

/* No more than this many threads, whatever the environment asks for */
#define STRESS_THREADS_MAX 256

/* Every fourth request carries garbage instead of a message */
#define STRESS_GARBAGE_EVERY 4

/* Largest garbage body - beyond the header, well inside what is accepted */
#define STRESS_GARBAGE_MAX 64

/*
 * Largest value written into a numeric field of a request, and largest buffer
 * written into one carrying bytes.
 */
#define STRESS_FIELD_MAX 1024
#define STRESS_BYTES_MAX 256

static unsigned long stress_threads = STRESS_THREADS;
static unsigned long stress_requests = STRESS_REQUESTS;

/* An unsigned number from the environment, the default if there is none */
static unsigned long stress_env(const char *name, unsigned long fallback,
				unsigned long max)
{
	const char *val = getenv(name);
	char *end;
	unsigned long num;

	if (!val || !*val)
		return fallback;

	num = strtoul(val, &end, 10);
	if (*end || !num || num > max) {
		printf("%s=%s ignored, staying at %lu\n", name, val, fallback);
		return fallback;
	}

	return num;
}

struct stress_thread {
	pthread_t thread;
	uint32_t id;
	struct xoshiro_state prng;
	/* The server writes the answers here, the thread reads them there */
	int server_fd;
	int client_fd;
	unsigned long sent;
	unsigned long answered;
	unsigned long mismatched;
	unsigned long unanswered;
	bool failed;
};

/* Fill in the fields of a request with values of the harness' choosing. */
static void stress_fill(const ProtobufCMessageDescriptor *desc,
			ProtobufCMessage *msg, struct xoshiro_state *prng,
			char *scratch, size_t scratch_len)
{
	unsigned int i;

	protobuf_c_message_init(desc, msg);

	for (i = 0; i < desc->n_fields; i++) {
		const ProtobufCFieldDescriptor *field = &desc->fields[i];
		void *member = (uint8_t *)msg + field->offset;
		uint64_t val;

		/* One value at a time - repeated fields are none of these */
		if (field->label == PROTOBUF_C_LABEL_REPEATED)
			continue;

		val = xoshiro_generate_interval(prng, 0, STRESS_FIELD_MAX);

		switch (field->type) {
		case PROTOBUF_C_TYPE_INT32:
		case PROTOBUF_C_TYPE_SINT32:
		case PROTOBUF_C_TYPE_SFIXED32:
		case PROTOBUF_C_TYPE_ENUM:
			*(int32_t *)member = (int32_t)val;
			break;
		case PROTOBUF_C_TYPE_UINT32:
		case PROTOBUF_C_TYPE_FIXED32:
			*(uint32_t *)member = (uint32_t)val;
			break;
		case PROTOBUF_C_TYPE_INT64:
		case PROTOBUF_C_TYPE_SINT64:
		case PROTOBUF_C_TYPE_SFIXED64:
			*(int64_t *)member = (int64_t)val;
			break;
		case PROTOBUF_C_TYPE_UINT64:
		case PROTOBUF_C_TYPE_FIXED64:
			*(uint64_t *)member = val;
			break;
		case PROTOBUF_C_TYPE_BOOL:
			*(protobuf_c_boolean *)member = (val & 1);
			break;
		case PROTOBUF_C_TYPE_BYTES: {
			ProtobufCBinaryData *data = member;
			size_t len = (size_t)xoshiro_generate_interval(
				prng, 1,
				(uint64_t)min_size(STRESS_BYTES_MAX,
						   scratch_len - 1));

			memset(scratch, (int)(val & 0xff), len);
			data->len = len;
			data->data = (uint8_t *)scratch;
			break;
		}
		case PROTOBUF_C_TYPE_STRING: {
			size_t len = (size_t)xoshiro_generate_interval(
				prng, 1,
				(uint64_t)min_size(STRESS_BYTES_MAX,
						   scratch_len - 1));

			memset(scratch, 'a' + (int)(val % 26), len);
			scratch[len] = '\0';
			*(char **)member = scratch;
			break;
		}
		case PROTOBUF_C_TYPE_FLOAT:
		case PROTOBUF_C_TYPE_DOUBLE:
		case PROTOBUF_C_TYPE_MESSAGE:
		default:
			/* None of these are part of this protocol */
			break;
		}
	}
}

/* The request ID of the @seq'th request of thread @id, unique across both */
static uint32_t stress_request_id(uint32_t id, unsigned long seq)
{
	return (id << 24) | (uint32_t)(seq & 0xffffff);
}

/* Take everything the socket holds, so an answer cannot be an old one */
static void stress_drain(struct stress_thread *st)
{
	static __thread uint8_t sink[ESDM_RPC_MAX_MSG_SIZE];

	while (recv(st->client_fd, sink, sizeof(sink), MSG_DONTWAIT) > 0)
		;
}

/*
 * Send one request and, where an answer is due, check that it is the answer to
 * this request rather than to one of another thread.
 */
static void stress_one(struct stress_thread *st, unsigned long seq)
{
	uint8_t buf[sizeof(struct esdm_rpc_proto_cs_header) + 1024];
	uint8_t answer[ESDM_RPC_MAX_MSG_SIZE];
	/* Holds a request, so it is aligned like one */
	uint64_t msg_mem[512 / sizeof(uint64_t)];
	ProtobufCMessage *msg = (ProtobufCMessage *)msg_mem;
	char scratch[STRESS_BYTES_MAX + 1];
	struct esdm_rpc_proto_cs_header header;
	struct esdm_rpc_proto_sc_header *reply;
	bool privileged = xoshiro_generate_interval(&st->prng, 0, 1);
	const ProtobufCServiceDescriptor *desc =
		privileged ? &priv_access__descriptor :
			     &unpriv_access__descriptor;
	ProtobufCService *service =
		privileged ? (ProtobufCService *)&priv_access_service :
			     (ProtobufCService *)&unpriv_access_service;
	uint32_t method = (uint32_t)xoshiro_generate_interval(
		&st->prng, 0, desc->n_methods - 1);
	uint32_t request_id = stress_request_id(st->id, seq);
	bool garbage = !(seq % STRESS_GARBAGE_EVERY);
	size_t body = 0;
	ssize_t received;

	if (garbage) {
		/* A body that is not the message the call expects. */
		body = (size_t)xoshiro_generate_interval(&st->prng, 1,
							 STRESS_GARBAGE_MAX);
		for (size_t i = 0; i < body; i++)
			buf[sizeof(header) + i] =
				(uint8_t)xoshiro_generate(&st->prng);
	} else {
		const ProtobufCMessageDescriptor *input =
			desc->methods[method].input;

		if (input->sizeof_message > sizeof(msg_mem))
			return;

		stress_fill(input, msg, &st->prng, scratch, sizeof(scratch));

		body = protobuf_c_message_get_packed_size(msg);
		if (sizeof(header) + body > sizeof(buf))
			return;

		protobuf_c_message_pack(msg, buf + sizeof(header));
	}

	header.method_index = le_bswap32(method);
	header.message_length = le_bswap32((uint32_t)body);
	header.request_id = le_bswap32(request_id);
	memcpy(buf, &header, sizeof(header));

	stress_drain(st);

	esdm_rpcs_fuzz_request(service, privileged, buf, sizeof(header) + body,
			       st->server_fd);
	st->sent++;

	if (garbage) {
		stress_drain(st);
		return;
	}

	/* A request the server could decode is a request it answers */
	received = recv(st->client_fd, answer, sizeof(answer), MSG_DONTWAIT);
	if (received < (ssize_t)sizeof(*reply)) {
		st->unanswered++;
		return;
	}

	reply = (struct esdm_rpc_proto_sc_header *)answer;
	if (le_bswap32(reply->request_id) != request_id) {
		printf("thread %u: answer to request %u carries request ID %u\n",
		       st->id, request_id, le_bswap32(reply->request_id));
		st->mismatched++;
		st->failed = true;
		return;
	}

	st->answered++;
}

static void *stress_run(void *priv)
{
	struct stress_thread *st = priv;
	unsigned long seq;

	for (seq = 0; seq < stress_requests; seq++)
		stress_one(st, seq);

	return NULL;
}

static int stress_thread_init(struct stress_thread *st, uint32_t id)
{
	int sockets[2];

	memset(st, 0, sizeof(*st));
	st->id = id;

	if (xoshiro_init(&st->prng)) {
		printf("cannot seed the PRNG of thread %u\n", id);
		return 1;
	}

	/* The type an accepted connection has, and its non-blocking mode */
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) < 0) {
		printf("cannot create the response socket of thread %u: %s\n",
		       id, strerror(errno));
		return 1;
	}

	st->server_fd = sockets[0];
	st->client_fd = sockets[1];

	if (set_fd_nonblocking(st->server_fd) ||
	    set_fd_nonblocking(st->client_fd)) {
		printf("cannot set the response socket of thread %u non-blocking\n",
		       id);
		return 1;
	}

	return 0;
}

static int esdm_rpc_stress_test(void)
{
	struct stress_thread threads[STRESS_THREADS_MAX];
	unsigned long sent = 0, answered = 0, mismatched = 0, unanswered = 0;
	uint32_t i;
	int ret = 0;

	stress_threads = stress_env("ESDM_STRESS_THREADS", STRESS_THREADS,
				    STRESS_THREADS_MAX);
	stress_requests = stress_env("ESDM_STRESS_REQUESTS", STRESS_REQUESTS,
				     ULONG_MAX);

	/* A fuzzer's worth of rejected requests, and none of it is news */
	esdm_logger_set_verbosity(LOGGER_NONE);

	if (esdm_init()) {
		printf("cannot initialize the ESDM\n");
		return 1;
	}

	for (i = 0; i < stress_threads; i++) {
		if (stress_thread_init(&threads[i], i)) {
			ret = 1;
			goto out;
		}
	}

	for (i = 0; i < stress_threads; i++) {
		if (pthread_create(&threads[i].thread, NULL, stress_run,
				   &threads[i])) {
			printf("cannot start thread %u\n", i);
			ret = 1;
			goto out;
		}
	}

	for (i = 0; i < stress_threads; i++) {
		pthread_join(threads[i].thread, NULL);

		sent += threads[i].sent;
		answered += threads[i].answered;
		mismatched += threads[i].mismatched;
		unanswered += threads[i].unanswered;

		close(threads[i].server_fd);
		close(threads[i].client_fd);
	}

	printf("%lu threads sent %lu requests: %lu answered, %lu without an answer, %lu answered to somebody else\n",
	       stress_threads, sent, answered, unanswered, mismatched);

	/* An answer that belongs to another request is the failure looked for */
	if (mismatched) {
		ret = 1;
		goto out;
	}

	/* Every valid request is answered. */
	if (unanswered) {
		printf("%lu valid request(s) went unanswered\n", unanswered);
		ret = 1;
		goto out;
	}

	if (!answered) {
		printf("no request was answered at all\n");
		ret = 1;
	}

out:
	esdm_fini();
	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return esdm_rpc_stress_test();
}
