/*
 * Fuzz harness: the request path of the RPC server
 *
 * Both RPC interfaces of the ESDM take their requests from a Unix domain
 * socket, and the unprivileged one is reachable by every user on the machine.
 * What arrives there is a length-prefixed header plus a protobuf message, i.e.
 * bytes that are parsed before anything at all is known about the sender. This
 * harness puts the fuzzer in the place of that sender.
 *
 * One input is one request: its first byte picks the interface, the rest is the
 * buffer as a read off the socket would deliver it. From there it is the
 * server's own request handling that runs - the header validation, the lookup
 * turning a method index into a message type, the protobuf decoding into the
 * arena allocator, the dispatch into the handler and the packing of the
 * response - see esdm_rpcs_fuzz_request().
 *
 * The ESDM library behind the handlers is brought up once, so a request that
 * survives the parsing is served rather than answered with "not available":
 * the arguments a decoded message carries - lengths, entropy counts, buffer
 * sizes - are as much a part of the interface as the bytes carrying them.
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
#include <stdbool.h>
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
#include "fuzz.h"
#include "helper.h"
#include "priv_access.pb-c.h"
#include "unpriv_access.pb-c.h"

/*
 * Where the responses go. A socketpair rather than /dev/null: the server asks
 * the descriptor a request came in on who is on the other end (SO_PEERCRED)
 * before it serves a privileged call, and only a socket can answer that.
 */
static int fuzz_response_fd = -1;
static int fuzz_response_peer_fd = -1;

/* Empty the response socket so it cannot fill up and stall the writes */
static void fuzz_drain_responses(void)
{
	static uint8_t sink[ESDM_RPC_MAX_MSG_SIZE];

	while (recv(fuzz_response_peer_fd, sink, sizeof(sink), MSG_DONTWAIT) >
	       0)
		;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int sockets[2];

	(void)argc;
	(void)argv;

	/*
	 * The ESDM logs every rejected request, and a fuzzer produces little
	 * else. Keep the output for the case that is being debugged.
	 */
	esdm_logger_set_verbosity(getenv("ESDM_FUZZ_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	/* The type a client connection has - see esdm_rpcs_start() */
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) < 0) {
		fprintf(stderr, "cannot create the response socket: %s\n",
			strerror(errno));
		exit(1);
	}

	fuzz_response_fd = sockets[0];
	fuzz_response_peer_fd = sockets[1];

	/*
	 * Non-blocking like an accepted connection, so a response that does
	 * not fit into the socket buffer is dropped with a timeout instead of
	 * stopping the fuzzer.
	 */
	if (set_fd_nonblocking(fuzz_response_fd) ||
	    set_fd_nonblocking(fuzz_response_peer_fd)) {
		fprintf(stderr,
			"cannot set the response socket non-blocking\n");
		exit(1);
	}

	if (esdm_init()) {
		fprintf(stderr, "cannot initialize the ESDM\n");
		exit(1);
	}

	return 0;
}

/* Frame the input as a request for one call and hand it over. */
static void fuzz_framed_request(ProtobufCService *service, bool privileged,
				uint8_t method, const uint8_t *data,
				size_t size)
{
	/* Aligned and sized like the buffer a request arrives in */
	static uint8_t buf[ESDM_RPC_MAX_MSG_SIZE]
		__attribute__((aligned(sizeof(uint64_t))));
	struct esdm_rpc_proto_cs_header header;

	if (size > ESDM_RPC_MAX_INTERNAL_MSG_SIZE)
		size = ESDM_RPC_MAX_INTERNAL_MSG_SIZE;

	header.method_index =
		le_bswap32(method % service->descriptor->n_methods);
	header.message_length = le_bswap32((uint32_t)size);
	header.request_id = le_bswap32(0);

	memcpy(buf, &header, sizeof(header));
	memcpy(buf + sizeof(header), data, size);

	esdm_rpcs_fuzz_request(service, privileged, buf, sizeof(header) + size,
			       fuzz_response_fd);
}

/*
 * One input is one request: byte 0 bit 0 the interface - unprivileged or
 * privileged bit 1 whether the harness frames the rest, see above byte 1 the
 * call, where the harness frames the request rest the request - a protobuf
 * message when framed, the buffer as it arrives off the socket when not Both
 * ways are kept because neither covers the other.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	bool privileged;
	ProtobufCService *service;

	/* The first byte picks the interface, so an empty input has none */
	if (!size)
		return 0;

	privileged = (data[0] & 1);
	service = privileged ? (ProtobufCService *)&priv_access_service :
			       (ProtobufCService *)&unpriv_access_service;

	if (data[0] & 2) {
		/* Framed - the call is picked by the byte after the flags */
		if (size < 2)
			return 0;

		fuzz_framed_request(service, privileged, data[1], data + 2,
				    size - 2);
	} else {
		esdm_rpcs_fuzz_request(service, privileged, data + 1, size - 1,
				       fuzz_response_fd);
	}

	fuzz_drain_responses();

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

/*
 * Two well formed requests per method of both interfaces, one in each of the
 * shapes above.
 */
#define FUZZ_MAX_SEEDS 64
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static char fuzz_seed_names[FUZZ_MAX_SEEDS][64];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][256];
static size_t fuzz_num_seeds;

/* One packed message, framed by the harness rather than by the seed */
static void fuzz_seed_add_framed(const ProtobufCServiceDescriptor *desc,
				 bool privileged, unsigned int method)
{
	const ProtobufCMessageDescriptor *input = desc->methods[method].input;
	uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];
	/* Holds a message, so it is aligned like one */
	uint64_t msg_mem[512 / sizeof(uint64_t)];
	ProtobufCMessage *msg = (ProtobufCMessage *)msg_mem;
	size_t packed;

	if (fuzz_num_seeds >= FUZZ_MAX_SEEDS)
		return;
	if (input->sizeof_message > sizeof(msg_mem))
		return;

	protobuf_c_message_init(input, msg);
	packed = protobuf_c_message_get_packed_size(msg);

	if (2 + packed > sizeof(fuzz_seed_data[0]))
		return;

	seed[0] = (privileged ? 1 : 0) | 2;
	seed[1] = (uint8_t)method;
	protobuf_c_message_pack(msg, seed + 2);

	snprintf(fuzz_seed_names[fuzz_num_seeds], sizeof(fuzz_seed_names[0]),
		 "%s-%s-framed", privileged ? "priv" : "unpriv",
		 desc->methods[method].name);

	fuzz_seeds[fuzz_num_seeds].name = fuzz_seed_names[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = 2 + packed;
	fuzz_num_seeds++;
}

/* Frame one packed message the way a client sends it */
static void fuzz_seed_add(const ProtobufCServiceDescriptor *desc,
			  bool privileged, unsigned int method)
{
	const ProtobufCMessageDescriptor *input = desc->methods[method].input;
	struct esdm_rpc_proto_cs_header header;
	uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];
	/* Holds a message, so it is aligned like one */
	uint64_t msg_mem[512 / sizeof(uint64_t)];
	ProtobufCMessage *msg = (ProtobufCMessage *)msg_mem;
	size_t packed;

	if (fuzz_num_seeds >= FUZZ_MAX_SEEDS)
		return;
	if (input->sizeof_message > sizeof(msg_mem))
		return;

	protobuf_c_message_init(input, msg);
	packed = protobuf_c_message_get_packed_size(msg);

	if (1 + sizeof(header) + packed > sizeof(fuzz_seed_data[0]))
		return;

	header.method_index = le_bswap32(method);
	header.message_length = le_bswap32((uint32_t)packed);
	header.request_id = le_bswap32(fuzz_num_seeds);

	/* The interface selector, then the buffer as it goes over the wire */
	seed[0] = privileged ? 1 : 0;
	memcpy(seed + 1, &header, sizeof(header));
	protobuf_c_message_pack(msg, seed + 1 + sizeof(header));

	snprintf(fuzz_seed_names[fuzz_num_seeds], sizeof(fuzz_seed_names[0]),
		 "%s-%s", privileged ? "priv" : "unpriv",
		 desc->methods[method].name);

	fuzz_seeds[fuzz_num_seeds].name = fuzz_seed_names[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = 1 + sizeof(header) + packed;
	fuzz_num_seeds++;
}

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	const ProtobufCServiceDescriptor *services[] = {
		&unpriv_access__descriptor,
		&priv_access__descriptor,
	};
	unsigned int i, method;

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	for (i = 0; i < ARRAY_SIZE(services); i++) {
		for (method = 0; method < services[i]->n_methods; method++) {
			fuzz_seed_add_framed(services[i], i == 1, method);
			fuzz_seed_add(services[i], i == 1, method);
		}
	}

	*num = fuzz_num_seeds;

	return fuzz_seeds;
}
