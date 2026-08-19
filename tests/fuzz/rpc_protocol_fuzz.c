/*
 * Fuzz harness: the RPC wire codec
 *
 * The narrow, fast counterpart to the two harnesses driving a whole request or
 * response: this one calls the wire format code in service-rpc/service/
 * directly, with neither an ESDM behind it nor a socket in front of it, so the
 * fuzzer spends its time in the parsers rather than in entropy collection.
 *
 * What it covers is the hand-rolled decoder and encoder for the messages
 * carrying random bytes - the ones that bypass the generated protobuf code on
 * the hot paths, and therefore the ones whose bounds checking is written here
 * rather than generated - plus the lookup that turns a method index off the
 * wire into a message type.
 *
 * Beyond crashes it checks that the two agree: whatever the decoder accepts,
 * the encoder must be able to write back, and decoding that again must yield
 * the same values. A decoder that reads a length the encoder cannot produce is
 * a bug even when nothing segfaults.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "conv_be_le.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_service.h"
#include "fuzz.h"
#include "helper.h"
#include "priv_access.pb-c.h"
#include "unpriv_access.pb-c.h"

/* What the input asks the harness to do with the bytes behind the selector */
enum fuzz_proto_mode {
	fuzz_proto_decode,
	fuzz_proto_unpack,
	fuzz_proto_unpack_framed,
	fuzz_proto_modes
};

/*
 * Decode a response the way the client does on its hot paths, and hold the
 * encoder to what came out of it.
 */
static void fuzz_bytes_response(const uint8_t *data, size_t size)
{
	static uint8_t encoded[ESDM_RPC_MAX_MSG_SIZE + 64];
	const uint8_t *payload, *payload2;
	size_t payload_len, payload2_len, encoded_len = 0;
	int64_t ret_val, ret_val2;

	if (esdm_rpc_decode_bytes_response(data, size, &ret_val, &payload,
					   &payload_len))
		return;

	/* Touch what the decoder handed out - it points into data */
	if (payload_len) {
		static volatile uint8_t sink;

		sink = payload[0];
		sink = payload[payload_len - 1];
		(void)sink;
	}

	/* An accepted message has to be one the encoder can write. */
	if (esdm_rpc_encode_bytes_response(encoded, sizeof(encoded), ret_val,
					   payload, payload_len,
					   &encoded_len)) {
		fprintf(stderr,
			"the encoder rejects a message the decoder accepted: ret %lld, payload %zu bytes\n",
			(long long)ret_val, payload_len);
		abort();
	}

	if (esdm_rpc_decode_bytes_response(encoded, encoded_len, &ret_val2,
					   &payload2, &payload2_len)) {
		fprintf(stderr,
			"the decoder rejects what the encoder wrote from it\n");
		abort();
	}

	if (ret_val != ret_val2 || payload_len != payload2_len ||
	    (payload_len && memcmp(payload, payload2, payload_len))) {
		fprintf(stderr,
			"a message changed over an encode/decode round trip\n");
		abort();
	}
}

/*
 * Turn the header of a request into a message type and decode the message
 * behind it - the two steps the server takes before it knows what it received.
 */
static void fuzz_request_unpack(const uint8_t *data, size_t size,
				bool privileged, bool framed)
{
	/* Aligned and sized like the buffer the server reads into */
	static uint8_t reqbuf[ESDM_RPC_MAX_MSG_SIZE]
		__attribute__((aligned(sizeof(uint64_t))));
	static uint8_t unpack_buf[ESDM_RPC_MAX_UNPACK_SIZE];
	struct buffer tlh = {
		.len = sizeof(unpack_buf),
		.consumed = 0,
		.buf = unpack_buf,
	};
	ProtobufCAllocator allocator = {
		.alloc = esdm_rpc_alloc,
		.free = esdm_rpc_free,
		.allocator_data = &tlh,
	};
	/*
	 * The lookup only ever asks the service for its descriptor, and the
	 * descriptor is what the request names.
	 */
	ProtobufCService service = {
		.descriptor = privileged ? &priv_access__descriptor :
					   &unpriv_access__descriptor,
		.invoke = NULL,
		.destroy = NULL,
	};
	const ProtobufCMessageDescriptor *desc;
	struct esdm_rpc_proto_cs *received;
	struct esdm_rpc_proto_cs_header *header;
	ProtobufCMessage *message;

	received = (struct esdm_rpc_proto_cs *)reqbuf;
	header = &received->header;

	if (framed) {
		uint32_t method;

		/* The byte picking the call, then the message */
		if (!size)
			return;

		method = data[0] % service.descriptor->n_methods;
		data++;
		size--;

		if (size > ESDM_RPC_MAX_INTERNAL_MSG_SIZE)
			size = ESDM_RPC_MAX_INTERNAL_MSG_SIZE;

		memcpy(reqbuf + sizeof(*header), data, size);

		header->method_index = method;
		header->message_length = (uint32_t)size;
		header->request_id = 0;

		size += sizeof(*header);
	} else {
		if (size < sizeof(*header))
			return;
		if (size > sizeof(reqbuf))
			size = sizeof(reqbuf);

		memcpy(reqbuf, data, size);

		header->method_index = le_bswap32(header->method_index);
		header->message_length = le_bswap32(header->message_length);
		header->request_id = le_bswap32(header->request_id);
	}

	/* The bounds the server insists on before it decodes anything */
	if (header->message_length > ESDM_RPC_MAX_INTERNAL_MSG_SIZE)
		return;
	if (size < sizeof(*header) + header->message_length)
		return;

	if (esdm_rpc_proto_get_descriptor(&service, received, &desc))
		return;

	message = protobuf_c_message_unpack(
		desc, &allocator, header->message_length, received->data);
	if (message)
		protobuf_c_message_free_unpacked(message, &allocator);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!size)
		return 0;

	/*
	 * The low bits of the first byte pick what the rest is taken for, the
	 * next one which interface it arrived at.
	 */
	switch (data[0] % fuzz_proto_modes) {
	case fuzz_proto_decode:
		fuzz_bytes_response(data + 1, size - 1);
		break;
	case fuzz_proto_unpack:
		fuzz_request_unpack(data + 1, size - 1, data[0] & 0x80, false);
		break;
	case fuzz_proto_unpack_framed:
		fuzz_request_unpack(data + 1, size - 1, data[0] & 0x80, true);
		break;
	default:
		break;
	}

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

#define FUZZ_MAX_SEEDS 8
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][256];
static size_t fuzz_num_seeds;

static void fuzz_seed_add(const char *name, uint8_t selector,
			  const uint8_t *data, size_t len)
{
	uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];

	if (fuzz_num_seeds >= FUZZ_MAX_SEEDS ||
	    1 + len > sizeof(fuzz_seed_data[0]))
		return;

	seed[0] = selector;
	memcpy(seed + 1, data, len);

	fuzz_seeds[fuzz_num_seeds].name = name;
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = 1 + len;
	fuzz_num_seeds++;
}

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	uint8_t msg[128];
	size_t msg_len = 0;
	const uint8_t payload[32] = { 0 };
	struct esdm_rpc_proto_cs_header header;
	uint8_t request[sizeof(header) + 8];
	GetRandomBytesRequest req = GET_RANDOM_BYTES_REQUEST__INIT;
	const ProtobufCMethodDescriptor *method;
	size_t packed;

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	/* A response carrying bytes, as the fast path writes it */
	if (!esdm_rpc_encode_bytes_response(msg, sizeof(msg), sizeof(payload),
					    payload, sizeof(payload), &msg_len))
		fuzz_seed_add("randval-response", fuzz_proto_decode, msg,
			      msg_len);

	/* And one reporting an error, which carries no bytes at all */
	msg_len = 0;
	if (!esdm_rpc_encode_bytes_response(msg, sizeof(msg), -EINVAL, NULL, 0,
					    &msg_len))
		fuzz_seed_add("error-response", fuzz_proto_decode, msg,
			      msg_len);

	/* A request for random bytes, framed the way a client sends it. */
	req.len = sizeof(payload);
	packed = get_random_bytes_request__get_packed_size(&req);
	method = protobuf_c_service_descriptor_get_method_by_name(
		&unpriv_access__descriptor, "RpcGetRandomBytes");
	if (method && sizeof(header) + packed <= sizeof(request)) {
		/* Its position in the method array is the index on the wire */
		uint32_t index =
			(uint32_t)(method - unpriv_access__descriptor.methods);

		header.method_index = le_bswap32(index);
		header.message_length = le_bswap32((uint32_t)packed);
		header.request_id = le_bswap32(1);

		memcpy(request, &header, sizeof(header));
		get_random_bytes_request__pack(&req, request + sizeof(header));

		fuzz_seed_add("get-random-bytes-request", fuzz_proto_unpack,
			      request, sizeof(header) + packed);

		/* The same request, left to the harness to frame */
		request[0] = (uint8_t)index;
		get_random_bytes_request__pack(&req, request + 1);

		fuzz_seed_add("get-random-bytes-request-framed",
			      fuzz_proto_unpack_framed, request, 1 + packed);
	}

	*num = fuzz_num_seeds;

	return fuzz_seeds;
}
