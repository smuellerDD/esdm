/*
 * Fuzz harness: the response path of the RPC client
 *
 * The other direction of the RPC interface. Every process that asks the ESDM
 * for random bytes - through the library, the CUSE device files, the getrandom
 * server, the OpenSSL provider - parses what comes back off the socket, and it
 * does so before it can know anything about the peer that sent it. Whoever gets
 * to answer on that socket therefore speaks straight into the parser this
 * harness drives.
 *
 * One input is one response: its first byte picks the message type the caller
 * was waiting for, the rest is placed on a connected socket for the client to
 * read. From there it is the client's own response handling that runs - the
 * header validation, then either the hand-rolled decoder for the messages
 * carrying random bytes or the generated protobuf code - and the closure below
 * stands for what a caller does with the result, down to reading the bytes the
 * response claims to carry.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.pb-c.h"
#include "conv_be_le.h"
#include "esdm_logger.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_service.h"
#include "fuzz.h"
#include "helper.h"
#include "priv_access.pb-c.h"
#include "ptr_err.h"
#include "unpriv_access.pb-c.h"

/* The message types a caller can be waiting for. */
static const ProtobufCMessageDescriptor *const fuzz_responses[] = {
	&rand_val_response__descriptor, &val_response__descriptor,
	&status_response__descriptor,	&is_fully_seeded_response__descriptor,
	&ret_response__descriptor,	&selftest_response__descriptor,
};

/* Keeps the reads below from being optimized away */
static volatile uint64_t fuzz_sink;

/*
 * Payload bytes behind the header of the response currently being handed over.
 */
static size_t fuzz_payload_avail;

/* Report a payload the response never carried and stop */
static void fuzz_overrun(const char *what, size_t len)
{
	fprintf(stderr,
		"the client reports %zu bytes of %s from a response carrying %zu\n",
		len, what, fuzz_payload_avail);
	abort();
}

/* What a caller does with the response: read what it says it carries. */
static void fuzz_response_closure(const ProtobufCMessage *message, void *priv)
{
	uint64_t sum = 0;
	size_t i;

	(void)priv;

	/* The client reports a rejected response as an error pointer */
	if (!message || IS_ERR(message))
		return;

	if (message->descriptor == &rand_val_response__descriptor) {
		const RandValResponse *resp = (const RandValResponse *)message;

		if (resp->randval.len > fuzz_payload_avail)
			fuzz_overrun("random data", resp->randval.len);

		for (i = 0; i < resp->randval.len; i++)
			sum += resp->randval.data[i];
		sum += (uint64_t)resp->ret;
	} else if (message->descriptor == &status_response__descriptor) {
		const StatusResponse *resp = (const StatusResponse *)message;

		if (resp->buffer) {
			size_t len = strlen(resp->buffer);

			if (len > fuzz_payload_avail)
				fuzz_overrun("status text", len);

			sum += len;
		}
		sum += (uint64_t)resp->ret;
	} else if (message->descriptor == &val_response__descriptor) {
		const ValResponse *resp = (const ValResponse *)message;

		sum += resp->val;
		sum += (uint64_t)resp->ret;
	}

	fuzz_sink += sum;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(getenv("ESDM_FUZZ_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	return 0;
}

/* Frame the input as the answer to a call and hand it over. */
static void fuzz_framed_response(const ProtobufCMessageDescriptor *desc,
				 const uint8_t *data, size_t size)
{
	static uint8_t buf[ESDM_RPC_MAX_MSG_SIZE]
		__attribute__((aligned(sizeof(uint64_t))));
	struct esdm_rpc_proto_sc_header header;

	if (size > ESDM_RPC_MAX_INTERNAL_MSG_SIZE)
		size = ESDM_RPC_MAX_INTERNAL_MSG_SIZE;

	header.status_code = le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
	header.method_index = 0;
	header.message_length = le_bswap32((uint32_t)size);
	header.request_id = 0;

	memcpy(buf, &header, sizeof(header));
	memcpy(buf + sizeof(header), data, size);

	/* All of what was framed is what the response can hand over */
	fuzz_payload_avail = size;

	esdm_rpcc_fuzz_response(desc, buf, sizeof(header) + size,
				fuzz_response_closure, NULL);
}

/*
 * One input is one response: byte 0 bits 0-6 the message type the caller is
 * waiting for bit 7 whether the harness frames the rest rest the response - a
 * protobuf message when framed, the buffer as it arrives off the socket when
 * not Both ways are kept because neither covers the other: framed, every input
 * reaches a decoder and the fuzzer works on the message; raw, it works on the
 * framing, which is where the length prefix that does not match the bytes
 * behind it comes from.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const ProtobufCMessageDescriptor *desc;

	/*
	 * The first byte picks the awaited message type, and an input without
	 * a response behind it is what a client sees when the server hangs up
	 * rather than something it parses.
	 */
	if (size < 2)
		return 0;

	/*
	 * More than a message never arrives in one piece: the socket carries
	 * datagrams of at most this size, and one that does not fit is not
	 * delivered at all.
	 */
	if (size > ESDM_RPC_MAX_MSG_SIZE)
		size = ESDM_RPC_MAX_MSG_SIZE;

	desc = fuzz_responses[(data[0] & 0x7f) % ARRAY_SIZE(fuzz_responses)];

	if (data[0] & 0x80) {
		fuzz_framed_response(desc, data + 1, size - 1);
		return 0;
	}

	/* What is behind the header is all the response can hand over */
	fuzz_payload_avail =
		(size - 1 > sizeof(struct esdm_rpc_proto_sc_header)) ?
			(size - 1 - sizeof(struct esdm_rpc_proto_sc_header)) :
			0;

	esdm_rpcc_fuzz_response(desc, data + 1, size - 1, fuzz_response_closure,
				NULL);

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

/*
 * One well formed response per message type, so the fuzzer starts from headers
 * whose status code and length prefix let the message behind them be decoded at
 * all, plus the responses whose length prefix is a lie - see below.
 */
#define FUZZ_MAX_SEEDS (2 * ARRAY_SIZE(fuzz_responses) + 2)
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static char fuzz_seed_names[FUZZ_MAX_SEEDS][64];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][256];
static size_t fuzz_num_seeds;

/* A response announcing more bytes than it brought. */
static void fuzz_seed_add_short(const char *name, uint32_t message_length)
{
	/*
	 * A RandValResponse announcing a hundred bytes of random data of which
	 * ten arrive: field 2, wire type 2, then the length and the bytes.
	 */
	static const uint8_t body[] = { 0x12, 100,  0xaa, 0xaa, 0xaa, 0xaa,
					0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
	struct esdm_rpc_proto_sc_header header;
	uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];

	if (fuzz_num_seeds >= FUZZ_MAX_SEEDS)
		return;

	header.status_code = le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
	header.method_index = 0;
	header.message_length = le_bswap32(message_length);
	header.request_id = 0;

	/* A response carrying bytes - the decoder that trusts the length */
	seed[0] = 0;
	memcpy(seed + 1, &header, sizeof(header));
	memcpy(seed + 1 + sizeof(header), body, sizeof(body));

	snprintf(fuzz_seed_names[fuzz_num_seeds], sizeof(fuzz_seed_names[0]),
		 "%s", name);

	fuzz_seeds[fuzz_num_seeds].name = fuzz_seed_names[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = 1 + sizeof(header) + sizeof(body);
	fuzz_num_seeds++;
}

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	size_t i;

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	for (i = 0; i < ARRAY_SIZE(fuzz_responses); i++) {
		const ProtobufCMessageDescriptor *desc = fuzz_responses[i];
		struct esdm_rpc_proto_sc_header header;
		uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];
		/* Holds a message, so it is aligned like one */
		uint64_t msg_mem[512 / sizeof(uint64_t)];
		ProtobufCMessage *msg = (ProtobufCMessage *)msg_mem;
		size_t packed;

		if (desc->sizeof_message > sizeof(msg_mem))
			continue;

		protobuf_c_message_init(desc, msg);
		packed = protobuf_c_message_get_packed_size(msg);

		if (1 + sizeof(header) + packed > sizeof(fuzz_seed_data[0]))
			continue;

		header.status_code =
			le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
		header.method_index = 0;
		header.message_length = le_bswap32((uint32_t)packed);
		header.request_id = le_bswap32((uint32_t)i);

		seed[0] = (uint8_t)i;
		memcpy(seed + 1, &header, sizeof(header));
		protobuf_c_message_pack(msg, seed + 1 + sizeof(header));

		snprintf(fuzz_seed_names[fuzz_num_seeds],
			 sizeof(fuzz_seed_names[0]), "%s", desc->name);

		fuzz_seeds[fuzz_num_seeds].name =
			fuzz_seed_names[fuzz_num_seeds];
		fuzz_seeds[fuzz_num_seeds].data = seed;
		fuzz_seeds[fuzz_num_seeds].len = 1 + sizeof(header) + packed;
		fuzz_num_seeds++;

		/* The same message, left to the harness to frame */
		if (fuzz_num_seeds >= FUZZ_MAX_SEEDS)
			continue;

		seed = fuzz_seed_data[fuzz_num_seeds];
		seed[0] = (uint8_t)i | 0x80;
		protobuf_c_message_pack(msg, seed + 1);

		snprintf(fuzz_seed_names[fuzz_num_seeds],
			 sizeof(fuzz_seed_names[0]), "%s-framed", desc->name);

		fuzz_seeds[fuzz_num_seeds].name =
			fuzz_seed_names[fuzz_num_seeds];
		fuzz_seeds[fuzz_num_seeds].data = seed;
		fuzz_seeds[fuzz_num_seeds].len = 1 + packed;
		fuzz_num_seeds++;
	}

	fuzz_seed_add_short("length-beyond-protocol", UINT32_MAX);
	fuzz_seed_add_short("length-beyond-message",
			    ESDM_RPC_MAX_INTERNAL_MSG_SIZE);

	*num = fuzz_num_seeds;

	return fuzz_seeds;
}
