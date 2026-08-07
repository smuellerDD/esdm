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
 * Tests for the RPC wire protocol helpers in service-rpc/service/ - the parts
 * of the RPC stack that need neither a server nor a socket.
 *
 * The interesting piece is the hand-rolled encoder/decoder for the
 * RandValResponse message, which bypasses the generated protobuf code on the
 * random hot paths. Two things have to hold for that to be safe, and both are
 * asserted here:
 *
 *   - it agrees byte for byte with what protobuf-c produces and accepts, and
 *   - it rejects every malformed input instead of walking off the buffer. The
 *     decoder parses attacker-reachable bytes straight from the receive buffer,
 *     so the truncated varints, over-long varints and length prefixes pointing
 *     past the end below are the point of the exercise, not an afterthought.
 *
 * Also covered: the arena allocator protobuf-c is handed for the request
 * decoding, the descriptor lookup that turns a method index off the wire into a
 * message type, and the bounded append callback the server packs responses
 * through.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "buffer.h"
#include "common_test.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_protocol_helper.h"
#include "unpriv_access.pb-c.h"

/******************************************************************************
 * Arena allocator handed to protobuf-c
 ******************************************************************************/

static void test_rpc_alloc(void)
{
	uint8_t mem[256];
	struct buffer tlh;
	uint8_t *p, *q;

	memset(mem, 0xff, sizeof(mem));
	tlh.buf = mem;
	tlh.len = sizeof(mem);
	tlh.consumed = 0;

	p = esdm_rpc_alloc(&tlh, 16);
	CHECK(p != NULL, "the first allocation failed");
	if (!p)
		return;
	CHECK(((uintptr_t)p & 7) == 0, "the allocation is not 8 byte aligned");
	CHECK(tlh.consumed >= 16, "consumed was not advanced");

	/* The handed out memory is zeroized */
	{
		static const uint8_t zero[16] = { 0 };

		CHECK_MEM_EQ(p, zero, sizeof(zero));
	}

	/*
	 * An odd-sized allocation leaves the cursor unaligned, and the next
	 * allocation has to align it again - at its own expense, not by
	 * handing out memory it did not account for.
	 */
	q = esdm_rpc_alloc(&tlh, 3);
	CHECK(q != NULL, "the odd sized allocation failed");
	q = esdm_rpc_alloc(&tlh, 8);
	CHECK(q != NULL, "the realigning allocation failed");
	if (q) {
		CHECK(((uintptr_t)q & 7) == 0,
		      "the realigning allocation is not 8 byte aligned");
		CHECK(q + 8 <= mem + sizeof(mem),
		      "the allocation reaches past the arena");
		CHECK(tlh.consumed <= tlh.len, "the arena was overcommitted");
	}

	/* Free is a no-op - the arena is discarded as a whole */
	esdm_rpc_free(&tlh, p);
	esdm_rpc_free(&tlh, NULL);
}

static void test_rpc_alloc_limits(void)
{
	uint8_t mem[64];
	struct buffer tlh;

	tlh.buf = mem;
	tlh.len = sizeof(mem);
	tlh.consumed = 0;

	/* Exactly the arena size fits ... */
	CHECK(esdm_rpc_alloc(&tlh, sizeof(mem)) != NULL,
	      "an allocation of the full arena failed");
	CHECK_EQ(tlh.consumed, sizeof(mem));

	/* ... and nothing more is handed out afterwards */
	CHECK(esdm_rpc_alloc(&tlh, 1) == NULL,
	      "the exhausted arena still handed out memory");

	/* One byte beyond the arena is refused */
	tlh.consumed = 0;
	CHECK(esdm_rpc_alloc(&tlh, sizeof(mem) + 1) == NULL,
	      "an oversized allocation was accepted");
	CHECK_EQ(tlh.consumed, 0);

	/* A cursor past the end is refused rather than computed with */
	tlh.consumed = sizeof(mem) + 1;
	CHECK(esdm_rpc_alloc(&tlh, 1) == NULL,
	      "an arena with an out of range cursor handed out memory");

	/*
	 * A size that would overflow when the alignment padding is added must
	 * not wrap around into a small request.
	 */
	tlh.buf = mem + 1;
	tlh.len = sizeof(mem) - 1;
	tlh.consumed = 0;
	CHECK(esdm_rpc_alloc(&tlh, SIZE_MAX) == NULL,
	      "an allocation overflowing the size computation was accepted");
	CHECK(esdm_rpc_alloc(&tlh, SIZE_MAX - 3) == NULL,
	      "an allocation overflowing the size computation was accepted");
}

/******************************************************************************
 * Descriptor lookup and non-blocking helper
 ******************************************************************************/

static void test_set_fd_nonblocking(void)
{
	int fds[2];
	int flags;

	CHECK_EQ(set_fd_nonblocking(-1), -EBADF);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	CHECK((fcntl(fds[0], F_GETFL) & O_NONBLOCK) == 0,
	      "the pipe is non-blocking to begin with");
	CHECK_EQ(set_fd_nonblocking(fds[0]), 0);

	flags = fcntl(fds[0], F_GETFL);
	CHECK(flags >= 0 && (flags & O_NONBLOCK),
	      "O_NONBLOCK was not set on the descriptor");

	/* Setting it again is idempotent */
	CHECK_EQ(set_fd_nonblocking(fds[0]), 0);

	close(fds[0]);
	close(fds[1]);
}

static void test_get_descriptor(void)
{
	ProtobufCService service = { 0 };
	struct esdm_rpc_proto_cs received;
	const ProtobufCMessageDescriptor *desc = NULL;
	unsigned int i;

	service.descriptor = &unpriv_access__descriptor;

	memset(&received, 0, sizeof(received));

	/* Every method index the service declares resolves to its input type */
	for (i = 0; i < unpriv_access__descriptor.n_methods; i++) {
		received.header.method_index = i;
		desc = NULL;
		CHECK_EQ(esdm_rpc_proto_get_descriptor(&service, &received,
						       &desc),
			 0);
		CHECK(desc == unpriv_access__descriptor.methods[i].input,
		      "method %u resolved to the wrong message descriptor", i);
	}

	/*
	 * A method index off the wire that the service does not have must be
	 * rejected rather than indexing the method table out of bounds.
	 */
	received.header.method_index =
		(uint32_t)unpriv_access__descriptor.n_methods;
	CHECK_EQ(esdm_rpc_proto_get_descriptor(&service, &received, &desc),
		 -EINVAL);

	received.header.method_index = UINT32_MAX;
	CHECK_EQ(esdm_rpc_proto_get_descriptor(&service, &received, &desc),
		 -EINVAL);
}

/******************************************************************************
 * Fast path applicability
 ******************************************************************************/

static void test_is_fast_bytes_response(void)
{
	/* The message the fast paths were written for */
	CHECK(esdm_rpc_is_fast_bytes_response(&rand_val_response__descriptor),
	      "RandValResponse does not qualify for the fast path");

	/* Everything else has to fall back to the generic protobuf code */
	CHECK(!esdm_rpc_is_fast_bytes_response(&val_response__descriptor),
	      "ValResponse must not use the bytes response fast path");
	CHECK(!esdm_rpc_is_fast_bytes_response(&status_response__descriptor),
	      "StatusResponse must not use the bytes response fast path");
	CHECK(!esdm_rpc_is_fast_bytes_response(
		      &get_random_bytes_request__descriptor),
	      "GetRandomBytesRequest must not use the bytes response fast path");
	CHECK(!esdm_rpc_is_fast_bytes_response(
		      &is_fully_seeded_response__descriptor),
	      "IsFullySeededResponse must not use the bytes response fast path");
}

/******************************************************************************
 * Encoder
 ******************************************************************************/

/* What protobuf-c emits for the same message */
static size_t reference_encode(int64_t ret_val, const uint8_t *payload,
			       size_t payload_len, uint8_t *dst, size_t dst_len)
{
	RandValResponse msg = RAND_VAL_RESPONSE__INIT;
	size_t len;

	msg.ret = ret_val;
	if (payload && payload_len) {
		msg.randval.data = (uint8_t *)(uintptr_t)payload;
		msg.randval.len = payload_len;
	}

	len = rand_val_response__get_packed_size(&msg);
	if (len > dst_len)
		return (size_t)-1;

	return rand_val_response__pack(&msg, dst);
}

static void check_encode_matches_protobuf(int64_t ret_val,
					  const uint8_t *payload,
					  size_t payload_len, const char *what)
{
	uint8_t own[512], reference[512];
	size_t own_len = (size_t)-1, reference_len;

	CHECK_EQ(esdm_rpc_encode_bytes_response(own, sizeof(own), ret_val,
						payload, payload_len, &own_len),
		 0);

	reference_len = reference_encode(ret_val, payload, payload_len,
					 reference, sizeof(reference));
	if (reference_len == (size_t)-1) {
		CHECK(0, "%s: the reference encoding does not fit", what);
		return;
	}

	CHECK(own_len == reference_len,
	      "%s: encoded %zu bytes, protobuf-c encodes %zu", what, own_len,
	      reference_len);
	if (own_len == reference_len)
		CHECK(!memcmp(own, reference, own_len),
		      "%s: the encoding differs from protobuf-c", what);
}

static void test_encode(void)
{
	static const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t dst[512];
	size_t out_len;
	uint8_t big[300];
	unsigned int i;

	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)(i * 7 + 1);

	/* Proto3 omits default valued fields entirely */
	out_len = (size_t)-1;
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, sizeof(dst), 0, NULL, 0,
						&out_len),
		 0);
	CHECK_EQ(out_len, 0);

	/* An empty payload counts as the default, whether NULL or not */
	out_len = (size_t)-1;
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, sizeof(dst), 0, payload, 0,
						&out_len),
		 0);
	CHECK_EQ(out_len, 0);

	out_len = (size_t)-1;
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, sizeof(dst), 0, NULL, 4,
						&out_len),
		 0);
	CHECK_EQ(out_len, 0);

	/* The individual fields and their combination match protobuf-c */
	check_encode_matches_protobuf(0, NULL, 0, "empty message");
	check_encode_matches_protobuf(42, NULL, 0, "return code only");
	check_encode_matches_protobuf(0, payload, sizeof(payload),
				      "payload only");
	check_encode_matches_protobuf(4, payload, sizeof(payload),
				      "return code and payload");
	check_encode_matches_protobuf(-1, NULL, 0, "negative return code");
	check_encode_matches_protobuf(-EINVAL, payload, sizeof(payload),
				      "negative return code and payload");
	check_encode_matches_protobuf(INT64_MAX, NULL, 0, "maximum return code");
	check_encode_matches_protobuf(INT64_MIN, NULL, 0, "minimum return code");
	/* A payload whose length needs a multi-byte varint */
	check_encode_matches_protobuf(300, big, sizeof(big), "large payload");
}

static void test_encode_overflow(void)
{
	static const uint8_t payload[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t dst[16];
	size_t out_len;

	/* No room for the field tag of the return code */
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, 0, 42, NULL, 0, &out_len),
		 -EOVERFLOW);

	/* Room for the tag but not for the value */
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, 1, 42, NULL, 0, &out_len),
		 -EOVERFLOW);

	/* No room for the payload field tag */
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, 0, 0, payload,
						sizeof(payload), &out_len),
		 -EOVERFLOW);

	/* Room for the tag but not for the length prefix */
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, 1, 0, payload,
						sizeof(payload), &out_len),
		 -EOVERFLOW);

	/* Room for the header but not for the payload itself */
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, 2, 0, payload,
						sizeof(payload), &out_len),
		 -EOVERFLOW);
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, 9, 0, payload,
						sizeof(payload), &out_len),
		 -EOVERFLOW);

	/* An exactly fitting destination is accepted */
	out_len = (size_t)-1;
	CHECK_EQ(esdm_rpc_encode_bytes_response(dst, 10, 0, payload,
						sizeof(payload), &out_len),
		 0);
	CHECK_EQ(out_len, 10);
}

/******************************************************************************
 * Decoder
 ******************************************************************************/

static void check_decode(const uint8_t *data, size_t data_len,
			 int expected_ret, int64_t expected_val,
			 const uint8_t *expected_payload,
			 size_t expected_payload_len, const char *what)
{
	int64_t ret_val = 0x5a5a;
	const uint8_t *payload = (const uint8_t *)0x1;
	size_t payload_len = 0x5a5a;
	int ret = esdm_rpc_decode_bytes_response(data, data_len, &ret_val,
						 &payload, &payload_len);

	CHECK(ret == expected_ret, "%s: got %d, expected %d", what, ret,
	      expected_ret);
	if (ret != expected_ret || ret)
		return;

	CHECK(ret_val == expected_val,
	      "%s: return code %lld, expected %lld", what,
	      (long long)ret_val, (long long)expected_val);
	CHECK(payload_len == expected_payload_len,
	      "%s: payload of %zu bytes, expected %zu", what, payload_len,
	      expected_payload_len);

	if (expected_payload_len) {
		CHECK(payload != NULL, "%s: no payload returned", what);
		if (payload && payload_len == expected_payload_len)
			CHECK(!memcmp(payload, expected_payload, payload_len),
			      "%s: the payload content differs", what);
		/* The payload is returned in place, not copied */
		CHECK(payload >= data && payload <= data + data_len,
		      "%s: the payload does not point into the input", what);
	} else if (!expected_payload) {
		CHECK(payload == NULL, "%s: a payload was reported", what);
	}
}

static void test_decode_roundtrip(void)
{
	static const uint8_t payload[] = { 0x00, 0x11, 0x22, 0x33, 0xff };
	uint8_t buf[512];
	size_t len;
	unsigned int i;
	static const int64_t rets[] = { 0,	 1,	    -1,	     255,
					-4711,	 INT64_MAX, INT64_MIN };

	for (i = 0; i < sizeof(rets) / sizeof(rets[0]); i++) {
		char what[64];

		snprintf(what, sizeof(what), "roundtrip of return code %lld",
			 (long long)rets[i]);

		CHECK_EQ(esdm_rpc_encode_bytes_response(buf, sizeof(buf),
							rets[i], payload,
							sizeof(payload), &len),
			 0);
		check_decode(buf, len, 0, rets[i], payload, sizeof(payload),
			     what);
	}

	/* An empty message decodes to the proto3 defaults */
	CHECK_EQ(esdm_rpc_encode_bytes_response(buf, sizeof(buf), 0, NULL, 0,
						&len),
		 0);
	CHECK_EQ(len, 0);
	check_decode(buf, 0, 0, 0, NULL, 0, "empty message");
}

/* What protobuf-c makes of the same bytes */
static void check_decode_matches_protobuf(const uint8_t *data, size_t data_len,
					  const char *what)
{
	RandValResponse *msg;
	int64_t ret_val = 0;
	const uint8_t *payload = NULL;
	size_t payload_len = 0;
	int ret = esdm_rpc_decode_bytes_response(data, data_len, &ret_val,
						 &payload, &payload_len);

	msg = rand_val_response__unpack(NULL, data_len, data);

	if (ret) {
		CHECK(msg == NULL,
		      "%s: rejected by the fast path but accepted by protobuf-c",
		      what);
		if (msg)
			rand_val_response__free_unpacked(msg, NULL);
		return;
	}

	if (!msg) {
		CHECK(0, "%s: accepted by the fast path but rejected by protobuf-c",
		      what);
		return;
	}

	CHECK(msg->ret == ret_val, "%s: return code %lld, protobuf-c says %lld",
	      what, (long long)ret_val, (long long)msg->ret);
	CHECK(msg->randval.len == payload_len,
	      "%s: payload of %zu bytes, protobuf-c says %zu", what, payload_len,
	      msg->randval.len);
	if (msg->randval.len == payload_len && payload_len)
		CHECK(!memcmp(msg->randval.data, payload, payload_len),
		      "%s: the payload differs from protobuf-c", what);

	rand_val_response__free_unpacked(msg, NULL);
}

static void test_decode_against_protobuf(void)
{
	static const uint8_t payload[] = { 0xca, 0xfe, 0xba, 0xbe };
	uint8_t buf[512];
	size_t len;

	CHECK_EQ(esdm_rpc_encode_bytes_response(buf, sizeof(buf), 32, payload,
						sizeof(payload), &len),
		 0);
	check_decode_matches_protobuf(buf, len, "return code and payload");

	CHECK_EQ(esdm_rpc_encode_bytes_response(buf, sizeof(buf), -EFAULT, NULL,
						0, &len),
		 0);
	check_decode_matches_protobuf(buf, len, "negative return code");

	check_decode_matches_protobuf(buf, 0, "empty message");
}

static void test_decode_malformed(void)
{
	uint8_t buf[64];

	/* A varint that never terminates before the end of the buffer */
	buf[0] = 0x80;
	check_decode(buf, 1, -EPROTO, 0, NULL, 0, "truncated tag varint");

	/* A return code whose varint is truncated */
	buf[0] = 0x08;
	buf[1] = 0x80;
	check_decode(buf, 2, -EPROTO, 0, NULL, 0, "truncated value varint");

	/* A tag without any value behind it */
	buf[0] = 0x08;
	check_decode(buf, 1, -EPROTO, 0, NULL, 0, "tag without value");

	/* An over-long varint: more than the 64 bits it could ever encode */
	memset(buf, 0x80, 12);
	buf[12] = 0x00;
	check_decode(buf, 13, -EPROTO, 0, NULL, 0, "over-long varint");

	/* A payload length pointing past the end of the message */
	buf[0] = 0x12; /* field 2, length delimited */
	buf[1] = 0x10; /* 16 bytes ... */
	buf[2] = 0xaa; /* ... of which one is present */
	check_decode(buf, 3, -EPROTO, 0, NULL, 0, "payload length past the end");

	/* A payload length prefix that is itself truncated */
	buf[0] = 0x12;
	buf[1] = 0x80;
	check_decode(buf, 2, -EPROTO, 0, NULL, 0, "truncated length prefix");

	/* Wire types that proto3 does not define */
	buf[0] = 0x0b; /* field 1, wire type 3 (start group) */
	check_decode(buf, 1, -EPROTO, 0, NULL, 0, "wire type 3");
	buf[0] = 0x0c; /* field 1, wire type 4 (end group) */
	check_decode(buf, 1, -EPROTO, 0, NULL, 0, "wire type 4");
	buf[0] = 0x0e; /* field 1, wire type 6 */
	check_decode(buf, 1, -EPROTO, 0, NULL, 0, "wire type 6");
	buf[0] = 0x0f; /* field 1, wire type 7 */
	check_decode(buf, 1, -EPROTO, 0, NULL, 0, "wire type 7");

	/* A fixed64 field that is cut short */
	buf[0] = 0x19; /* field 3, wire type 1 */
	memset(buf + 1, 0, 7);
	check_decode(buf, 8, -EPROTO, 0, NULL, 0, "truncated fixed64");

	/* A fixed32 field that is cut short */
	buf[0] = 0x1d; /* field 3, wire type 5 */
	memset(buf + 1, 0, 3);
	check_decode(buf, 4, -EPROTO, 0, NULL, 0, "truncated fixed32");

	/* An unknown length delimited field reaching past the end */
	buf[0] = 0x1a; /* field 3, wire type 2 */
	buf[1] = 0x20;
	check_decode(buf, 2, -EPROTO, 0, NULL, 0,
		     "unknown field length past the end");
}

static void test_decode_unknown_fields(void)
{
	uint8_t buf[64];
	size_t len;

	/*
	 * A message from a newer peer carries fields this decoder does not
	 * know. They have to be skipped, not to make the whole message fail -
	 * and the fields it does know still have to come out right.
	 */

	/* varint (wire type 0) in front of the return code */
	len = 0;
	buf[len++] = 0x18; /* field 3, varint */
	buf[len++] = 0xac;
	buf[len++] = 0x02; /* 300 */
	buf[len++] = 0x08; /* field 1, varint */
	buf[len++] = 0x2a; /* 42 */
	check_decode(buf, len, 0, 42, NULL, 0, "skipped varint field");

	/* fixed64 (wire type 1) */
	len = 0;
	buf[len++] = 0x19; /* field 3, fixed64 */
	memset(buf + len, 0xa5, 8);
	len += 8;
	buf[len++] = 0x08;
	buf[len++] = 0x07;
	check_decode(buf, len, 0, 7, NULL, 0, "skipped fixed64 field");

	/* fixed32 (wire type 5) */
	len = 0;
	buf[len++] = 0x1d; /* field 3, fixed32 */
	memset(buf + len, 0x5a, 4);
	len += 4;
	buf[len++] = 0x08;
	buf[len++] = 0x09;
	check_decode(buf, len, 0, 9, NULL, 0, "skipped fixed32 field");

	/* length delimited (wire type 2) */
	len = 0;
	buf[len++] = 0x1a; /* field 3, length delimited */
	buf[len++] = 0x03;
	buf[len++] = 'a';
	buf[len++] = 'b';
	buf[len++] = 'c';
	buf[len++] = 0x08;
	buf[len++] = 0x0b;
	check_decode(buf, len, 0, 11, NULL, 0, "skipped length delimited field");

	/*
	 * The known field numbers carrying an unexpected wire type take the
	 * skip path as well rather than being read as their declared type.
	 */
	len = 0;
	buf[len++] = 0x0a; /* field 1 as length delimited */
	buf[len++] = 0x01;
	buf[len++] = 0xff;
	check_decode(buf, len, 0, 0, NULL, 0,
		     "return code with an unexpected wire type");

	len = 0;
	buf[len++] = 0x10; /* field 2 as varint */
	buf[len++] = 0x05;
	check_decode(buf, len, 0, 0, NULL, 0,
		     "payload with an unexpected wire type");
}

static void test_decode_edge_cases(void)
{
	uint8_t buf[64];
	int64_t ret_val = -1;
	const uint8_t *payload = NULL;
	size_t payload_len = 1;
	size_t len;

	/* A zero length payload is a payload, not an absent field */
	len = 0;
	buf[len++] = 0x12;
	buf[len++] = 0x00;
	CHECK_EQ(esdm_rpc_decode_bytes_response(buf, len, &ret_val, &payload,
						&payload_len),
		 0);
	CHECK_EQ(ret_val, 0);
	CHECK_EQ(payload_len, 0);
	CHECK(payload == buf + len, "the empty payload does not point into "
				    "the message");

	/* The last field of a repeated field number wins */
	len = 0;
	buf[len++] = 0x08;
	buf[len++] = 0x01;
	buf[len++] = 0x08;
	buf[len++] = 0x02;
	check_decode(buf, len, 0, 2, NULL, 0, "repeated return code");

	/* A payload that fills the message to its last byte */
	len = 0;
	buf[len++] = 0x12;
	buf[len++] = 0x02;
	buf[len++] = 0xab;
	buf[len++] = 0xcd;
	check_decode(buf, len, 0, 0, buf + 2, 2, "payload up to the last byte");
}

/******************************************************************************
 * Bounded append callback used to pack responses
 ******************************************************************************/

static void test_append_data(void)
{
	static const uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	struct esdm_rpc_write_data_buf write_buf;
	uint8_t dst[16];

	memset(dst, 0, sizeof(dst));
	memset(&write_buf, 0, sizeof(write_buf));
	write_buf.base.append = esdm_rpc_append_data;
	write_buf.dst_buf = dst;
	write_buf.dst_len = sizeof(dst);
	write_buf.dst_written = 0;

	/* Successive appends are concatenated */
	esdm_rpc_append_data(&write_buf.base, sizeof(data), data);
	CHECK_EQ(write_buf.dst_written, sizeof(data));
	CHECK_MEM_EQ(dst, data, sizeof(data));

	esdm_rpc_append_data(&write_buf.base, sizeof(data), data);
	CHECK_EQ(write_buf.dst_written, 2 * sizeof(data));
	CHECK_MEM_EQ(dst + sizeof(data), data, sizeof(data));

	/* The destination is now full and nothing more is taken */
	esdm_rpc_append_data(&write_buf.base, 1, data);
	CHECK_EQ(write_buf.dst_written, sizeof(dst));

	/* A zero length append is accepted at any point */
	esdm_rpc_append_data(&write_buf.base, 0, data);
	CHECK_EQ(write_buf.dst_written, sizeof(dst));
}

static void test_append_data_overflow(void)
{
	static const uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	struct esdm_rpc_write_data_buf write_buf;
	uint8_t dst[16];

	memset(dst, 0xff, sizeof(dst));
	memset(&write_buf, 0, sizeof(write_buf));
	write_buf.base.append = esdm_rpc_append_data;
	write_buf.dst_buf = dst;
	write_buf.dst_len = 4;
	write_buf.dst_written = 0;

	/* More than the destination holds is refused, not truncated */
	esdm_rpc_append_data(&write_buf.base, sizeof(data), data);
	CHECK_EQ(write_buf.dst_written, 0);
	CHECK_EQ(dst[0], 0xff);

	/* An exact fit is taken */
	esdm_rpc_append_data(&write_buf.base, 4, data);
	CHECK_EQ(write_buf.dst_written, 4);
	CHECK_MEM_EQ(dst, data, 4);

	/* One byte beyond it is not */
	esdm_rpc_append_data(&write_buf.base, 1, data);
	CHECK_EQ(write_buf.dst_written, 4);
	CHECK_EQ(dst[4], 0xff);

	/*
	 * A write counter that already exceeds the capacity - which cannot
	 * happen through this interface, but would be catastrophic if it did -
	 * stops the append instead of writing past the end.
	 */
	write_buf.dst_written = write_buf.dst_len + 1;
	esdm_rpc_append_data(&write_buf.base, 1, data);
	CHECK_EQ(write_buf.dst_written, write_buf.dst_len + 1);
	CHECK_EQ(dst[5], 0xff);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_rpc_alloc();
	test_rpc_alloc_limits();
	test_set_fd_nonblocking();
	test_get_descriptor();
	test_is_fast_bytes_response();
	test_encode();
	test_encode_overflow();
	test_decode_roundtrip();
	test_decode_against_protobuf();
	test_decode_malformed();
	test_decode_unknown_fields();
	test_decode_edge_cases();
	test_append_data();
	test_append_data_overflow();

	return common_test_result("rpc_protocol");
}
