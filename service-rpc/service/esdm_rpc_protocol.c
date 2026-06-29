/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <fcntl.h>
#include <string.h>

#include "buffer.h"
#include "esdm_rpc_protocol.h"

/* Allocate 8-byte aligned memory from thread local storage */
void *esdm_rpc_alloc(void *allocator_data, size_t size)
{
	struct buffer *tlh = allocator_data;
	uint8_t *new, *new_aligned;
	size_t alignment_offset;

	/* Validate bounds before any pointer arithmetic */
	if (tlh->consumed > tlh->len)
		return NULL;

	new = tlh->buf + tlh->consumed;
	new_aligned = ALIGN_PTR_8(new, 8);

	/* Add any potential alignment offset to the required size */
	alignment_offset = (size_t)(new_aligned - new);

	if (size > SIZE_MAX - alignment_offset)
		return NULL;
	size += alignment_offset;

	/* If the size request overflows the available memory, return nothing */
	if (size > (tlh->len - tlh->consumed))
		return NULL;

	/* Adjust the consumed memory indicator */
	tlh->consumed += size;
	memset(new, 0, size);

	/* Return the aligned memory */
	return new_aligned;
}

/*
 * Do not free the thread local storage - at the end of the whole operation
 * the thread-local storage will be cleared anyway.
 */
void esdm_rpc_free(void *allocator_data, void *data)
{
	(void)allocator_data;
	(void)data;
	return;
}

int set_fd_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0)
		return -errno;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;
	return 0;
}

/* Read a base-128 varint, advancing *pos. Returns 0 or -EPROTO. */
static int esdm_rpc_get_varint(const uint8_t *data, size_t data_len,
			       size_t *pos, uint64_t *val)
{
	uint64_t v = 0;
	unsigned int shift = 0;

	for (;;) {
		uint8_t b;

		/* Over-long varint or buffer exhausted -> malformed. */
		if (*pos >= data_len || shift > 63)
			return -EPROTO;

		b = data[(*pos)++];
		v |= (uint64_t)(b & 0x7f) << shift;
		if (!(b & 0x80))
			break;
		shift += 7;
	}

	*val = v;
	return 0;
}

/*
 * Decode a "bytes-carrying" RPC response (int64 ret = field 1, bytes
 * randval = field 2) straight from the receive buffer without copying the
 * payload: on success *payload points into data and the caller performs the
 * single mandatory copy into its own buffer. This avoids the copy and the
 * allocation that protobuf_c_message_unpack() would otherwise incur for the
 * random/seed hot paths.
 *
 * The proto3 wire format is parsed defensively; any malformed input yields
 * -EPROTO. Absent fields keep their proto3 default (ret 0, empty payload).
 */
int esdm_rpc_decode_bytes_response(const uint8_t *data, size_t data_len,
				   int64_t *ret_val, const uint8_t **payload,
				   size_t *payload_len)
{
	size_t pos = 0;

	*ret_val = 0;
	*payload = NULL;
	*payload_len = 0;

	while (pos < data_len) {
		uint64_t tag, field, wire, v;

		if (esdm_rpc_get_varint(data, data_len, &pos, &tag))
			return -EPROTO;
		field = tag >> 3;
		wire = tag & 0x7;

		if (field == 1 && wire == 0) {
			/* int64 ret encoded as a plain varint */
			if (esdm_rpc_get_varint(data, data_len, &pos, &v))
				return -EPROTO;
			*ret_val = (int64_t)v;
		} else if (field == 2 && wire == 2) {
			/* bytes randval: length-delimited, point in place */
			if (esdm_rpc_get_varint(data, data_len, &pos, &v))
				return -EPROTO;
			if (v > data_len - pos)
				return -EPROTO;
			*payload = data + pos;
			*payload_len = (size_t)v;
			pos += (size_t)v;
		} else {
			/* Unknown field: skip it based on the wire type. */
			switch (wire) {
			case 0:
				if (esdm_rpc_get_varint(data, data_len, &pos,
							&v))
					return -EPROTO;
				break;
			case 1:
				if (data_len - pos < 8)
					return -EPROTO;
				pos += 8;
				break;
			case 2:
				if (esdm_rpc_get_varint(data, data_len, &pos,
							&v))
					return -EPROTO;
				if (v > data_len - pos)
					return -EPROTO;
				pos += (size_t)v;
				break;
			case 5:
				if (data_len - pos < 4)
					return -EPROTO;
				pos += 4;
				break;
			default:
				return -EPROTO;
			}
		}
	}

	return 0;
}

int esdm_rpc_proto_get_descriptor(const ProtobufCService *service,
				  const struct esdm_rpc_proto_cs *received_data,
				  const ProtobufCMessageDescriptor **desc)
{
	const struct esdm_rpc_proto_cs_header *header = &received_data->header;
	uint32_t method_index = header->method_index;

	if (method_index >= service->descriptor->n_methods)
		return -EINVAL;

	*desc = service->descriptor->methods[method_index].input;
	return 0;
}
