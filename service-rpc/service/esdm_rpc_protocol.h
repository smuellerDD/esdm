/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_RPC_PROTOCOL_H
#define ESDM_RPC_PROTOCOL_H

#include <protobuf-c/protobuf-c.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default RPC Protocol implementation that is consistent with protobuf-c-rpc
 *	client issues request with header:
 *      	method_index	32-bit little-endian
 *		message_length	32-bit little-endian
 *		request_id	32-bit any-endian
 *	server responds with header:
 *		status_code	32-bit little-endian
 *		method_index	32-bit little-endian
 *		message_length	32-bit little-endian
 *		request_id	32-bit any-endian
 */
struct esdm_rpc_proto_cs_header {
	uint32_t method_index;
	uint32_t message_length;
	uint32_t request_id;
} __attribute__((packed));

struct esdm_rpc_proto_sc_header {
	uint32_t status_code;
	uint32_t method_index;
	uint32_t message_length;
	uint32_t request_id;
} __attribute__((packed));

/* Data buffer client to server */
struct esdm_rpc_proto_cs {
	struct esdm_rpc_proto_cs_header header;
	uint8_t data[];
} __attribute__((packed));

/* Data buffer client to server */
struct esdm_rpc_proto_sc {
	struct esdm_rpc_proto_sc_header header;
	uint8_t data[];
} __attribute__((packed));

/* Use same error codes as protobuf-c-rpc */
typedef enum {
	PROTOBUF_C_RPC_STATUS_CODE_SUCCESS,
	PROTOBUF_C_RPC_STATUS_CODE_SERVICE_FAILED,
	PROTOBUF_C_RPC_STATUS_CODE_TOO_MANY_PENDING
} ProtobufC_RPC_Status_Code;

void set_fd_nonblocking(int fd);

int esdm_rpc_proto_get_descriptor(const ProtobufCService *service,
				  const struct esdm_rpc_proto_cs *received_data,
				  const ProtobufCMessageDescriptor **desc);

/* Helpers used for protobuf-c allocator */
void *esdm_rpc_alloc(void *allocator_data, size_t size);
void esdm_rpc_free(void *allocator_data, void *data);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_PROTOCOL_H */
