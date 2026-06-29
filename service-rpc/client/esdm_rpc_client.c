/* RPC Client: Connection handler to server
 *
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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "bool.h"
#include "buffer.h"
#include "config.h"
#include "atomic.h"
#include "conv_be_le.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_protocol_helper.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "esdm_logger.h"
#include "math_helper.h"
#include "memset_secure.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "test_pertubation.h"
#include "visibility.h"

struct esdm_rpcc_write_buf {
	ProtobufCBuffer base;
	esdm_rpc_client_connection_t *rpc_conn;
};

/*
 * Per-thread request/response and unpack scratch buffers. An invoke runs
 * entirely in the calling thread while it holds the connection lock, and the
 * buffers are filled, processed and zeroized within that single synchronous
 * call - they never carry state across calls or get touched by another thread.
 * So one buffer set per calling thread suffices instead of one per connection,
 * bounding this memory by the number of RPC-issuing threads rather than by the
 * connection pool size. esdm_rpcc_reqbuf is cast to the protocol header
 * structs, hence the 64-bit alignment.
 */
static __thread uint8_t esdm_rpcc_reqbuf[ESDM_RPC_MAX_MSG_SIZE]
	__attribute__((aligned(sizeof(uint64_t))));
/*
 * Scratch buffer used to unpack a response without a malloc()/free() round-trip
 * per call; backs the esdm_rpc_alloc() bump allocator while in use.
 */
static __thread uint8_t esdm_rpcc_unpack_buf[ESDM_RPC_MAX_UNPACK_SIZE];

static void register_fork_handler_unprivileged(void);
static void register_fork_handler_privileged(void);

static void reset_conn_socket(esdm_rpc_client_connection_t *rpc_conn)
{
	if (rpc_conn == NULL) {
		return;
	}
	if (rpc_conn->fd >= 0) {
		shutdown(rpc_conn->fd, SHUT_RDWR);
		close(rpc_conn->fd);
	}
	rpc_conn->fd = -1;
	memset(&rpc_conn->last_used, 0, sizeof(rpc_conn->last_used));
}

static void esdm_fini_proto_service(esdm_rpc_client_connection_t *rpc_conn)
{
	ProtobufCService *service;

	if (!rpc_conn)
		return;

	if (rpc_conn->fd >= 0) {
		reset_conn_socket(rpc_conn);
	}

	service = &rpc_conn->service;
	if (service->descriptor) {
		protobuf_c_service_destroy(service);
		service->descriptor = NULL;
	}

	mutex_w_destroy(&rpc_conn->lock);
	mutex_w_destroy(&rpc_conn->ref_cnt);
}

static int esdm_connect_proto_service(esdm_rpc_client_connection_t *rpc_conn)
{
	const char *socketname = rpc_conn->socketname;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 1U << (ESDM_CLIENT_CONNECT_TIMEOUT_EXPONENT)
	};
	struct stat statbuf;
	struct sockaddr_un addr;
	unsigned int attempts = 0;
	int errsv;

	/* defensive check, detected by modern compilers if missing */
	if (socketname == NULL) {
		return -EFAULT;
	}

	if (rpc_conn->fd >= 0) {
		reset_conn_socket(rpc_conn);
	}

	/* Does the path exist? */
	if (stat(socketname, &statbuf) == -1) {
		errsv = errno;

		if (errsv == ENOENT) {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
				    "ESDM server interface %s not available\n",
				    socketname);
		}

		return -errsv;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Attempting to access ESDM server interface %s\n",
		    socketname);

	/* Connect to the Unix domain socket */
	addr.sun_family = AF_UNIX;

	if (strlen(socketname) >= sizeof(addr.sun_path)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Socket path too long: %s\n", socketname);
		return -ENAMETOOLONG;
	}
	memset(addr.sun_path, 0, sizeof(addr.sun_path));
	memcpy(addr.sun_path, socketname, strlen(socketname));

	/*
	 * The use of SOCK_SEQPACKET is intended to guarantee that the entire
	 * message is sent and that the receiving server will only receive
	 * the full message. Short reads will therefore not happen on the server
	 * side.
	 */
	rpc_conn->fd = socket(addr.sun_family,
			      SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (rpc_conn->fd < 0) {
		errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Error creating socket: %s\n", strerror(errsv));

		reset_conn_socket(rpc_conn);

		return -errsv;
	}

	do {
		/* If we have another attempt, try to wait a bit */
		if (attempts)
			nanosleep(&ts, NULL);

		if (connect(rpc_conn->fd, (struct sockaddr *)&addr,
			    sizeof(addr)) < 0) {
			errsv = errno;

			esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    "Error connecting socket: %s\n",
				    strerror(errsv));
			attempts++;
		} else {
			errsv = 0;
		}
	} while (attempts < (ESDM_CLIENT_RECONNECT_ATTEMPTS) &&
		 (errsv == EAGAIN || errsv == ECONNREFUSED || errsv == EINTR ||
		  errsv == EINPROGRESS));

	if (errsv || attempts >= ESDM_CLIENT_RECONNECT_ATTEMPTS) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Connection attempt using socket %s failed\n",
			    socketname);
		reset_conn_socket(rpc_conn);
	} else {
		/* only update this time on a successful connection */
		clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);
	}

	return -errsv;
}

static int esdm_rpc_client_write_data_fd(esdm_rpc_client_connection_t *rpc_conn,
					 const uint8_t *data, size_t len)
{
	static const int CLIENT_TX_TIMEOUT_MS =
		(1 << ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT) / 1000000;
	unsigned int retries = 0;
	int pret = -1;
	ssize_t ret;

	if (rpc_conn->fd < 0)
		return -EINVAL;

	do {
		/* Does the caller wants us to interrupt? */
		if (rpc_conn->interrupt_func &&
		    rpc_conn->interrupt_func(rpc_conn->interrupt_data)) {
			return -EAGAIN;
		}

		retries++;
		ret = write(rpc_conn->fd, data, len);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pfd = { .fd = rpc_conn->fd,
					      .events = POLLOUT };

			pret = poll(&pfd, 1, CLIENT_TX_TIMEOUT_MS);
			/* data available before timeout? */
			if (pret > 0) {
				continue;
			}
			if (pret < 0 && errno == EINTR) {
				continue;
			}
		}

		if (ret < 0) {
			int errsv = errno;

			/*
			 * EPIPE is due to the server was restarted -> reconnect
			 */
			if (pret == 0) {
				continue;
			}

			if (errsv == EPIPE) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_RPC,
					"Connection to server needs to be re-established\n");

				reset_conn_socket(rpc_conn);
				int rc = esdm_connect_proto_service(rpc_conn);
				if (rc)
					return rc;
				continue;
			}

			esdm_logger(
				LOGGER_ERR, LOGGER_C_RPC,
				"Writing of data to file descriptor %d failed: %s\n",
				rpc_conn->fd, strerror(errsv));

			return -errsv;
		}
	} while (ret < 0 && retries <= ESDM_MAX_RX_TX_RETRIES);

	/*
	 * SOCK_SEQPACKET guarantees atomic messages - a short write is a
	 * protocol violation, not a partial transfer to be retried.
	 */
	if (ret != (ssize_t)len) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_RPC,
			"Partial write on SEQPACKET socket: %zd of %zu bytes on fd %d\n",
			ret, len, rpc_conn->fd);
		return -EIO;
	}
	esdm_logger(LOGGER_DEBUG2, LOGGER_C_ANY, "%zu bytes written\n", len);

	return 0;
}

/*
 * Implementation of packing data and sending it out. Properties:
 *
 * - one call to write data out to the file descriptor
 *
 * - one more copy of entire data required to linearize all data
 */
static int esdm_rpc_client_pack(const ProtobufCMessage *message,
				unsigned int method_index,
				esdm_rpc_client_connection_t *rpc_conn)
{
#define ESDM_RPCC_BUF_WRITE_HEADER_SZ (sizeof(struct esdm_rpc_proto_cs_header))

	size_t message_length;
	int ret;
	struct esdm_rpc_proto_cs_header *cs_header;
	struct esdm_rpc_write_data_buf tmp = {
		.dst_written = 0,
	};

	tmp.base.append = esdm_rpc_append_data;

	message_length = protobuf_c_message_get_packed_size(message);
	if (message_length > ESDM_RPC_MAX_INTERNAL_MSG_SIZE) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "Unexpected message length: %zu\n", message_length);
		return -EFAULT;
	}

	tmp.dst_buf = esdm_rpcc_reqbuf + ESDM_RPCC_BUF_WRITE_HEADER_SZ;

	cs_header = (struct esdm_rpc_proto_cs_header *)esdm_rpcc_reqbuf;
	cs_header->method_index = le_bswap32(method_index);
	cs_header->message_length = le_bswap32(message_length);
	cs_header->request_id = le_bswap32(0);

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_RPC,
		"Client sending: message length %u, message index %u, request ID %u\n",
		cs_header->message_length, cs_header->method_index,
		cs_header->request_id);

	if (protobuf_c_message_pack_to_buffer(message, &tmp.base) !=
	    message_length) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Short write of data to file descriptor \n");
		ret = -EFAULT;
		goto out;
	}

	CKINT_LOG(esdm_rpc_client_write_data_fd(rpc_conn, esdm_rpcc_reqbuf,
						ESDM_RPCC_BUF_WRITE_HEADER_SZ +
							message_length),
		  "Submission of message data failed with error %d\n", ret);

out:
	/*
	 * Zeroization only here is not sufficient.
	 * Make sure to enable zeroize on alloc and free in your Linux kernel
	 * and clear data from ESDM in your application or patch
	 * ESDM to include a cryptographic tunnel to your application.
	 */
	memset_secure(esdm_rpcc_reqbuf, 0,
		      message_length + ESDM_RPCC_BUF_WRITE_HEADER_SZ);
	return ret;
}

static int
esdm_rpc_client_read_handler(esdm_rpc_client_connection_t *rpc_conn,
			     const ProtobufCMessageDescriptor *message_desc,
			     ProtobufCClosure closure, void *closure_data)
{
	static const int CLIENT_RX_TIMEOUT_MS =
		(1 << ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT) / 1000000;
	struct esdm_rpc_proto_sc *received_data;
	struct esdm_rpc_proto_sc_header *header = NULL;
	ssize_t received;
	unsigned int retries = 0;
	int ret = 0;
	int pret;
	bool interrupted = false;

	if (rpc_conn->fd < 0)
		return -EINVAL;

	/* The cast is appropriate as the buffer is aligned to 64 bits. */
	received_data = (struct esdm_rpc_proto_sc *)esdm_rpcc_reqbuf;

	/* Read the data into the local buffer storage */
	do {
		/* Does the caller wants us to interrupt? */
		if (rpc_conn->interrupt_func &&
		    rpc_conn->interrupt_func(rpc_conn->interrupt_data)) {
			interrupted = true;
			break;
		}

		retries++;

		/*
		 * The server uses SOCK_SEQPACKET which ensures that always the
		 * full message is submitted in one send operation. Therefore,
		 * short-reads cannot occur here and can be ignored.
		 */
		received = read(rpc_conn->fd, esdm_rpcc_reqbuf,
				sizeof(esdm_rpcc_reqbuf));

		pret = 0;
		if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pfd = { .fd = rpc_conn->fd,
					      .events = POLLIN };

			pret = poll(&pfd, 1, CLIENT_RX_TIMEOUT_MS);
			/* data available before timeout? */
			if (pret > 0) {
				continue;
			}
			if (pret < 0 && errno == EINTR) {
				continue;
			}
		}

		/* Handle a read timeout */
		if (received < 0) {
			if (pret == 0) {
				/* Trigger the re-submission of the request */
				ret = -EAGAIN;
				goto out;
			}

			ret = -errno;
			esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
				    "Read failed: %s\n", strerror(errno));
			break;
		}

		if (received < (ssize_t)sizeof(*header))
			continue;

		header = &received_data->header;

		/* Convert incoming data to LE */
		header->status_code = le_bswap32(header->status_code);
		header->message_length = le_bswap32(header->message_length);
		header->method_index = le_bswap32(header->method_index);
		header->request_id = le_bswap32(header->request_id);

		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_RPC,
			"Client received: server status %u, message length %u, message index %u, request ID %u\n",
			header->status_code, header->message_length,
			header->method_index, header->request_id);

		/*
		 * Reject if the server specified too much buffer
		 * data. As the server also checks this, it is a
		 * clear protocol violation.
		 */
		if (header->message_length > ESDM_RPC_MAX_INTERNAL_MSG_SIZE) {
			ret = -EOVERFLOW;
			break;
		}

		if (received <
		    (ssize_t)(sizeof(struct esdm_rpc_proto_sc_header) +
			      header->message_length)) {
			ret = -EPROTO;
			break;
		}
	} while (received <= 0 && retries <= ESDM_MAX_RX_TX_RETRIES);

	if (!interrupted && header &&
	    header->status_code == PROTOBUF_C_RPC_STATUS_CODE_SUCCESS) {
		/*
		 * We now have a filled buffer that has a header and received
		 * as much data as the header defined. We also start the
		 * processing of data which returns it to the caller.
		 */
		if (esdm_rpc_is_fast_bytes_response(message_desc)) {
			/*
			 * Zero-copy fast path for the random responses:
			 * decode the (ret, randval) message in place so
			 * randval.data points straight into the receive buffer.
			 * The closure then performs the single mandatory copy
			 * into the caller's buffer - avoiding the extra copy and
			 * allocation that a full unpack would incur. The receive
			 * buffer (and thus the payload) is zeroized at out:.
			 */
			GetRandomBytesFullResponse resp =
				GET_RANDOM_BYTES_FULL_RESPONSE__INIT;
			const uint8_t *payload;
			size_t payload_len;
			int64_t retval;

			if (!esdm_rpc_decode_bytes_response(
				    received_data->data, header->message_length,
				    &retval, &payload, &payload_len)) {
				resp.base.descriptor = message_desc;
				resp.ret = retval;
				resp.randval.data = (uint8_t *)payload;
				resp.randval.len = payload_len;
				closure((ProtobufCMessage *)&resp, closure_data);
			} else {
				esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
					    "Response message could not be decoded\n");
				closure(ERR_PTR(-EPROTO), closure_data);
			}
		} else {
			/*
			 * Unpack into a per-connection scratch buffer via a bump
			 * allocator instead of malloc()/free(). This avoids a
			 * heap allocation per call and lets us reliably zeroize
			 * the unpacked copy afterwards - the default allocator's
			 * free() would otherwise leave it in the heap unscrubbed.
			 */
			struct buffer tlh = {
				.len = sizeof(esdm_rpcc_unpack_buf),
				.consumed = 0,
				.buf = esdm_rpcc_unpack_buf,
			};
			ProtobufCAllocator allocator = {
				.alloc = esdm_rpc_alloc,
				.free = esdm_rpc_free,
				.allocator_data = &tlh,
			};
			ProtobufCMessage *msg = protobuf_c_message_unpack(
				message_desc, &allocator, header->message_length,
				received_data->data);
			if (msg) {
				closure(msg, closure_data);
				protobuf_c_message_free_unpacked(msg, &allocator);
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_RPC,
					"Data with length %u send to client closure handler\n",
					header->message_length);
			} else {
				esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
					    "Response message not found\n");
				msg = ERR_PTR(-EFAULT);
				closure(msg, closure_data);
			}
			if (tlh.consumed)
				memset_secure(esdm_rpcc_unpack_buf, 0,
					      tlh.consumed);
		}
		clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);
	} else if (interrupted) {
		ProtobufCMessage *msg;

		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Request interrupted\n");
		msg = ERR_PTR(-EINTR);
		closure(msg, closure_data);
	} else {
		ProtobufCMessage *msg;

		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Server returned with an error\n");
		msg = ERR_PTR(-EPROTO);
		closure(msg, closure_data);
	}

out:
	if (received > 0) {
		memset_secure(esdm_rpcc_reqbuf, 0, (size_t)received);
	}
	return ret;
}

static void esdm_client_invoke(ProtobufCService *service,
			       unsigned int method_index,
			       const ProtobufCMessage *input,
			       ProtobufCClosure closure, void *closure_data)
{
	const ProtobufCServiceDescriptor *desc = service->descriptor;
	const ProtobufCMethodDescriptor *method = desc->methods + method_index;
	esdm_rpc_client_connection_t *rpc_conn =
		(esdm_rpc_client_connection_t *)service;
	static const int64_t half_server_timeout_ns =
		(int64_t)ESDM_RPC_IDLE_TIMEOUT_USEC * 1000 / 2;
	struct timespec current_time;
	int64_t used_before_ns;
	int ret;

	mutex_w_lock(&rpc_conn->lock);

	do {
		clock_gettime(CLOCK_MONOTONIC, &current_time);
		used_before_ns =
			((int64_t)current_time.tv_sec -
			 (int64_t)rpc_conn->last_used.tv_sec) *
				1000000000LL +
			((int64_t)current_time.tv_nsec -
			 (int64_t)rpc_conn->last_used.tv_nsec);

		/*
		 * Connect to the server if we do not have a connection,
		 * otherwise reuse the session.
		 *
		 * Server keeps the connection open for
		 * ESDM_RPC_IDLE_TIMEOUT_USEC, consider it closed a bit earlier.
		 */
		if (rpc_conn->fd == -1 ||
		    used_before_ns >= half_server_timeout_ns) {
			reset_conn_socket(rpc_conn);
			CKINT(esdm_connect_proto_service(rpc_conn));
		}

		/* Pack the protobuf-c data and send it over the wire */
		CKINT_LOG(esdm_rpc_client_pack(input, method_index, rpc_conn),
			  "Sending of data failed: %d\n", ret);

		/* Receive data */
		ret = esdm_rpc_client_read_handler(rpc_conn, method->output,
						   closure, closure_data);
		/* EAGAIN is ok here, since sockets are non-blocking now */
		if (ret < 0 && ret != -EAGAIN) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Receiving of data failed: %d\n", ret);
		}
	} while (ret == -EAGAIN);

out:
	mutex_w_unlock(&rpc_conn->lock);
}

static void esdm_client_destroy(ProtobufCService *service)
{
	esdm_rpc_client_connection_t *rpc_conn =
		(esdm_rpc_client_connection_t *)service;

	mutex_w_lock(&rpc_conn->lock);
	if (rpc_conn->fd >= 0) {
		reset_conn_socket(rpc_conn);
	}
	/*
	 * No per-connection buffer to wipe - the per-thread esdm_rpcc_reqbuf is
	 * zeroized after every invoke in esdm_rpc_client_read_handler().
	 */
	mutex_w_unlock(&rpc_conn->lock);
}

static int esdm_init_proto_service(const ProtobufCServiceDescriptor *descriptor,
				   const char *socketname,
				   esdm_rpcc_interrupt_func_t interrupt_func,
				   esdm_rpc_client_connection_t *rpc_conn)
{
	ProtobufCService *service;
	int ret = 0;

	CKNULL(rpc_conn, -EINVAL);
	service = &rpc_conn->service;

	strncpy(rpc_conn->socketname, socketname, sizeof(rpc_conn->socketname));
	rpc_conn->socketname[sizeof(rpc_conn->socketname) - 1] = '\0';
	rpc_conn->interrupt_func = interrupt_func;

	service->descriptor = descriptor;
	service->invoke = esdm_client_invoke;
	service->destroy = esdm_client_destroy;

	mutex_w_init(&rpc_conn->ref_cnt, 0, 0);
	rpc_conn->fd = -1;
	reset_conn_socket(rpc_conn);
	mutex_w_init(&rpc_conn->lock, 0, 0);
	atomic_set(&rpc_conn->state, esdm_rpcc_initialized);

out:
	return ret;
}

/******************************************************************************
 * General service handlers
 ******************************************************************************/
static uint32_t esdm_rpcc_max_nodes = UINT32_MAX;

DSO_PUBLIC
int esdm_rpcc_set_max_online_nodes(uint32_t nodes)
{
	esdm_rpcc_max_nodes = min_uint32(esdm_rpcc_max_nodes, nodes);
	return 0;
}

static uint32_t esdm_rpcc_get_online_nodes(void)
{
	return (min_uint32(esdm_rpcc_max_nodes, esdm_online_nodes()));
}

static uint32_t esdm_rpcc_curr_node(void)
{
	return (esdm_curr_node() % esdm_rpcc_max_nodes);
}

static void esdm_rpcc_fini_service(esdm_rpc_client_connection_t **rpc_conn,
				   uint32_t *num)
{
	struct timespec abstime;
	esdm_rpc_client_connection_t *rpc_conn_array;
	esdm_rpc_client_connection_t *rpc_conn_p;
	uint32_t i, num_conn = *num;
	int lock_res;

	/*
	 * Atomic exchange. Null the array pointer first, then clear the count:
	 * a concurrent getter then either sees the NULL pointer (rejected by its
	 * CKNULL) or a stale-but-consistent count, never a non-NULL pointer with
	 * a count it is about to modulo against.
	 */
	rpc_conn_array = __sync_lock_test_and_set(rpc_conn, NULL);
	*num = 0;
	if (!rpc_conn_array)
		return;

	rpc_conn_p = rpc_conn_array;

	esdm_test_shm_status_fini();

	/* Tell everybody that the connection is about to terminate */
	for (i = 0; i < num_conn; i++, rpc_conn_p++)
		atomic_set(&rpc_conn_p->state, esdm_rpcc_in_termination);

	/*
	 * Wait until the processing for a connection completed and then delete
	 * it.
	 */
	for (i = 0, rpc_conn_p = rpc_conn_array; i < num_conn;
	     i++, rpc_conn_p++) {
		/*
		 * Do not wait forever as during shutdown, the thread using
		 * the handle may have been already killed. In this case,
		 * we want to avoid a deadlock as the lock will not be released
		 * by a killed thread.
		 */
		clock_gettime(CLOCK_MONOTONIC, &abstime);
		abstime.tv_sec += 1;
		lock_res = mutex_w_timedlock(&rpc_conn_p->ref_cnt, &abstime);
		if (lock_res == 0 || lock_res == ETIMEDOUT)
			mutex_w_unlock(&rpc_conn_p->ref_cnt);

		/* Terminate the handle */
		esdm_fini_proto_service(rpc_conn_p);
	}

	free(rpc_conn_array);
}

static int esdm_rpcc_init_service(const ProtobufCServiceDescriptor *descriptor,
				  const char *socketname,
				  esdm_rpcc_interrupt_func_t interrupt_func,
				  esdm_rpc_client_connection_t **rpc_conn,
				  uint32_t *num_conn)
{
	esdm_rpc_client_connection_t *tmp = *rpc_conn, *tmp_p;
	uint32_t i = 0, nodes = esdm_rpcc_get_online_nodes();
	int ret = 0;

	/*
	 * It is a legitimate scenario that this function is called twice for
	 * one connection as follows: if the libesdm_getrandom is preloaded, the
	 * connection is already allocated. Now, the caller also wants to
	 * establish a new connection, it cannot assume that libesdm_getrandom
	 * is preloaded. Thus, it will unconditionally call the init function
	 * as well. Thus catch this issue here and avoid double allocation.
	 * Note, the esdm_rpcc_fini_service will ensure that there is also no
	 * double free.
	 */
	if (tmp) {
		/*
		 * If the existing nodes are already sufficient, do not allocate
		 * more.
		 */
		if (*num_conn >= nodes)
			return 0;

		/*
		 * The caller wants more ESDM connections now - release all
		 * connections to allocate them anew.
		 *
		 * It is inefficient to release the connections, free the memory
		 * and allocate it anew. Yet, it is the hope that this code
		 * is never called by assuming the user avoids such situations.
		 *
		 * But it is conceivable to have such situations:
		 * libesdm_getrandom allocates memory for one connection. If
		 * this library is preloaded, and the application itself wants
		 * to allow a larger set of ESDM connections, we end up in this
		 * code path.
		 *
		 * NOTE: This is only permissible when assuming that the
		 * init_service call is done at the beginning of an application,
		 * i.e. when there is no transaction running.
		 */
		for (i = 0, tmp_p = tmp; i < *num_conn; i++, tmp_p++)
			esdm_fini_proto_service(tmp_p);
		if (tmp)
			free(tmp);
		*num_conn = 0;
	}

	tmp = calloc(nodes, sizeof(*tmp));
	CKNULL(tmp, -ENOMEM);

	for (i = 0, tmp_p = tmp; i < nodes; i++, tmp_p++) {
		CKINT(esdm_init_proto_service(descriptor, socketname,
					      interrupt_func, tmp_p));
	}

	CKINT(esdm_test_shm_status_init());

	if (__sync_val_compare_and_swap(rpc_conn, NULL, tmp) != NULL) {
		ret = -EAGAIN;
		goto out;
	}
	*num_conn = nodes;

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ANY,
		"Service supporting %u parallel requests for socket %s enabled\n",
		nodes, socketname);

out:
	if (ret) {
		uint32_t j;

		for (j = 0, tmp_p = tmp; j < i; j++, tmp_p++)
			esdm_fini_proto_service(tmp_p);

		if (tmp)
			free(tmp);
	}
	return ret;
}

static int esdm_rpcc_get_service(esdm_rpc_client_connection_t *rpc_conn_array,
				 uint32_t num_conn,
				 esdm_rpc_client_connection_t **ret_rpc_conn,
				 void *int_data)
{
	esdm_rpc_client_connection_t *rpc_conn_p;
	/* Protection against client programming errors */
	uint32_t node = min_uint32(esdm_rpcc_curr_node(), num_conn);
	bool found_unused_conn = false;
	int ret = 0;
	uint32_t i;

	CKNULL(rpc_conn_array, -EFAULT);
	CKNULL(ret_rpc_conn, -EFAULT);

	/*
	 * num_conn can transiently be observed as 0 by a caller racing a
	 * concurrent init/fini: the connection array pointer and its count are
	 * published (init) / cleared (fini) as two separate stores, so a window
	 * exists where the pointer is non-NULL but the count is 0. The modulo
	 * operations below would then be a divide-by-zero (SIGFPE), so bail.
	 */
	if (!num_conn)
		return -ESHUTDOWN;

	/*
	 * Always using a fixed connection based on the current
	 * core slows the client down, as under load a thread waiting
	 * on a reply from ESDM is paused and probably another thread
	 * also communicating with ESDM scheduled on the same node
	 * waiting for the RPC connection to become available again
	 * with no gain.
	 *
	 * Try to optimistically find a free connection slot first.
	 */
	for (i = 0; i < num_conn; ++i) {
		rpc_conn_p = rpc_conn_array + (i + node) % num_conn;
		if (mutex_w_trylock(&rpc_conn_p->ref_cnt) == 0) {
			found_unused_conn = true;
			break;
		}
	}

	if (!found_unused_conn) {
		rpc_conn_p = rpc_conn_array + node % num_conn;

		/*
		 * Wait until the previous call completed - each connection
		 * handle has only one caller at one given time. Lock the
		 * ref_cnt if we obtained the connection handle.
		 */
		mutex_w_lock(&rpc_conn_p->ref_cnt);
		found_unused_conn = true;
	}

	if (atomic_read(&rpc_conn_p->state) != esdm_rpcc_initialized) {
		mutex_w_unlock(&rpc_conn_p->ref_cnt);

		/* Safety measure */
		*ret_rpc_conn = NULL;

		return -ESHUTDOWN;
	}

	*ret_rpc_conn = rpc_conn_p;
	rpc_conn_p->interrupt_data = int_data;

out:
	return ret;
}

static void esdm_rpcc_put_service(esdm_rpc_client_connection_t *rpc_conn)
{
	if (!rpc_conn)
		return;

	mutex_w_unlock(&rpc_conn->ref_cnt);
}

/******************************************************************************
 * Unprivileged connection
 ******************************************************************************/
static esdm_rpc_client_connection_t *unpriv_rpc_conn = NULL;
static uint32_t unpriv_rpc_conn_num = 0;

DSO_PUBLIC
int esdm_rpcc_get_unpriv_service(esdm_rpc_client_connection_t **rpc_conn,
				 void *int_data)
{
	return esdm_rpcc_get_service(unpriv_rpc_conn, unpriv_rpc_conn_num,
				     rpc_conn, int_data);
}

DSO_PUBLIC
void esdm_rpcc_put_unpriv_service(esdm_rpc_client_connection_t *rpc_conn)
{
	esdm_rpcc_put_service(rpc_conn);
}

DSO_PUBLIC
int esdm_rpcc_init_unpriv_service(esdm_rpcc_interrupt_func_t interrupt_func)
{
	register_fork_handler_unprivileged();

	return esdm_rpcc_init_service(&unpriv_access__descriptor,
				      ESDM_RPC_UNPRIV_SOCKET, interrupt_func,
				      &unpriv_rpc_conn, &unpriv_rpc_conn_num);
}

DSO_PUBLIC
void esdm_rpcc_fini_unpriv_service(void)
{
	esdm_rpcc_fini_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num);
}

/******************************************************************************
 * Privileged connection
 ******************************************************************************/
static esdm_rpc_client_connection_t *priv_rpc_conn = NULL;
static uint32_t priv_rpc_conn_num = 0;

DSO_PUBLIC
int esdm_rpcc_get_priv_service(esdm_rpc_client_connection_t **rpc_conn,
			       void *int_data)
{
	return esdm_rpcc_get_service(priv_rpc_conn, priv_rpc_conn_num, rpc_conn,
				     int_data);
}

DSO_PUBLIC
void esdm_rpcc_put_priv_service(esdm_rpc_client_connection_t *rpc_conn)
{
	esdm_rpcc_put_service(rpc_conn);
}

DSO_PUBLIC
int esdm_rpcc_init_priv_service(esdm_rpcc_interrupt_func_t interrupt_func)
{
	register_fork_handler_privileged();

	return esdm_rpcc_init_service(&priv_access__descriptor,
				      ESDM_RPC_PRIV_SOCKET, interrupt_func,
				      &priv_rpc_conn, &priv_rpc_conn_num);
}

DSO_PUBLIC
void esdm_rpcc_fini_priv_service(void)
{
	esdm_rpcc_fini_service(&priv_rpc_conn, &priv_rpc_conn_num);
}

/******************************************************************************
 * Fork Handling
 ******************************************************************************/
static pid_t owner_pid_unprivileged = -1;
static pid_t owner_pid_privileged = -1;

/* does nothing, if no connections were allocated and nums are 0 */
static void cleanup_after_fork_unprivileged(void)
{
	uint32_t i;

	/* close all unprivileged sockets and reinit robust mutexes */
	for (i = 0; i < unpriv_rpc_conn_num; ++i) {
		reset_conn_socket(&unpriv_rpc_conn[i]);
		mutex_w_destroy(&unpriv_rpc_conn[i].ref_cnt);
		mutex_w_destroy(&unpriv_rpc_conn[i].lock);
		mutex_w_init(&unpriv_rpc_conn[i].ref_cnt, 0, 0);
		mutex_w_init(&unpriv_rpc_conn[i].lock, 0, 0);
	}
}

/* does nothing, if no connections were allocated and nums are 0 */
static void cleanup_after_fork_privileged(void)
{
	uint32_t i;

	/* close all privileged sockets and reinit robust mutexes */
	for (i = 0; i < priv_rpc_conn_num; ++i) {
		reset_conn_socket(&priv_rpc_conn[i]);
		mutex_w_destroy(&priv_rpc_conn[i].ref_cnt);
		mutex_w_destroy(&priv_rpc_conn[i].lock);
		mutex_w_init(&priv_rpc_conn[i].ref_cnt, 0, 0);
		mutex_w_init(&priv_rpc_conn[i].lock, 0, 0);
	}
}

/* need different handlers in order to not interfere with the other case, when opened
 * in two threads at different times */
static void register_fork_handler_unprivileged(void)
{
	/* handlers stay registered after fork, only register once */
	if (owner_pid_unprivileged == -1) {
		pthread_atfork(NULL, NULL, &register_fork_handler_unprivileged);
	}

	/* also works in the initial call */
	if (getpid() != owner_pid_unprivileged) {
		owner_pid_unprivileged = getpid();
		cleanup_after_fork_unprivileged();
	}
}

/* need different handlers in order to not interfere with the other case, when opened
 * in two threads at different times */
static void register_fork_handler_privileged(void)
{
	/* handlers stay registered after fork, only register once */
	if (owner_pid_privileged == -1) {
		pthread_atfork(NULL, NULL, &register_fork_handler_privileged);
	}

	/* also works in the initial call */
	if (getpid() != owner_pid_privileged) {
		owner_pid_privileged = getpid();
		cleanup_after_fork_privileged();
	}
}
