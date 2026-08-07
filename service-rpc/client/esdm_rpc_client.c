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
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include <stdbool.h>
#include "buffer.h"
#include "config.h"
#include "conv_be_le.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_protocol_helper.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "esdm_logger.h"
#include "math_helper.h"
#include "mutex.h"
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

static void register_fork_handler(void);

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
		.dst_len = sizeof(esdm_rpcc_reqbuf) - ESDM_RPCC_BUF_WRITE_HEADER_SZ,
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
	/*
	 * Must start at 0: the interrupt check below can break out of the read
	 * loop before the first read() ever runs, and the zeroization at out:
	 * uses this as the length of the data to wipe.
	 */
	ssize_t received = 0;
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
				/*
				 * Keep waiting rather than asking again. The
				 * request is already at the server - this is a
				 * connected SOCK_SEQPACKET socket, so it cannot
				 * have been lost - and it answers everything it
				 * accepted. Re-sending only makes it produce the
				 * whole answer a second time, which for the
				 * random calls means generating the data twice,
				 * and leaves the first answer queued to be
				 * handed out as the reply to whatever is asked
				 * next, because responses are matched purely by
				 * order.
				 *
				 * The retry budget of the loop bounds the wait;
				 * re-submission stays available for when it is
				 * exhausted, below.
				 */
				continue;
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

	/*
	 * The answer never came within the whole budget. Ask again from a clean
	 * slate - the caller resets the connection first, so the answer to the
	 * abandoned request cannot turn up later and be taken for the next one.
	 */
	if (!interrupted && received < 0 && !ret)
		ret = -EAGAIN;

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
			RandValResponse resp =
				RAND_VAL_RESPONSE__INIT;
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

	/*
	 * EOWNERDEAD means the lock was taken over from a thread that died in
	 * the middle of its request. The lock is consistent again, but the
	 * connection is not: a partially written request or an unconsumed
	 * response would desynchronize every later request on this socket, as
	 * the client matches responses purely by order. Drop the socket so the
	 * loop below establishes a fresh one.
	 */
	if (mutex_w_lock(&rpc_conn->lock) == EOWNERDEAD)
		reset_conn_socket(rpc_conn);

	rpc_conn->last_error = 0;

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

		/*
		 * Re-submitting means the answer to the request just sent was
		 * given up on. Drop the socket so that answer cannot arrive
		 * afterwards: responses carry nothing that ties them to a
		 * request and are matched purely by order, so a late one would
		 * be handed out as the reply to the next call on this
		 * connection.
		 */
		if (ret == -EAGAIN)
			reset_conn_socket(rpc_conn);
	} while (ret == -EAGAIN);

out:
	/*
	 * Hand the reason for a failed request to the caller: the closure is
	 * not invoked when the RPC never reached the server, so this is the
	 * only place the actual errno survives.
	 */
	if (ret < 0)
		rpc_conn->last_error = ret;

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

	/*
	 * Both mutexes are robust. A connection is owned by one caller from
	 * esdm_rpcc_get_*_service() until it is returned, and that caller holds
	 * ref_cnt for that whole span and rpc_conn->lock across the request
	 * itself. If such a thread is killed - which the interrupt callbacks
	 * exist for in the first place - a plain mutex would stay locked
	 * forever, permanently wedging that connection for the rest of the
	 * process lifetime and making the teardown leak it. A robust mutex
	 * hands the lock to the next taker with EOWNERDEAD instead, which the
	 * mutex_w_* wrappers recover from.
	 *
	 * A failed mutex initialization must not be published: the connection
	 * would be handed out with a lock that neither serializes its callers
	 * nor can be destroyed again.
	 */
	CKINT(mutex_w_init(&rpc_conn->ref_cnt, 0, 1));
	rpc_conn->fd = -1;
	reset_conn_socket(rpc_conn);

	ret = mutex_w_init(&rpc_conn->lock, 0, 1);
	if (ret) {
		/*
		 * Undo the ref_cnt initialization here: the caller only runs
		 * esdm_fini_proto_service() over the connections that were
		 * initialized completely, so this one is not covered there.
		 */
		mutex_w_destroy(&rpc_conn->ref_cnt);
		goto out;
	}

	/* Only a fully constructed connection may be handed out. */
	atomic_store(&rpc_conn->state, esdm_rpcc_initialized);

out:
	return ret;
}

/******************************************************************************
 * General service handlers
 ******************************************************************************/
/*
 * Upper bound for the number of connections of a service. Only ever lowered
 * (see esdm_rpcc_set_max_online_nodes), which together with the caching in
 * esdm_online_nodes() is what makes the connection count of a service
 * non-growing - see esdm_rpcc_init_service(). Atomic as the getters read it
 * outside of any lock.
 */
static _Atomic uint32_t esdm_rpcc_max_nodes = UINT32_MAX;

/*
 * Guards the pairing of a connection-array pointer and its count across
 * init/fini versus concurrent getters. A getter holds the reader side from
 * loading the array pointer until it owns a connection's ref_cnt, so a
 * concurrent fini (which takes the writer side for the pointer swap and only
 * then waits on each ref_cnt) can no longer destroy and free the array
 * between the getter's pointer load and its ref_cnt acquisition. The same
 * writer side serializes concurrent init calls against each other.
 * Writer-preferring so init/fini cannot be starved by a flood of getters.
 */
static mutex_t esdm_rpcc_conn_lock = MUTEX_UNLOCKED_PREFER_WRITER;

DSO_PUBLIC
int esdm_rpcc_set_max_online_nodes(uint32_t nodes)
{
	/*
	 * Clamp to at least one node: esdm_rpcc_curr_node() divides by this
	 * value, so accepting 0 would turn every later service lookup into a
	 * SIGFPE.
	 */
	uint32_t new_nodes = max_uint32(nodes, 1);
	uint32_t curr = atomic_load(&esdm_rpcc_max_nodes);

	/*
	 * Lower the limit, never raise it. The loop keeps that true also when
	 * two callers race, which the read-modify-write of a plain variable
	 * would not - and the whole connection handling relies on the limit
	 * being monotonic (see esdm_rpcc_init_service).
	 */
	while (new_nodes < curr &&
	       !atomic_compare_exchange_weak(&esdm_rpcc_max_nodes, &curr,
					     new_nodes))
		;

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

/*
 * Release a connection array that is not reachable through the global service
 * pointer any more.
 *
 * The caller must have removed the array from that pointer first, so that no
 * getter can pick up one of its connections any more. Invoke this without
 * holding esdm_rpcc_conn_lock: waiting for the in-flight callers can take up
 * to a second per connection, which must not block getters of a connection
 * array that is meanwhile installed.
 */
static void esdm_rpcc_release_conns(
	esdm_rpc_client_connection_t *rpc_conn_array, uint32_t num_conn)
{
	struct timespec abstime;
	esdm_rpc_client_connection_t *rpc_conn_p;
	uint32_t i;
	bool still_in_use = false;

	if (!rpc_conn_array)
		return;

	/* Tell everybody that the connection is about to terminate */
	for (i = 0, rpc_conn_p = rpc_conn_array; i < num_conn; i++, rpc_conn_p++)
		atomic_store(&rpc_conn_p->state, esdm_rpcc_in_termination);

	/*
	 * Wait until the processing for a connection completed and then delete
	 * it.
	 */
	for (i = 0, rpc_conn_p = rpc_conn_array; i < num_conn;
	     i++, rpc_conn_p++) {
		/*
		 * Do not wait forever: a caller that is still working on its
		 * request would otherwise block the shutdown for as long as it
		 * takes. A handle whose owner was killed does not need the
		 * timeout - ref_cnt is robust, so it is handed over right away.
		 */
		clock_gettime(CLOCK_MONOTONIC, &abstime);
		abstime.tv_sec += 1;
		if (mutex_w_timedlock(&rpc_conn_p->ref_cnt, &abstime)) {
			/*
			 * A live caller still owns this connection and did not
			 * return it within the timeout. Leave the handle alone:
			 * neither the mutexes nor the socket may be recycled
			 * while a running request can still reach them, so the
			 * whole array is leaked below rather than risking a
			 * use-after-free.
			 *
			 * A connection whose owner died without returning it is
			 * no longer part of this case: ref_cnt is robust, so
			 * the timedlock takes it over and reports success, and
			 * the handle is torn down normally below.
			 */
			still_in_use = true;
			continue;
		}
		mutex_w_unlock(&rpc_conn_p->ref_cnt);

		/* Terminate the handle */
		esdm_fini_proto_service(rpc_conn_p);
	}

	if (still_in_use) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_RPC,
			"Connection handles still in use on termination - leaking the connection memory\n");
		return;
	}

	free(rpc_conn_array);
}

/*
 * Release the connections of a service.
 *
 * @param force If false, this is one matching counterpart of an init call: the
 *		connections are only torn down once as many finis as inits were
 *		seen. If true, the connections are released regardless of how
 *		many init calls are still outstanding.
 */
static void esdm_rpcc_fini_service(
	_Atomic(esdm_rpc_client_connection_t *) *rpc_conn, uint32_t *num,
	uint32_t *init_ref, bool force)
{
	esdm_rpc_client_connection_t *rpc_conn_array;
	uint32_t num_conn;

	/*
	 * Swap out the pointer/count pair under the writer side of the
	 * connection lock: getters read both and acquire their connection's
	 * ref_cnt under the reader side, so after this critical section every
	 * getter either sees NULL or already owns a ref_cnt that the timedlock
	 * loop below waits for. The same lock guards the init reference count,
	 * so the decision to tear down and the pointer swap are one atomic step
	 * with respect to a concurrent init.
	 */
	mutex_lock(&esdm_rpcc_conn_lock);

	/* Not initialized, or already released - nothing to do. */
	if (!*init_ref) {
		mutex_unlock(&esdm_rpcc_conn_lock);
		return;
	}

	/* Other users are still around - keep the connections alive. */
	if (!force && --(*init_ref)) {
		mutex_unlock(&esdm_rpcc_conn_lock);
		return;
	}

	*init_ref = 0;
	num_conn = *num;
	rpc_conn_array = atomic_exchange(rpc_conn, NULL);
	*num = 0;
	mutex_unlock(&esdm_rpcc_conn_lock);
	if (!rpc_conn_array)
		return;

	/*
	 * Counterpart of the one esdm_test_shm_status_init() that the initial
	 * allocation of this service performed - a mere replacement of the
	 * connections keeps the shared memory attached.
	 */
	esdm_test_shm_status_fini();

	esdm_rpcc_release_conns(rpc_conn_array, num_conn);
}

/*
 * Set up the connections of a service.
 *
 * Every successful call adds one reference which esdm_rpcc_fini_service()
 * consumes again - the connections stay alive until as many finis as inits
 * were seen. This allows independent users within one process (e.g. an
 * application and a preloaded library) to init and fini without one of them
 * pulling the connections away from the other.
 *
 * The connections are allocated by the first init and are released by the last
 * fini only - an init never replaces an existing set. This is what makes a
 * connection handle that esdm_rpcc_get_service() handed out safe to use: no
 * concurrent init can free it underneath its caller.
 *
 * Doing so costs nothing because the number of nodes cannot grow during the
 * lifetime of a process: esdm_rpcc_set_max_online_nodes() only ever lowers its
 * limit and esdm_online_nodes() caches the CPU count on its first call. A
 * later init can therefore never ask for more connections than the first one
 * already allocated.
 */
static int esdm_rpcc_init_service(const ProtobufCServiceDescriptor *descriptor,
				  const char *socketname,
				  esdm_rpcc_interrupt_func_t interrupt_func,
				  _Atomic(esdm_rpc_client_connection_t *) *rpc_conn,
				  uint32_t *num_conn, uint32_t *init_ref)
{
	esdm_rpc_client_connection_t *tmp = NULL, *tmp_p, *curr_conn_array;
	uint32_t i = 0, nodes = esdm_rpcc_get_online_nodes();
	int ret = 0;

	/* Serialize against concurrent init/fini and exclude getters. */
	mutex_lock(&esdm_rpcc_conn_lock);
	curr_conn_array = atomic_load(rpc_conn);

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
	if (curr_conn_array) {
		/*
		 * The interrupt function is a property of the connection and
		 * thus shared by all users of the service. The one supplied
		 * with the first init stays in effect - replacing it would
		 * silently disable the interrupt handling of its owner.
		 */
		if (interrupt_func &&
		    interrupt_func != curr_conn_array->interrupt_func) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_RPC,
				"Interrupt function for socket %s ignored: the connections are already established\n",
				socketname);
		}

		/*
		 * Cannot happen as the node count never grows (see above). Do
		 * not silently hand out fewer connections than asked for if it
		 * ever does - the existing ones are kept either way, as freeing
		 * them would break the callers currently using them.
		 */
		if (*num_conn < nodes) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_RPC,
				"Keeping the %u existing connections for socket %s although %u are requested\n",
				*num_conn, socketname, nodes);
		}

		(*init_ref)++;
		goto out;
	}

	/*
	 * Build the connections completely before publishing them: a failure
	 * thus leaves the service in the uninitialized state it had before
	 * instead of a half-built one.
	 */
	tmp = calloc(nodes, sizeof(*tmp));
	CKNULL(tmp, -ENOMEM);

	for (i = 0, tmp_p = tmp; i < nodes; i++, tmp_p++) {
		CKINT(esdm_init_proto_service(descriptor, socketname,
					      interrupt_func, tmp_p));
	}

	/* Paired with the fini in esdm_rpcc_fini_service(). */
	CKINT(esdm_test_shm_status_init());

	/*
	 * Publish the connections. A plain store is sufficient: the pointer is
	 * NULL at this point and only init and fini ever write it, both under
	 * the writer side of the connection lock which is held throughout.
	 */
	atomic_store(rpc_conn, tmp);
	*num_conn = nodes;
	(*init_ref)++;

	/* The connection array is owned by the service now. */
	tmp = NULL;

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ANY,
		"Service supporting %u parallel requests for socket %s enabled\n",
		nodes, socketname);

out:
	/* Only still set if the connections were not published. */
	if (tmp) {
		uint32_t j;

		for (j = 0, tmp_p = tmp; j < i; j++, tmp_p++)
			esdm_fini_proto_service(tmp_p);

		free(tmp);
	}
	mutex_unlock(&esdm_rpcc_conn_lock);

	return ret;
}

static int esdm_rpcc_get_service(
	_Atomic(esdm_rpc_client_connection_t *) *rpc_conn_array_ptr,
	uint32_t *num_conn_ptr, esdm_rpc_client_connection_t **ret_rpc_conn,
	void *int_data)
{
	esdm_rpc_client_connection_t *rpc_conn_array, *rpc_conn_p;
	uint32_t node, num_conn;
	bool found_unused_conn = false;
	int ret = 0;
	uint32_t i;

	if (!ret_rpc_conn)
		return -EFAULT;

	/*
	 * Hold the reader side from the pointer load until the connection's
	 * ref_cnt is owned: fini swaps the pointer under the writer side and
	 * only then waits on each ref_cnt, so it cannot destroy and free the
	 * array between our load and the ref_cnt acquisition. The lock also
	 * makes the pointer and count a consistent pair (no transient
	 * non-NULL pointer with count 0 and its modulo-by-zero SIGFPE).
	 */
	mutex_reader_lock(&esdm_rpcc_conn_lock);

	rpc_conn_array = atomic_load(rpc_conn_array_ptr);
	num_conn = *num_conn_ptr;

	if (!rpc_conn_array) {
		ret = -EFAULT;
		goto out;
	}
	if (!num_conn) {
		ret = -ESHUTDOWN;
		goto out;
	}

	/*
	 * Protection against client programming errors: esdm_rpcc_curr_node()
	 * is bounded by the node limit, which may exceed the number of
	 * connections this service actually holds.
	 */
	node = min_uint32(esdm_rpcc_curr_node(), num_conn - 1);

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

	if (atomic_load(&rpc_conn_p->state) != esdm_rpcc_initialized) {
		mutex_w_unlock(&rpc_conn_p->ref_cnt);

		/* Safety measure */
		*ret_rpc_conn = NULL;

		ret = -ESHUTDOWN;
		goto out;
	}

	*ret_rpc_conn = rpc_conn_p;
	rpc_conn_p->interrupt_data = int_data;

out:
	mutex_reader_unlock(&esdm_rpcc_conn_lock);
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
static _Atomic(esdm_rpc_client_connection_t *) unpriv_rpc_conn = NULL;
static uint32_t unpriv_rpc_conn_num = 0;
/* Number of outstanding init calls, guarded by esdm_rpcc_conn_lock */
static uint32_t unpriv_rpc_conn_init_ref = 0;

DSO_PUBLIC
int esdm_rpcc_get_unpriv_service(esdm_rpc_client_connection_t **rpc_conn,
				 void *int_data)
{
	return esdm_rpcc_get_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num,
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
	register_fork_handler();

	return esdm_rpcc_init_service(&unpriv_access__descriptor,
				      ESDM_RPC_UNPRIV_SOCKET, interrupt_func,
				      &unpriv_rpc_conn, &unpriv_rpc_conn_num,
				      &unpriv_rpc_conn_init_ref);
}

DSO_PUBLIC
void esdm_rpcc_fini_unpriv_service(void)
{
	esdm_rpcc_fini_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num,
			       &unpriv_rpc_conn_init_ref, false);
}

DSO_PUBLIC
void esdm_rpcc_force_fini_unpriv_service(void)
{
	esdm_rpcc_fini_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num,
			       &unpriv_rpc_conn_init_ref, true);
}

/******************************************************************************
 * Privileged connection
 ******************************************************************************/
static _Atomic(esdm_rpc_client_connection_t *) priv_rpc_conn = NULL;
static uint32_t priv_rpc_conn_num = 0;
/* Number of outstanding init calls, guarded by esdm_rpcc_conn_lock */
static uint32_t priv_rpc_conn_init_ref = 0;

DSO_PUBLIC
int esdm_rpcc_get_priv_service(esdm_rpc_client_connection_t **rpc_conn,
			       void *int_data)
{
	return esdm_rpcc_get_service(&priv_rpc_conn, &priv_rpc_conn_num,
				     rpc_conn, int_data);
}

DSO_PUBLIC
void esdm_rpcc_put_priv_service(esdm_rpc_client_connection_t *rpc_conn)
{
	esdm_rpcc_put_service(rpc_conn);
}

DSO_PUBLIC
int esdm_rpcc_init_priv_service(esdm_rpcc_interrupt_func_t interrupt_func)
{
	register_fork_handler();

	return esdm_rpcc_init_service(&priv_access__descriptor,
				      ESDM_RPC_PRIV_SOCKET, interrupt_func,
				      &priv_rpc_conn, &priv_rpc_conn_num,
				      &priv_rpc_conn_init_ref);
}

DSO_PUBLIC
void esdm_rpcc_fini_priv_service(void)
{
	esdm_rpcc_fini_service(&priv_rpc_conn, &priv_rpc_conn_num,
			       &priv_rpc_conn_init_ref, false);
}

DSO_PUBLIC
void esdm_rpcc_force_fini_priv_service(void)
{
	esdm_rpcc_fini_service(&priv_rpc_conn, &priv_rpc_conn_num,
			       &priv_rpc_conn_init_ref, true);
}

/******************************************************************************
 * Fork Handling
 ******************************************************************************/
/*
 * The child handler below runs in the child of a fork, where only the forking
 * thread exists: the connections are inherited from the parent with sockets
 * that are now shared and with mutexes that may have been left locked by a
 * thread which does not exist here any more.
 *
 * The handlers are registered from the init calls, which may run concurrently -
 * hence pthread_once. A plain "did I register already" flag races: two
 * initializing threads both see it unset, register the handler twice and,
 * worse, both run the cleanup right away, which destroys and re-initializes the
 * mutexes of connections that a third thread may be using at that moment.
 *
 * One registration covers both services rather than one per service: they share
 * esdm_rpcc_conn_lock, and the prepare handler below takes its non-recursive
 * writer side - two prepare handlers doing that would deadlock the fork. Having
 * the child touch a service that was never initialized is harmless, as its
 * connection array is NULL and its count 0 then.
 */
static pthread_once_t fork_handler_once = PTHREAD_ONCE_INIT;

/*
 * Hold the connection lock across the fork. Without it the child can come up
 * with a torn view of a service: init and fini publish the connection array
 * pointer and its count as two separate stores, so a fork in between leaves the
 * child with a NULL array and a non-zero count (fini) or with an array the
 * child considers empty forever (init). Holding the lock also means the child
 * does not inherit it locked by a thread that no longer exists, which would
 * deadlock the first esdm_rpcc_get_service() there.
 *
 * The price is that a fork waits for an in-flight esdm_rpcc_get_service() to
 * hand out its connection, as that holds the reader side while it waits for a
 * free connection handle. That wait is bounded by one RPC round trip and only
 * occurs when all connections are busy.
 */
static void prepare_fork(void)
{
	mutex_lock(&esdm_rpcc_conn_lock);
}

static void cleanup_after_fork_parent(void)
{
	mutex_unlock(&esdm_rpcc_conn_lock);
}

/* does nothing, if no connections were allocated and num_conn is 0 */
static void reinit_conns_after_fork(
	_Atomic(esdm_rpc_client_connection_t *) *rpc_conn, uint32_t num_conn)
{
	esdm_rpc_client_connection_t *rpc_conn_array = atomic_load(rpc_conn);
	uint32_t i;

	if (!rpc_conn_array)
		return;

	/*
	 * Close all sockets and reinit the mutexes - robust, matching
	 * esdm_init_proto_service(). Recreating them rather than recovering
	 * them is what is needed here: a mutex left locked by a thread of the
	 * parent has no owner in this process at all, so there is nobody for
	 * the robustness protocol to hand it over to.
	 */
	for (i = 0; i < num_conn; ++i) {
		reset_conn_socket(&rpc_conn_array[i]);
		mutex_w_destroy(&rpc_conn_array[i].ref_cnt);
		mutex_w_destroy(&rpc_conn_array[i].lock);
		mutex_w_init(&rpc_conn_array[i].ref_cnt, 0, 1);
		mutex_w_init(&rpc_conn_array[i].lock, 0, 1);
	}
}

static void cleanup_after_fork_child(void)
{
	reinit_conns_after_fork(&unpriv_rpc_conn, unpriv_rpc_conn_num);
	reinit_conns_after_fork(&priv_rpc_conn, priv_rpc_conn_num);

	/*
	 * Drop the lock taken by prepare_fork(). Re-initializing rather than
	 * unlocking discards any waiter state inherited from the parent's
	 * threads, none of which exist here. This is safe precisely because
	 * prepare_fork() ran: the sole surviving thread is the owner, so no
	 * other thread in this process can be inside the lock.
	 */
	mutex_init(&esdm_rpcc_conn_lock, 0);
}

static void do_register_fork_handler(void)
{
	pthread_atfork(&prepare_fork, &cleanup_after_fork_parent,
		       &cleanup_after_fork_child);
}

/*
 * The registration survives a fork, so the child does not need to repeat it -
 * which is what the inherited pthread_once state provides. As the handler is
 * installed before any connection can be allocated, every fork after that
 * point runs the cleanup in the child.
 */
static void register_fork_handler(void)
{
	pthread_once(&fork_handler_once, do_register_fork_handler);
}
