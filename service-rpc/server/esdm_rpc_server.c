/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <bits/time.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <protobuf-c/protobuf-c.h>
#include <semaphore.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/queue.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

#include "atomic.h"
#include "build_bug_on.h"
#include "conv_be_le.h"
#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_protocol_helper.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "linux_support.h"
#include "math_helper.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "privileges.h"
#include "ret_checkers.h"
#include "queue.h"
#include "systemd_support.h"
#include "threading_support.h"

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)          \
    for ((var) = TAILQ_FIRST((head));                       \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1);   \
         (var) = (tvar))
#endif

struct esdm_rpcs {
	ProtobufCService *service;
	int server_listening_fd;
	bool privileged;
};

struct esdm_rpcs_connection {
	struct esdm_rpcs *proto;
	int child_fd;
	ProtobufCAllocator *rpc_allocator;
	uint32_t method_index;
	uint32_t request_id;
	struct timespec last_used;

	/* per request data */
	struct esdm_rpc_proto_cs *received_data;
	uint8_t buf[ESDM_RPC_MAX_MSG_SIZE + sizeof(struct esdm_rpc_proto_cs)];
	size_t total_received;
	uint32_t data_to_fetch;
	uint8_t *buf_p;

	/* list handling for cleanup */
	TAILQ_ENTRY(esdm_rpcs_connection) tailq;
};
TAILQ_HEAD(esdm_rpcs_connection_list, esdm_rpcs_connection);

struct esdm_rpc_thread {
	struct esdm_rpcs *proto;
	uint32_t id;
	int eventfd;
};

struct esdm_rpcs_write_buf {
	ProtobufCBuffer base;
	struct esdm_rpcs_connection *rpc_conn;
};

enum esdm_rpcs_init_state {
	esdm_rpcs_state_uninitialized,
	esdm_rpcs_state_priv_init_complete,
	esdm_rpcs_state_unpriv_init,
	esdm_rpcs_state_perm_dropped,
};

static atomic_t esdm_rpc_init_state =
	ATOMIC_INIT(esdm_rpcs_state_uninitialized);
static DECLARE_WAIT_QUEUE(esdm_rpc_thread_init_wait);

static atomic_t server_exit = ATOMIC_INIT(0);

/* Remove a potentially left-over old Unix Domain socket. */
static void esdm_rpcs_stale_socket(const char *path, struct sockaddr *addr,
				   unsigned addr_len)
{
	struct stat statbuf;
	int fd;

	if (stat(path, &statbuf) < 0)
		return;
	if (!S_ISSOCK(statbuf.st_mode))
		return;

	fd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0)
		return;
	set_fd_nonblocking(fd);
	if (connect(fd, addr, addr_len) < 0) {
		if (errno == EINPROGRESS) {
			close(fd);
			return;
		}
	} else {
		close(fd);
		return;
	}

	/* ok, we should delete the stale socket */
	close(fd);
	unlink(path);
}

/* Write data into an RPC connection. */
static int esdm_rpcs_write_data(struct esdm_rpcs_connection *rpc_conn,
				const uint8_t *data, size_t len)
{
	const int TIMEOUT_MS = 5;
	size_t written = 0;
	ssize_t ret;

	if (rpc_conn->child_fd < 0)
		return -EINVAL;

	do {
		ret = write(rpc_conn->child_fd, data, len);
		/* we use non-blocking sockets */
		if (ret < 0 && errno == EAGAIN) {
			/* Wait a short moment for writeability, but not forever */
			struct pollfd pfd = {
				.fd = rpc_conn->child_fd,
				.events = POLLOUT
			};
			int poll_ret = poll(&pfd, 1, TIMEOUT_MS);

			/* early check for writeable */
			if (poll_ret > 0 && pfd.revents & EPOLLOUT) {
				continue;
			}

			/* signal? */
			if (poll_ret < 0 && errno == EINTR) {
				continue;
			}

			/* connection lost? */
			if (poll_ret < 0 && pfd.revents & (POLLERR | POLLHUP)) {
				ret = -EPIPE;
				break;
			}

			/* timeout or error: fall through */
			if (poll_ret <= 0) {
				ret = -errno;
			}
		};

		if (ret < 0) {
			int errsv = errno;

			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_RPC,
				"Writting of data to file descriptor %d failed: %s\n",
				rpc_conn->child_fd, strerror(errsv));

			if (errsv == EPIPE) {
				close(rpc_conn->child_fd);
				rpc_conn->child_fd = -1;
			}

			return -errsv;
		}

		written += (size_t)ret;
	} while (written < len);

	esdm_logger(LOGGER_DEBUG2, LOGGER_C_ANY, "%zu bytes written\n", len);

	return 0;
}

#ifdef ESDM_RPCS_BUF_WRITE

/*
 * Implementation of packing data and sending it out. Properties:
 *
 * - one call to write data out to the file descriptor
 *
 * - one more copy of entire data required to linearize all data
 */
static int esdm_rpcs_pack_internal(const ProtobufCMessage *message,
				   struct esdm_rpcs_connection *rpc_conn)
{
#define ESDM_RPCS_BUF_WRITE_HEADER_SZ (sizeof(struct esdm_rpc_proto_sc_header))

	size_t message_length;
	int ret;
	uint8_t *data_buf_alloc = NULL;
	uint8_t *data_buf;
	struct esdm_rpc_proto_sc_header *sc_header;
	struct esdm_rpc_write_data_buf tmp = {
		.dst_written = 0,
	};

	tmp.base.append = esdm_rpc_append_data;

	message_length = protobuf_c_message_get_packed_size(message);
	if (message_length > ESDM_RPC_MAX_MSG_SIZE) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "Unexpected message length: %zu\n", message_length);
		return -EFAULT;
	}

	data_buf_alloc = malloc(ESDM_RPCS_BUF_WRITE_HEADER_SZ + message_length +
				sizeof(uint64_t) - 1);
	CKNULL(data_buf_alloc, -ENOMEM);

	data_buf = ALIGN_PTR_8(data_buf_alloc, sizeof(uint64_t));
	tmp.dst_buf = (data_buf + ESDM_RPCS_BUF_WRITE_HEADER_SZ);

	sc_header = (struct esdm_rpc_proto_sc_header *)data_buf;
	sc_header->status_code = le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
	sc_header->method_index = le_bswap32(rpc_conn->method_index);
	sc_header->message_length = le_bswap32(message_length);
	sc_header->request_id = le_bswap32(rpc_conn->request_id);

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_RPC,
		"Server sending: server status %u, message length %u, message index %u, request ID %u\n",
		sc_header->status_code, sc_header->message_length,
		sc_header->method_index, sc_header->request_id);

	if (protobuf_c_message_pack_to_buffer(message, &tmp.base) !=
	    message_length) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Short write of data to file descriptor\n");
		ret = -EFAULT;
		goto out;
	}

	CKINT_LOG(esdm_rpcs_write_data(rpc_conn, data_buf,
				       ESDM_RPCS_BUF_WRITE_HEADER_SZ +
					       message_length),
		  "Submission of message data failed with error %d\n", ret);

out:
	/*
	 * Zeroization not needed, as data will go out through unprotected
	 * channel anyway. If the data is not already protected, there is a
	 * bigger problem.
	 */
	if (data_buf_alloc)
		free(data_buf_alloc);
	return ret;
}

#else /* ESDM_RPCS_BUF_WRITE */

/* Write out data from a ProtobufC buffer. */
static void esdm_rpcs_append_data(ProtobufCBuffer *buffer, size_t len,
				  const uint8_t *data)
{
	struct esdm_rpcs_write_buf *buf = (struct esdm_rpcs_write_buf *)buffer;
	int ret = esdm_rpcs_write_data(buf->rpc_conn, data, len);

	if (ret < 0)
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Submission of payload data failed with error %d\n",
			    ret);
}

/*
 * Implementation of packing data and sending it out. Properties:
 *
 * - multiple calls to write data out to the file descriptor
 *
 * - no additional memory required
 */
static int esdm_rpcs_pack_internal(const ProtobufCMessage *message,
				   struct esdm_rpcs_connection *rpc_conn)
{
	struct esdm_rpc_proto_sc_header sc_header;
	struct esdm_rpcs_write_buf tmp = { 0 };
	size_t message_length;
	int ret;

	message_length = protobuf_c_message_get_packed_size(message);
	tmp.base.append = esdm_rpcs_append_data;
	tmp.rpc_conn = rpc_conn;

	sc_header.status_code = le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
	sc_header.method_index = le_bswap32(rpc_conn->method_index);
	sc_header.message_length = le_bswap32(message_length);
	sc_header.request_id = le_bswap32(rpc_conn->request_id);

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_RPC,
		"Server sending: server status %u, message length %u, message index %u, request ID %u\n",
		sc_header.status_code, sc_header.message_length,
		sc_header.method_index, sc_header.request_id);

	CKINT_LOG(esdm_rpcs_write_data(rpc_conn, (uint8_t *)&sc_header,
				       sizeof(sc_header)),
		  "Submission of header data failed with error %d\n", ret);

	if (protobuf_c_message_pack_to_buffer(message, &tmp.base) !=
	    message_length) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Short write of data to file descriptor\n");
		ret = -EFAULT;
	}

out:
	return ret;
}

#endif /* ESDM_RPCS_BUF_WRITE */

/* Pack the message into a ProtobufC structure and write it to the receiver. */
static int esdm_rpcs_pack(const ProtobufCMessage *message,
			  struct esdm_rpcs_connection *rpc_conn)
{
	struct esdm_rpc_proto_sc_header sc_header;

	if (!protobuf_c_message_check(message)) {
		sc_header.status_code =
			le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SERVICE_FAILED);
		sc_header.method_index = le_bswap32(rpc_conn->method_index);
		sc_header.message_length = 0;
		sc_header.request_id = le_bswap32(rpc_conn->request_id);
		return esdm_rpcs_write_data(rpc_conn, (uint8_t *)&sc_header,
					    sizeof(sc_header));
	}

	return esdm_rpcs_pack_internal(message, rpc_conn);
}

/* Is the calling RPC client a privileged user? */
bool esdm_rpc_client_is_privileged(void *closure_data)
{
	struct esdm_rpcs_connection *rpc_conn = closure_data;
	struct ucred cred;
	socklen_t len = sizeof(cred);

	if (getsockopt(rpc_conn->child_fd, SOL_SOCKET, SO_PEERCRED, &cred,
		       &len) < 0)
		return false;

	if (cred.uid == 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "Remote client is privileged\n");
		return true;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "Remote client is not privileged\n");
	return false;
}

static void esdm_rpcs_response_closure(const ProtobufCMessage *message,
				       void *closure_data)
{
	struct esdm_rpcs_connection *rpc_conn = closure_data;
	int ret;

	CKINT_LOG(esdm_rpcs_pack(message, rpc_conn),
		  "Failed to serialize response: %d\n", ret);

out:
	return;
}

/* Unpack the received data and invoke the intended ProtobufC handler. */
static int esdm_rpcs_unpack(struct esdm_rpcs_connection *rpc_conn,
			    struct esdm_rpc_proto_cs *received_data)
{
	const ProtobufCMessageDescriptor *desc;
	struct esdm_rpcs *proto = rpc_conn->proto;
	ProtobufCService *service = proto->service;
	ProtobufCMessage *message = NULL;
	struct esdm_rpc_proto_cs_header *header = &received_data->header;
	uint32_t method_index = header->method_index;
	int ret = 0;

	CKINT(esdm_rpc_proto_get_descriptor(service, received_data, &desc));
	message = protobuf_c_message_unpack(desc, rpc_conn->rpc_allocator,
					    header->message_length,
					    received_data->data);

	CKNULL(message, -ENOMEM);

	rpc_conn->method_index = method_index;
	rpc_conn->request_id = header->request_id;

	/* Invoke the RPC call */
	service->invoke(service, method_index, message,
			esdm_rpcs_response_closure, rpc_conn);

out:
	if (message)
		protobuf_c_message_free_unpacked(message,
						 rpc_conn->rpc_allocator);

	/* Pick up the error from esdm_rpcs_write_data */
	if (rpc_conn->child_fd == -1)
		ret = -EPIPE;

	return ret;
}

/* Read data from the RPC connection into a local buffer. */
static int esdm_rpcs_read(struct esdm_rpcs_connection *rpc_conn)
{
	ssize_t received;
	int ret = 0;

	if (rpc_conn->child_fd < 0)
		return -EINVAL;

	/* (re-)set per-request data */
	if (rpc_conn->received_data == NULL) {
		/* The cast is appropriate as the buffer is aligned to 64 bits. */
		rpc_conn->received_data = (struct esdm_rpc_proto_cs *)rpc_conn->buf;
		rpc_conn->total_received = 0;
		rpc_conn->data_to_fetch = 0;
		rpc_conn->buf_p = rpc_conn->buf;
	}

	received = read(rpc_conn->child_fd, rpc_conn->buf_p,
			sizeof(rpc_conn->buf) - rpc_conn->total_received);
	if (received < 0) {
		ret = -errno;
		if (errno != EAGAIN) {
			goto out_clear;
		} else {
			goto out;
		}
	}

	/* Received EOF */
	if (received == 0) {
		ret = -EOF;
		goto out_clear;
	}

	rpc_conn->total_received += (size_t)received;
	rpc_conn->buf_p += (size_t)received;

	clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			"Reading %zd bytes, already consumed %zu bytes\n",
			received, rpc_conn->total_received);

	/* We insist on having at least a header received. */
	if (rpc_conn->total_received < sizeof(*rpc_conn->received_data)) {
		ret = -EINVAL;
		goto out_clear;
	}

	/* Header is received, analyze it. */
	if (!rpc_conn->data_to_fetch) {
		struct esdm_rpc_proto_cs_header *header =
			&rpc_conn->received_data->header;

		/* Convert incoming data to LE */
		header->message_length =
			le_bswap32(header->message_length);
		header->method_index = le_bswap32(header->method_index);
		header->request_id = le_bswap32(header->request_id);

		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_RPC,
			"Server received: message length %u, message index %u, request ID %u\n",
			header->message_length, header->method_index,
			header->request_id);

		/*
		* Truncate the buffer length if client specified
		* too much buffer data.
		*/
		if (header->message_length > ESDM_RPC_MAX_MSG_SIZE)
			header->message_length = ESDM_RPC_MAX_MSG_SIZE;

		/* How much data are we expecting to fetch? */
		rpc_conn->data_to_fetch = header->message_length;

		/*
		* To allow comparison with total_received, let us
		* add the header length to the data to fetch value.
		*/
		rpc_conn->data_to_fetch += sizeof(*rpc_conn->received_data);
	}

	/* Now, we need to receive more and can skip deserialization */
	if (rpc_conn->total_received < rpc_conn->data_to_fetch) {
		ret = -EAGAIN;
		goto out_clear;
	}

	/* If we have received insufficient data, bail out now. */
	if (rpc_conn->total_received < sizeof(*rpc_conn->received_data) ||
	    rpc_conn->total_received < rpc_conn->data_to_fetch) {
		ret = -EINVAL;
		goto out_clear;
	}

	/*
	 * We now have a filled buffer that has a header and received
	 * as much data as the header defined. We also start the
	 * processing of data and the subsequent submission of the answer here.
	 */
	CKINT(esdm_rpcs_unpack(rpc_conn, rpc_conn->received_data));

out_clear:
	/* Clear the memory after processing one request. */
	memset_secure(rpc_conn->buf, 0, rpc_conn->total_received);
	rpc_conn->received_data = NULL;
	rpc_conn->buf_p = NULL;

out:
	return ret;
}

static void esdm_rpcs_release_conn(struct esdm_rpcs_connection *rpc_conn)
{
	if (!rpc_conn)
		return;
	if (rpc_conn->child_fd >= 0) {
		shutdown(rpc_conn->child_fd, SHUT_RDWR);
		close(rpc_conn->child_fd);
		rpc_conn->child_fd = -1;
	}
	if (rpc_conn->received_data) {
		memset_secure(rpc_conn->buf, 0, sizeof(*rpc_conn->buf));
		rpc_conn->received_data = NULL;
	}
	free(rpc_conn);
}

static bool esdm_time_after(struct timespec *curr, struct timespec *timeout)
{
	if (curr == NULL || timeout == NULL)
		return false;

	if (curr->tv_sec > timeout->tv_sec)
		return true;
	if (curr->tv_sec == timeout->tv_sec && curr->tv_nsec > timeout->tv_nsec)
		return true;

	return false;
}

/* Thread main for receiving new connections and processing them. */
static int esdm_rpcs_handler(void *args)
{
	struct esdm_rpcs_connection_list rpc_conn_list;
	struct esdm_rpc_thread *thread = args;
	struct esdm_rpcs_connection *tmp1;
	struct esdm_rpcs_connection *tmp2;
	const size_t max_events = 512;
	struct epoll_event events[max_events];
	const size_t max_connections = 1024;
	size_t num_connections = 0;
	int epfd = -1;
	int tfd = -1;
	int ret = 0;

	if (thread == NULL) {
		ret = -EINVAL;
		goto out;
	}

	TAILQ_INIT(&rpc_conn_list);

	thread_set_name(thread->proto->privileged ? rpc_handler_priv : rpc_handler_unpriv, thread->id);

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		ret = -errno;
		goto out;
	}

	/* server socket */
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, thread->proto->server_listening_fd,
				&(struct epoll_event) {
					.events = EPOLLIN,
					.data.ptr = NULL,
				}) < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				"Unable to add server FD %d to epoll\n",
				thread->proto->server_listening_fd);
		ret = -errno;
		goto out;
	}

	/* cleanup timer */
	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	struct itimerspec its = {
		.it_interval = {
			.tv_sec = ESDM_RPC_IDLE_TIMEOUT_USEC / 1000000,
			.tv_nsec = ESDM_RPC_IDLE_TIMEOUT_USEC % 1000000 * 1000,
		 },
		.it_value = {
			.tv_sec = ESDM_RPC_IDLE_TIMEOUT_USEC / 1000000,
			.tv_nsec = ESDM_RPC_IDLE_TIMEOUT_USEC % 1000000 * 1000,
		},
	};
	timerfd_settime(tfd, 0, &its, NULL);

	/* timerfd for cleanup */
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd,
				&(struct epoll_event) {
					.events = EPOLLIN,
					.data.u64 = 1 /* no ptr will have this value */
				}) < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				"Unable to add timer FD %d to epoll\n",
				tfd);
		ret = -errno;
		goto out;
	}

	/* eventfd for fast termination */
	epoll_ctl(epfd, EPOLL_CTL_ADD, thread->eventfd, &(struct epoll_event){
		.events = EPOLLIN,
		.data.u64 = 2 /* no ptr will have this value */
	});

	while (atomic_read(&server_exit) == 0) {
		int nfds = epoll_wait(epfd, events, (int)max_events, -1);
		/* signal? */
		if (nfds == -EINTR) {
			esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    "epoll_wait interrupted\n");
			continue;
		}

		if (nfds < 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    "epoll_wait failed\n");
			ret = -errno;
			goto out;
		}

		bool do_cleanup = false;

		for (int i = 0; i < nfds; i++) {
			int accepted_fd = -1;
			bool has_error = false;
			struct esdm_rpcs_connection *rpc_conn = NULL;

			/* timer fired */
			if (events[i].data.u64 == 1) {
				uint64_t expirations;
				ssize_t v = read(tfd, &expirations, sizeof(expirations));
				do_cleanup = true;
				(void) v;
				continue;
			}

			/* event fired */
			if (events[i].data.u64 == 2) {
				uint64_t event_val;
				ssize_t v = read(thread->eventfd, &event_val, sizeof(event_val));
				(void) v;
				esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    	    "termination event triggered\n");
				break;
			}

			rpc_conn = events[i].data.ptr;

			/* new connection? */
			if (events[i].events & EPOLLIN && rpc_conn == NULL && num_connections < max_connections) {
				accepted_fd = accept4(
					thread->proto->server_listening_fd,
					NULL, NULL,
					SOCK_NONBLOCK | SOCK_CLOEXEC);
				if (accepted_fd < 0) {
					continue;
				}
				rpc_conn = calloc(1, sizeof(struct esdm_rpcs_connection));
				if (rpc_conn == NULL &&
					errno == -ENOMEM) {
					esdm_logger(
						LOGGER_ERR,
						LOGGER_C_RPC,
						"Unable to alloc client conn\n");
					ret = -errno;
					goto out;
				}
				rpc_conn->child_fd =
					accepted_fd;
				rpc_conn->proto = thread->proto;
				struct epoll_event ev = {
					.events = EPOLLIN | EPOLLRDHUP,
					.data.ptr = rpc_conn
				};
				TAILQ_INSERT_TAIL(&rpc_conn_list, rpc_conn, tailq);

				if (epoll_ctl(epfd, EPOLL_CTL_ADD, accepted_fd,
					      &ev) < 0) {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_RPC,
						"Unable to add client FD %d to epoll\n",
						accepted_fd);
					ret = -errno;
					goto out;
				}

				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_RPC,
					"Processing new incoming connection for FD %d\n",
					rpc_conn->child_fd);

				++num_connections;
				esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "num connections: %lu\n", num_connections);
			}

			if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
				has_error = true;
			}

			if (rpc_conn != NULL) {
				if (has_error) {
					esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
						"Closing client FD %d\n",
						rpc_conn->child_fd);
					epoll_ctl(epfd, EPOLL_CTL_DEL,
							rpc_conn->child_fd, NULL);
					TAILQ_REMOVE(&rpc_conn_list, rpc_conn, tailq);
					esdm_rpcs_release_conn(rpc_conn);
					rpc_conn = NULL;
					--num_connections;
					esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "num connections: %lu\n", num_connections);
					continue;
				}

				ret = esdm_rpcs_read(rpc_conn);
				if (ret && errno != EAGAIN) {
					esdm_logger(
						LOGGER_DEBUG, LOGGER_C_RPC,
						"Closing incoming connection for FD %d\n",
						rpc_conn->child_fd);
					epoll_ctl(epfd, EPOLL_CTL_DEL, rpc_conn->child_fd,
						  NULL);
					TAILQ_REMOVE(&rpc_conn_list, rpc_conn, tailq);
					esdm_rpcs_release_conn(rpc_conn);
					rpc_conn = NULL;
					--num_connections;
					esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "num connections: %lu\n", num_connections);
				}
			}
		}

		if (do_cleanup) {
			struct timespec timeout_threshold;
			clock_gettime(CLOCK_MONOTONIC, &timeout_threshold);
			timeout_threshold.tv_sec -= ESDM_RPC_IDLE_TIMEOUT_USEC / 1000000;

			TAILQ_FOREACH_SAFE(tmp1, &rpc_conn_list, tailq, tmp2) {
				if (esdm_time_after(&timeout_threshold, &tmp1->last_used)) {
					TAILQ_REMOVE(&rpc_conn_list, tmp1, tailq);
					esdm_logger(
						LOGGER_DEBUG, LOGGER_C_RPC,
						"Closing incoming connection for FD %d after timeout\n",
						tmp1->child_fd);
					epoll_ctl(epfd, EPOLL_CTL_DEL, tmp1->child_fd,
						  NULL);
					esdm_rpcs_release_conn(tmp1);
					--num_connections;
					esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "num connections: %lu\n", num_connections);
				}
			}
		}
	}

out:
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "Exiting worker thread\n");

	TAILQ_FOREACH_SAFE(tmp1, &rpc_conn_list, tailq, tmp2) {
		TAILQ_REMOVE(&rpc_conn_list, tmp1, tailq);
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_RPC,
			"Closing incoming connection for FD %d at exit\n",
			tmp1->child_fd);
		epoll_ctl(epfd, EPOLL_CTL_DEL, tmp1->child_fd, NULL);
		esdm_rpcs_release_conn(tmp1);
	}

	if (tfd > 0) {
		close(tfd);
	}
	if (epfd > 0) {
		close(epfd);
	}

	return 0;
}

/* The ESDM RPC server main worker loop. */
static int esdm_rpcs_workerloop(struct esdm_rpcs *proto)
{
	struct esdm_rpc_thread *threads = NULL;
	size_t num_threads = 0;
	int ret = 0;
	uint32_t t;

	if (proto->server_listening_fd < 0)
		return -EINVAL;

	CKNULL(proto->service, -EINVAL);

	if (proto->privileged) {
		num_threads = 1;
	} else {
		num_threads = min_size(esdm_config_online_nodes(), THREADING_MAX_WORKER_THREADS);
	}

	threads = calloc(num_threads, sizeof(struct esdm_rpc_thread));
	if (threads == NULL) {
		ret = -errno;
		goto out;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
		    "Using %zu %sprivileged RPC worker threads\n", num_threads, proto->privileged ? "" : "un");

	for (t = 0; t < num_threads; ++t) {
		esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
			    "Starting %sprivileged RPC worker thread %u\n", proto->privileged ? "" : "un", t);
		threads[t].proto = proto;
		threads[t].id = t;
		threads[t].eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (threads[t].eventfd < 0) {
			ret = -errno;
			goto out;
		}
		thread_start(esdm_rpcs_handler, &threads[t], 0, NULL);
	}

	while (atomic_read(&server_exit) == 0) {
		/* 125ms */
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 125000000 };
		clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
	}

	for (t = 0; t < num_threads; ++t) {
		uint64_t val = 1;
		ssize_t v = write(threads[t].eventfd, &val, sizeof(val));
		(void) v;
	}

	ret = thread_wait();

	for (t = 0; t < num_threads; ++t) {
		close(threads[t].eventfd);
		threads[t].eventfd = -1;
	}

out:
	if (threads != NULL) {
		free(threads);
		threads = NULL;
	}
	esdm_logger(LOGGER_STATUS, LOGGER_C_RPC, "Exiting %sprivileged RPC worker loop\n", proto->privileged ? "" : "un");
	return ret;
}

/* Open the socket that we want to use for receiving data. */
static int esdm_rpcs_start(const char *unix_socket, uint16_t tcp_port,
			   ProtobufCService *service, struct esdm_rpcs *proto)
{
	struct sockaddr_un addr_un;
	struct sockaddr_in addr_in;
	struct sockaddr *address;
	int errsv, fd = -1, protocol_family;
	socklen_t address_len;

	if (unix_socket) {
		protocol_family = PF_UNIX;
		memset(&addr_un, 0, sizeof(addr_un));
		addr_un.sun_family = AF_UNIX;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
		strncpy(addr_un.sun_path, unix_socket,
			sizeof(addr_un.sun_path));
#pragma GCC diagnostic pop
		address_len = sizeof(addr_un);
		address = (struct sockaddr *)(&addr_un);

		esdm_rpcs_stale_socket(unix_socket, address, address_len);
	} else if (tcp_port) {
		protocol_family = PF_INET;
		memset(&addr_in, 0, sizeof(addr_in));
		addr_in.sin_family = AF_INET;
		addr_in.sin_port = htons(tcp_port);
		address_len = sizeof(addr_in);
		address = (struct sockaddr *)(&addr_in);
	} else {
		return -EINVAL;
	}

	fd = socket(protocol_family,
		    SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
		    0);
	if (fd < 0) {
		errsv = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "RPC Server: cannot create socket: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	if (bind(fd, address, address_len) < 0) {
		errsv = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "RPC Server: cannot bind to socket: %s\n",
			    strerror(errsv));
		close(fd);
		return -errsv;
	}

	if (listen(fd, 4096) < 0) {
		errsv = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "RPC Server: cannot listen on socket: %s\n",
			    strerror(errsv));
		close(fd);
		return -errsv;
	}

	proto->server_listening_fd = fd;
	proto->service = service;

	return 0;
}

/* Use the socket that we want to use for receiving data. */
static int esdm_rpcs_start_systemd(const char *socket_name,
				   ProtobufCService *service,
				   struct esdm_rpcs *proto)
{
#ifdef ESDM_SYSTEMD_SUPPORT
	int fd = -1;
	int type;
	socklen_t length = sizeof(type);

	if (systemd_listen_fds() > 0) {
		fd = systemd_listen_fd_for_name(socket_name);
	}
	if (fd >= 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			    "use systemd provided socket %s = %i\n",
			    socket_name, fd);

		/* double check, that we are responsible for this socket/fd */
		assert(systemd_listen_pid() == getppid());

		if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == -1) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SERVER,
				"unable to fetch socket type of systemd provided socket");
			close(fd);
			return -1;
		}

		if (type != SOCK_SEQPACKET) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SERVER,
				"systemd provided socket is not of type SOCK_SEQPACKET");
			close(fd);
			return -1;
		}

		proto->server_listening_fd = fd;
		proto->service = service;
		return 0;
	}

	esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
		    "unable to find systemd provided socket %s\n", socket_name);
	return -1;
#else
	(void)socket_name;
	(void)service;
	(void)proto;
	return 0;
#endif
}

/* Terminating the RPC server. */
static void eesdm_rpcs_stop(struct esdm_rpcs *proto)
{
	if (proto->server_listening_fd >= 0) {
		close(proto->server_listening_fd);
		proto->server_listening_fd = -1;
	}
}

/* Initialize one thread handling an unprivileged interface instance */
static int esdm_rpcs_unpriv_init(void *args)
{
	struct esdm_rpcs unpriv_proto;
	ProtobufCService *unpriv_service =
		(ProtobufCService *)&unpriv_access_service;
	int ret;

	(void)args;

	thread_set_name(rpc_unpriv_server, 0);
	memset(&unpriv_proto, 0, sizeof(unpriv_proto));

	unpriv_proto.server_listening_fd = -1;
	unpriv_proto.privileged = false;

	/* Create server handler for privileged interface in main thread */
	if (systemd_listen_fds() > 0) {
		CKINT(esdm_rpcs_start_systemd("ESDM_RPC_UNPRIV_SOCKET",
					      unpriv_service, &unpriv_proto));
	} else {
		CKINT(esdm_rpcs_start(ESDM_RPC_UNPRIV_SOCKET, 0, unpriv_service,
				      &unpriv_proto));
	}

	/* Make unprivileged socket available for all users */
	if (chmod(ESDM_RPC_UNPRIV_SOCKET,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) ==
	    -1) {
		ret = -errno;

		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"Failed to set permissions for Unix domain socket %s: %s\n",
			ESDM_RPC_UNPRIV_SOCKET, strerror(errno));

		goto out;
	}

	/* Notify the mother that the unprivileged thread is initialized. */
	atomic_set(&esdm_rpc_init_state, esdm_rpcs_state_unpriv_init);
	thread_wake_all(&esdm_rpc_thread_init_wait);

	/* Wait for the mother to drop the privileges. */
	thread_wait_event(&esdm_rpc_thread_init_wait,
			  (atomic_read(&esdm_rpc_init_state) ==
			   esdm_rpcs_state_perm_dropped));
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Unprivileged server thread for %s available\n",
		    ESDM_RPC_UNPRIV_SOCKET);

	/* Server handing unprivileged interface in current thread */
	CKINT(esdm_rpcs_workerloop(&unpriv_proto));

	return 0;

out:
	eesdm_rpcs_stop(&unpriv_proto);

	return ret;
}

/*
 * Initialize the RPC server interfaces:
 *	* The current thread processes the privileged RPC interface.
 *	* A newly started thread processes the unprivileged RPC interface.
 */
static int esdm_rpcs_interfaces_init(const char *username)
{
	struct esdm_rpcs priv_proto;
	ProtobufCService *priv_service =
		(ProtobufCService *)&priv_access_service;
	int ret;

	thread_set_name(rpc_priv_server, 0);
	memset(&priv_proto, 0, sizeof(priv_proto));

	priv_proto.server_listening_fd = -1;
	priv_proto.privileged = true;

	/* Create server handler for privileged interface in main thread */
	if (systemd_listen_fds() > 0) {
		CKINT(esdm_rpcs_start_systemd("ESDM_RPC_PRIV_SOCKET",
					      priv_service, &priv_proto));
	} else {
		CKINT(esdm_rpcs_start(ESDM_RPC_PRIV_SOCKET, 0, priv_service,
				      &priv_proto));
	}

	/* Make privileged socket available for root only */
	if (chmod(ESDM_RPC_PRIV_SOCKET, S_IRUSR | S_IWUSR) == -1) {
		int errsv = errno;

		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"Failed to set permissions for Unix domain socket %s: %s\n",
			ESDM_RPC_PRIV_SOCKET, strerror(errsv));
		ret = -errsv;
		goto out;
	}

	/* Spawn the thread handling the unprivileged interface */
	CKINT_LOG(thread_start(esdm_rpcs_unpriv_init, NULL,
			       ESDM_THREAD_RPC_UNPRIV_GROUP, NULL),
		  "Starting server thread failed\n");

	/* Wait for the unprivileged thread to complete initialization. */
	thread_wait_event(&esdm_rpc_thread_init_wait,
			  (atomic_read(&esdm_rpc_init_state) ==
			   esdm_rpcs_state_unpriv_init));

	/* Permanently drop all privileges */
	CKINT(drop_privileges_permanent(username ? username : "nobody"));

	/* Notify all unpriv handler threads that they can become active */
	atomic_set(&esdm_rpc_init_state, esdm_rpcs_state_perm_dropped);
	thread_wake_all(&esdm_rpc_thread_init_wait);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Privileged server thread for %s available\n",
		    ESDM_RPC_PRIV_SOCKET);

	systemd_notify_status("ESDM ready, all sockets allocated");
	systemd_notify_ready();
	systemd_notify_status("Running");

	/* Server handing privileged interface in current thread */
	CKINT(esdm_rpcs_workerloop(&priv_proto));

	return 0;

out:
	eesdm_rpcs_stop(&priv_proto);
	return ret;
}

static void esdm_rpc_priv_init_complete(void)
{
	if (atomic_read(&esdm_rpc_init_state) != esdm_rpcs_state_uninitialized)
		return;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		    "Privileged initialization complete\n");
	/* Notification that the privileged initialization is complete. */
	atomic_set(&esdm_rpc_init_state, esdm_rpcs_state_priv_init_complete);
	thread_wake_all(&esdm_rpc_thread_init_wait);
}

static int esdm_rpc_server_es_monitor(void __unused *unused)
{
	thread_set_name(es_monitor, 0);

	return esdm_init_monitor(esdm_rpc_priv_init_complete);
}

int esdm_rpc_server_init(const char *username)
{
	int ret = 0;

	/* Enter PID name space */
	CKINT(linux_isolate_namespace_prefork());

	pthread_setname_np(pthread_self(), "ESDM master");

	/* Main ESDM Init DRNG state, ES', ... */
	CKINT(esdm_init());

	/* Initialize test pertubation support */
	CKINT(esdm_test_shm_status_init());

	/* One thread group */
	CKINT(thread_init(1));

	/* Create thread for entropy source monitor */
	if (thread_start(esdm_rpc_server_es_monitor, NULL,
				ESDM_THREAD_ES_MONITOR, NULL)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_RPC,
				"Starting ES monitor thread failed\n");
	}

	/* Wait for the privileged initialization to complete. */
	thread_wait_event(&esdm_rpc_thread_init_wait,
				(atomic_read(&esdm_rpc_init_state) ==
				esdm_rpcs_state_priv_init_complete));

	esdm_logger(LOGGER_WARN, LOGGER_C_RPC, "RPC server started\n");

	/* start the RPC server threads */
	esdm_rpcs_interfaces_init(username);

out:
	return ret;
}

void esdm_rpc_server_fini(void)
{
	/* comment out when debugging with address sanitizer */
	thread_stop_spawning();

	atomic_set(&server_exit, 1);
	thread_wake_all(&esdm_rpc_thread_init_wait);

	thread_send_signal(ESDM_THREAD_RPC_UNPRIV_GROUP, SIGUSR1);
	thread_send_signal(ESDM_THREAD_CUSE_POLL_GROUP, SIGUSR1);

	/* Terminate test pertubation support */
	esdm_test_shm_status_fini();

	/* set first argument to false, when debugging with address sanitizer */
	thread_release(true, false);
}
