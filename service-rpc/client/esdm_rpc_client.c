/* RPC Client: Connection handler to server
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <stdlib.h>
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
#include "esdm_rpc_service.h"
#include "helper.h"
#include "logger.h"
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

static void esdm_fini_proto_service(esdm_rpc_client_connection_t *rpc_conn)
{
	ProtobufCService *service;

	if (!rpc_conn)
		return;

	if (rpc_conn->fd >= 0) {
		close(rpc_conn->fd);
		rpc_conn->fd = -1;
	}

	service = &rpc_conn->service;
	if (service->descriptor) {
		protobuf_c_service_destroy(service);
		service->descriptor = NULL;
	}
}

static int esdm_connect_proto_service(esdm_rpc_client_connection_t *rpc_conn)
{
	const char *socketname = rpc_conn->socketname;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 1U << (ESDM_CLIENT_CONNECT_TIMEOUT_EXPONENT)
	};
	struct timeval tv = {
		.tv_sec = 0,
		.tv_usec = (1U << (ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT)) >> 10
	};
	struct stat statbuf;
	struct sockaddr_un addr;
	unsigned int attempts = 0;
	int errsv;

	if (rpc_conn->fd >= 0) {
		close(rpc_conn->fd);
		rpc_conn->fd = -1;
	}

	/* Does the path exist? */
	if (stat(socketname, &statbuf) == -1) {
		errsv = errno;

		if (errsv == ENOENT) {
			logger(LOGGER_DEBUG, LOGGER_C_RPC,
			       "ESDM server interface %s not available\n",
			       socketname);
		}

		return -errsv;
	}

	logger(LOGGER_DEBUG, LOGGER_C_RPC,
	       "Attempting to access ESDM server interface %s\n", socketname);

	/* Connect to the Unix domain socket */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socketname, sizeof(addr.sun_path));
	rpc_conn->fd = socket(addr.sun_family, SOCK_SEQPACKET, 0);
	if (rpc_conn->fd < 0) {
		errsv = errno;

		logger(LOGGER_ERR, LOGGER_C_RPC, "Error creating socket: %s\n",
		       strerror(errsv));
		return -errsv;
	}

	/* Set timeout on socket */
	if (setsockopt(rpc_conn->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv,
		       sizeof(tv)) < 0 ||
	    setsockopt(rpc_conn->fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv,
		       sizeof(tv)) < 0) {
		errsv = errno;

		logger(LOGGER_ERR, LOGGER_C_RPC,
		       "Error setting timeout on socket: %s\n",
		       strerror(errsv));
		return -errsv;
	}

	do {
		/* If we have another attempt, try to wait a bit */
		if (attempts)
			nanosleep(&ts, NULL);

		if (connect(rpc_conn->fd, (struct sockaddr *)&addr,
			    sizeof(addr)) < 0) {
			errsv = errno;

			logger(LOGGER_ERR, LOGGER_C_RPC,
			       "Error connecting socket: %s\n",
			       strerror(errsv));
			attempts++;
		} else {
			errsv = 0;
		}
	} while (attempts < (ESDM_CLIENT_RECONNECT_ATTEMPTS) &&
		 (errsv == EAGAIN || errsv == ECONNREFUSED || errsv == EINTR));

	if (errsv) {
		logger(LOGGER_ERR, LOGGER_C_RPC,
		       "Connection attempt using socket %s failed\n",
		       socketname);
	}

	return -errsv;
}

static int esdm_rpc_client_write_data(esdm_rpc_client_connection_t *rpc_conn,
				      const uint8_t *data, size_t len)
{
	size_t written = 0;
	ssize_t ret;

	if (rpc_conn->fd < 0)
		return -EINVAL;

	do {
		ret = write(rpc_conn->fd, data, len);
		if (ret < 0) {
			int errsv = errno;

			/*
			 * EPIPE is due to the server was restarted -> reconnect
			 * EAGAIN/EWOULDBLOCK is due to the socket
			 * timeout -> call write again
			 */
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* Does the caller wants us to interrupt? */
				if (rpc_conn->interrupt_func &&
				    rpc_conn->interrupt_func(
					    rpc_conn->interrupt_data)) {
					return -EAGAIN;
				}

				continue;
			}

			if (errsv == EPIPE) {
				logger(LOGGER_DEBUG, LOGGER_C_RPC,
				       "Connection to server needs to be re-established\n");

				int rc = esdm_connect_proto_service(rpc_conn);
				if (rc)
					return rc;
				continue;
			}

			logger(LOGGER_ERR, LOGGER_C_RPC,
			       "Writting of data to file descriptor %d failed: %s\n",
			       rpc_conn->fd, strerror(errsv));

			return -errsv;
		}

		written += (size_t)ret;

		/* Cover short writes, e.g. due to timeouts */
		data += (size_t)ret;
		len -= (size_t)ret;
	} while (written < len);

	logger(LOGGER_DEBUG2, LOGGER_C_ANY, "%zu bytes written\n", len);

	return 0;
}

static void esdm_rpc_client_append_data(ProtobufCBuffer *buffer, size_t len,
					const uint8_t *data)
{
	struct esdm_rpcc_write_buf *buf = (struct esdm_rpcc_write_buf *)buffer;
	int ret = esdm_rpc_client_write_data(buf->rpc_conn, data, len);

	if (ret < 0)
		logger(LOGGER_ERR, LOGGER_C_RPC,
		       "Submission of payload data failed with error %d\n",
		       ret);
}

static int esdm_rpc_client_pack(const ProtobufCMessage *message,
				unsigned int method_index,
				esdm_rpc_client_connection_t *rpc_conn)
{
	struct esdm_rpc_proto_cs_header cs_header;
	struct esdm_rpcc_write_buf tmp = { 0 };
	size_t message_length;
	int ret;

	message_length = protobuf_c_message_get_packed_size(message);
	tmp.base.append = esdm_rpc_client_append_data;
	tmp.rpc_conn = rpc_conn;

	cs_header.method_index = le_bswap32(method_index);
	cs_header.message_length = le_bswap32(message_length);
	cs_header.request_id = le_bswap32(0);

	logger(LOGGER_DEBUG, LOGGER_C_RPC,
	       "Client sending: message length %u, message index %u, request ID %u\n",
	       cs_header.message_length, cs_header.method_index,
	       cs_header.request_id);

	CKINT_LOG(esdm_rpc_client_write_data(rpc_conn, (uint8_t *)&cs_header,
					     sizeof(cs_header)),
		  "Submission of header data failed with error %d\n", ret);

	if (protobuf_c_message_pack_to_buffer(message, &tmp.base) !=
	    message_length) {
		logger(LOGGER_VERBOSE, LOGGER_C_RPC,
		       "Short write of data to file descriptor \n");
		ret = -EFAULT;
	}

out:
	return ret;
}

static int
esdm_rpc_client_read_handler(esdm_rpc_client_connection_t *rpc_conn,
			     const ProtobufCMessageDescriptor *message_desc,
			     ProtobufCClosure closure, void *closure_data)
{
	ProtobufCAllocator esdm_rpc_client_allocator = {
		.alloc = &esdm_rpc_alloc,
		.free = &esdm_rpc_free,
		.allocator_data = NULL,
	};
	BUFFER_INIT(tls);
	struct esdm_rpc_proto_sc *received_data;
	struct esdm_rpc_proto_sc_header *header = NULL;
	uint8_t buf[ESDM_RPC_MAX_MSG_SIZE + sizeof(*received_data)] __aligned(
		sizeof(uint64_t));
	uint8_t unpacked[ESDM_RPC_MAX_MSG_SIZE + 128] __aligned(
		sizeof(uint64_t));
	size_t total_received = 0;
	ssize_t received;
	uint32_t data_to_fetch = 0;
	int ret = 0;
	uint8_t *buf_p = buf;
	bool interrupted = false;

	if (rpc_conn->fd < 0)
		return -EINVAL;

	tls.buf = unpacked;
	tls.len = sizeof(unpacked);
	esdm_rpc_client_allocator.allocator_data = &tls;

	/* The cast is appropriate as the buffer is aligned to 64 bits. */
	received_data = (struct esdm_rpc_proto_sc *)buf;

	/* Read the data into the local buffer storage */
	do {
		received =
			read(rpc_conn->fd, buf_p, sizeof(buf) - total_received);
		if (received < 0) {
			/* Handle a read timeout due to SO_RCVTIMEO */
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* Does the caller wants us to interrupt? */
				if (rpc_conn->interrupt_func &&
				    rpc_conn->interrupt_func(
					    rpc_conn->interrupt_data)) {
					interrupted = true;
					break;
				}

				/* Trigger the re-submission of the request */
				ret = EAGAIN;
				goto out;
			}

			ret = -errno;
			logger(LOGGER_DEBUG, LOGGER_C_RPC, "Read failed: %s\n",
			       strerror(errno));
			break;
		}

		/* Received EOF */
		if (received == 0) {
			ret = 0;
			break;
		}

		total_received += (size_t)received;
		buf_p += (size_t)received;

		if (total_received < sizeof(*received_data))
			continue;

		if (!data_to_fetch) {
			header = &received_data->header;

			/* Convert incoming data to LE */
			header->status_code = le_bswap32(header->status_code);
			header->message_length =
				le_bswap32(header->message_length);
			header->method_index = le_bswap32(header->method_index);
			header->request_id = le_bswap32(header->request_id);

			logger(LOGGER_DEBUG, LOGGER_C_RPC,
			       "Client received: server status %u, message length %u, message index %u, request ID %u\n",
			       header->status_code, header->message_length,
			       header->method_index, header->request_id);

			/*
			 * Truncate the buffer length if client specified
			 * too much buffer data.
			 */
			if (header->message_length > ESDM_RPC_MAX_MSG_SIZE)
				header->message_length = ESDM_RPC_MAX_MSG_SIZE;

			/* How much data are we expecting to fetch? */
			data_to_fetch = header->message_length;

			/* If we are not expecting anything, simply stop now */
			if (!data_to_fetch)
				break;

			/*
			 * To allow comparison with total_received, let us
			 * add the header length to the data to fetch value.
			 */
			data_to_fetch += sizeof(*received_data);
		}

		/* Now, we received enough and can stop the reading */
		if (total_received >= data_to_fetch)
			break;

	} while (total_received < sizeof(buf));

	if (header &&
	    header->status_code == PROTOBUF_C_RPC_STATUS_CODE_SUCCESS) {
		/*
		 * We now have a filled buffer that has a header and received
		 * as much data as the header defined. We also start the
		 * processing of data which returns it to the caller.
		 */
		ProtobufCMessage *msg = protobuf_c_message_unpack(
			message_desc, &esdm_rpc_client_allocator,
			header->message_length, received_data->data);
		if (msg) {
			closure(msg, closure_data);
			protobuf_c_message_free_unpacked(
				msg, &esdm_rpc_client_allocator);
			logger(LOGGER_DEBUG, LOGGER_C_RPC,
			       "Data with length %u send to client closure handler\n",
			       header->message_length);
		} else {
			logger(LOGGER_ERR, LOGGER_C_RPC,
			       "Response message not found\n");
			msg = ERR_PTR(-EFAULT);
			closure(msg, closure_data);
		}
	} else if (interrupted) {
		ProtobufCMessage *msg;

		logger(LOGGER_VERBOSE, LOGGER_C_RPC, "Request interrupted\n");
		msg = ERR_PTR(-EINTR);
		closure(msg, closure_data);
	} else {
		ProtobufCMessage *msg;

		logger(LOGGER_VERBOSE, LOGGER_C_RPC,
		       "Server returned with an error\n");
		msg = ERR_PTR(-EINTR);
		closure(msg, closure_data);
	}

out:
	memset_secure(buf, 0, total_received);
	memset_secure(tls.buf, 0, tls.consumed);
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
	int ret;

	mutex_w_lock(&rpc_conn->lock);

	do {
		CKINT(esdm_connect_proto_service(rpc_conn));

		/* Pack the protobuf-c data and send it over the wire */
		CKINT_LOG(esdm_rpc_client_pack(input, method_index, rpc_conn),
			  "Sending of data failed: %d\n", ret);

		/* Receive data */
		CKINT_LOG(esdm_rpc_client_read_handler(rpc_conn, method->output,
						       closure, closure_data),
			  "Receiving of data failed: %d\n", ret);
	} while (ret == EAGAIN);

out:
	mutex_w_unlock(&rpc_conn->lock);
}

static void esdm_client_destroy(ProtobufCService *service)
{
	esdm_rpc_client_connection_t *rpc_conn =
		(esdm_rpc_client_connection_t *)service;

	mutex_w_lock(&rpc_conn->lock);
	if (rpc_conn->fd >= 0) {
		close(rpc_conn->fd);
		rpc_conn->fd = -1;
	}
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

	mutex_w_init(&rpc_conn->ref_cnt, 0, 1);
	rpc_conn->fd = -1;
	mutex_w_init(&rpc_conn->lock, 0, 1);
	atomic_set(&rpc_conn->state, esdm_rpcc_initialized);

out:
	return ret;
}

/******************************************************************************
 * General service handlers
 ******************************************************************************/
static uint32_t esdm_rpcc_max_nodes = 0xffffffff;

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
	const struct timespec abstime = { .tv_sec = 1, .tv_nsec = 0 };
	esdm_rpc_client_connection_t *rpc_conn_array = *rpc_conn;
	esdm_rpc_client_connection_t *rpc_conn_p = rpc_conn_array;
	uint32_t i, num_conn = *num;

	if (!rpc_conn_array)
		return;

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
		if (mutex_w_timedlock(&rpc_conn_p->ref_cnt, &abstime))
			mutex_w_unlock(&rpc_conn_p->ref_cnt);

		/* Terminate the handle */
		esdm_fini_proto_service(rpc_conn_p);
	}

	free(rpc_conn_array);
	*rpc_conn = NULL;
	*num = 0;
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

	*rpc_conn = tmp;
	*num_conn = nodes;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
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
	int ret = 0;

	CKNULL(rpc_conn_array, -EFAULT);
	CKNULL(ret_rpc_conn, -EFAULT);

	rpc_conn_p = rpc_conn_array + node;

	/*
	 * Wait until the previous call completed - each connection handle is
	 * has only one caller at one given time. Lock the ref_cnt if we
	 * obtained the connection handle.
	 */
	mutex_w_lock(&rpc_conn_p->ref_cnt);

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
	return esdm_rpcc_init_service(&priv_access__descriptor,
				      ESDM_RPC_PRIV_SOCKET, interrupt_func,
				      &priv_rpc_conn, &priv_rpc_conn_num);
}

DSO_PUBLIC
void esdm_rpcc_fini_priv_service(void)
{
	esdm_rpcc_fini_service(&priv_rpc_conn, &priv_rpc_conn_num);
}
