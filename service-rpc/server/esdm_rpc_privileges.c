/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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
#include <sys/socket.h>
#include <sys/un.h>

#include "esdm_rpc_privileges.h"
#include "logger.h"
#include "protobuf-c-rpc/protobuf-c-rpc.h"
#include "unpriv_access.pb-c.h"

/*
 * WARNING This is an ugly hack to get access to the file descriptor of the
 * communication. This needs to be replaced with a service to be offered by
 * the Protobuf-C-RPC code.
 */
typedef struct _ServerRequest ServerRequest;
typedef struct _ServerConnection ServerConnection;
typedef struct _ProtobufC_RPC_Server ProtobufC_RPC_Server;
struct _ServerRequest
{
  uint32_t request_id;                  /* in little-endian */
  uint32_t method_index;                /* in native-endian */
  ServerConnection *conn;
  ProtobufC_RPC_Server *server;
  union {
    /* if conn != NULL, then the request is alive: */
    struct { ServerRequest *prev, *next; } alive;

    /* if conn == NULL, then the request is defunct: */
    struct { ProtobufCAllocator *allocator; } defunct;

    /* well, if it is in the recycled list, then it's recycled :/ */
    struct { ServerRequest *next; } recycled;
  } info;
};

struct _ServerConnection
{
  int fd;
  ProtobufCRPCDataBuffer incoming, outgoing;

  ProtobufC_RPC_Server *server;
  ServerConnection *prev, *next;

  unsigned n_pending_requests;
  ServerRequest *first_pending_request, *last_pending_request;
};

struct _ProtobufC_RPC_Server
{
  ProtobufCRPCDispatch *dispatch;
  ProtobufCAllocator *allocator;
  ProtobufCService *underlying;
  ProtobufC_RPC_AddressType address_type;
  char *bind_name;
  ServerConnection *first_connection, *last_connection;
  ProtobufC_RPC_FD listening_fd;

  ServerRequest *recycled_requests;

  /* multithreading support */
  ProtobufC_RPC_IsRpcThreadFunc is_rpc_thread_func;
  void * is_rpc_thread_data;
  int proxy_pipe[2];
  unsigned proxy_extra_data_len;
  uint8_t proxy_extra_data[sizeof (void*)];

  ProtobufC_RPC_Error_Func error_handler;
  void *error_handler_data;

  ProtobufC_RPC_Protocol rpc_protocol;

  /* configuration */
  unsigned max_pending_requests_per_connection;
};

bool esdm_rpc_client_is_privileged(void *closure_data)
{
	ServerRequest *server_request = closure_data;
	ServerConnection *conn = server_request->conn;
	struct ucred cred;
	socklen_t len = sizeof(cred);

	if (getsockopt(conn->fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		return false;

	if (cred.uid == 0) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Remote client is privileged\n");
		return true;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Remote client is not privileged\n");
	return false;
}

void esdm_rpc_kick_dispatcher(void *closure_data)
{
	ServerRequest *server_request = closure_data;
	ServerConnection *conn = server_request->conn;

	protobuf_c_rpc_dispatch_run(conn->server->dispatch);
}
