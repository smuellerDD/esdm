/* RPC Client: Connection handler to server
 *
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

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bool.h"
#include "atomic.h"
#include "esdm_rpc_client_connection.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "logger.h"

static int esdm_init_proto_service(const ProtobufCServiceDescriptor *descriptor,
				   const char *socket_name_template,
				   uint32_t node, struct esdm_dispatcher *disp)
{
	ProtobufC_RPC_Client *client;
	ProtobufCService *service = disp->service;
	ProtobufCRPCDispatch *dispatch = disp->dispatch;
	ProtobufCRPCDispatchTimer *timer = NULL;
	char socketname[FILENAME_MAX];
	protobuf_c_boolean is_done = 0;
	bool new_service = false;

	/* If we do not have a server definition, establish it */
	if (!service) {
		struct stat statbuf;

		/* Create path name of Unix domain socket */
		if (node)
			snprintf(socketname, sizeof(socketname), "%s%u.socket",
				 socket_name_template, node);
		else
			snprintf(socketname, sizeof(socketname), "%s.socket",
				 socket_name_template);

		/* Does the path exist? */
		if (stat(socketname, &statbuf) == -1) {
			int errsv = errno;

			if (errsv == ENOENT) {
				logger(LOGGER_DEBUG, LOGGER_C_RPC,
				       "ESDM server interface %s not available\n",
				       socketname);
			}

			return -errsv;
		}

		logger(LOGGER_DEBUG, LOGGER_C_RPC,
		       "Attempting to access ESDM server interface %s\n",
		       socketname);

		new_service = true;

		service = protobuf_c_rpc_client_new(
			PROTOBUF_C_RPC_ADDRESS_LOCAL, socketname, descriptor,
			dispatch);
		if (!service)
			return -EFAULT;
		disp->service = service;
	}

	client = (ProtobufC_RPC_Client *)service;

	/* Now, try to connect to server, if connection is not established. */
	if (!protobuf_c_rpc_client_is_connected(client)) {
		/* Set reconnect timer */
		protobuf_c_rpc_client_set_autoreconnect_period(client, 10);

		/* Set timeout */
		timer = protobuf_c_rpc_dispatch_add_timer_millis(
			dispatch, 2500, set_boolean_true, &is_done);
	}

	while (!is_done && !protobuf_c_rpc_client_is_connected(client))
		protobuf_c_rpc_dispatch_run(dispatch);

	if (timer)
		protobuf_c_rpc_dispatch_remove_timer(timer);

	/* Use EPERM to indicate that we had no permission to access the pipe */
	if (!protobuf_c_rpc_client_is_connected(client)) {
		/*
		 * If we got an error on a newly created service, attempt to
		 * re-create it during next call.
		 */
		if (new_service) {
			protobuf_c_service_destroy(service);
			disp->service = NULL;
			return -ENOENT;
		} else {
			return -EPERM;
		}
	}

	if (new_service)
		logger(LOGGER_DEBUG, LOGGER_C_RPC,
		       "Access ESDM server interface %s established\n",
		       socketname);

	return 0;
}

void esdm_fini_proto_service(struct esdm_dispatcher *disp)
{
	if (disp->service)
		protobuf_c_service_destroy(disp->service);
	disp->service = NULL;
}

int esdm_init_unpriv_proto_service(struct esdm_dispatcher *disp)
{
	/* Use the Unix domain socket as selected by current node */
	uint32_t node = esdm_curr_node();
	int ret;

	/* Get the established link */
	ret = esdm_init_proto_service(&unpriv_access__descriptor,
				      ESDM_RPC_UNPRIV_SOCKET, node, disp);

	/*
	 * If the node does not exist and we have a node different than zero
	 * (the default node), retry with the default node.
	 */
	if (ret == -ENOENT && node > 0)
		ret = esdm_init_proto_service(&unpriv_access__descriptor,
					      ESDM_RPC_UNPRIV_SOCKET, 0, disp);

	return ret;
}

int esdm_init_priv_proto_service(struct esdm_dispatcher *disp)
{
	return esdm_init_proto_service(&priv_access__descriptor,
				       ESDM_RPC_PRIV_SOCKET, 0, disp);
}
