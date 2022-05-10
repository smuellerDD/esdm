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

#include <errno.h>
#include <stdlib.h>

#include "esdm.h"
#include "esdm_rpc_privileges.h"
#include "esdm_rpc_service.h"
#include "logger.h"
#include "memset_secure.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

struct esdm_rpc_thread_data {
	size_t requested_len;
	GetRandomBytesFullResponse_Closure closure;
	void *closure_data;
	bool free;
};

/*
 * Handler function wrapped by threading
 */
static int _esdm_rpc_get_random_bytes_full_thread(void *args)
{
	struct esdm_rpc_thread_data *tdata = args;
	GetRandomBytesFullResponse_Closure closure;
	size_t requested_len;
	void *closure_data;
	GetRandomBytesFullResponse response =
					GET_RANDOM_BYTES_FULL_RESPONSE__INIT;
	uint8_t rndval[ESDM_RPC_MAX_MSG_SIZE];

	requested_len = tdata->requested_len;
	closure = tdata->closure;
	closure_data = tdata->closure_data;

	response.ret = (int)esdm_get_random_bytes_full(rndval, requested_len);

	if (response.ret > 0) {
		response.randval.data = rndval;
		response.randval.len = (size_t)response.ret;
	}
	closure(&response, closure_data);
	if (tdata->free) {
		esdm_rpc_kick_dispatcher(closure_data);
		free(tdata);
	}

	memset_secure(rndval, 0, sizeof(rndval));

	return 0;
}

/* Fallback for synchronous operation when thread start failed */
static void
esdm_rpc_get_random_bytes_full_sync(const GetRandomBytesFullRequest *request,
				    GetRandomBytesFullResponse_Closure closure,
				    void *closure_data)
{
	struct esdm_rpc_thread_data tdata_stack;

	tdata_stack.requested_len = request->len;
	tdata_stack.closure = closure;
	tdata_stack.closure_data = closure_data;
	tdata_stack.free = false;

	logger(LOGGER_DEBUG, LOGGER_C_RPC, "Using synchronous fallback\n");

	_esdm_rpc_get_random_bytes_full_thread(&tdata_stack);
}

/*
 * This code does not work as the closure is not allowed to be called in a
 * different thread.
 */
#if 0
/* Spawning thread for handling request */
static void
esdm_rpc_get_random_bytes_full_thread(const GetRandomBytesFullRequest *request,
				      GetRandomBytesFullResponse_Closure closure,
				      void *closure_data)
{
	struct esdm_rpc_thread_data *tdata;

	tdata = malloc(sizeof(*tdata));
	if (!tdata) {
		esdm_rpc_get_random_bytes_full_sync(request, closure,
						    closure_data);
	} else {
		tdata->requested_len = request->len;
		tdata->closure = closure;
		tdata->closure_data = closure_data;
		tdata->free = true;

		logger(LOGGER_DEBUG, LOGGER_C_RPC,
		       "Using asynchronous DRNG handler\n");

		if (thread_start(_esdm_rpc_get_random_bytes_full_thread,
				 tdata, 0, NULL)) {
			free(tdata);
			esdm_rpc_get_random_bytes_full_sync(request, closure,
							    closure_data);
		}
	}
}
#endif

void esdm_rpc_get_random_bytes_full(UnprivAccess_Service *service,
				    const GetRandomBytesFullRequest *request,
				    GetRandomBytesFullResponse_Closure closure,
				    void *closure_data)
{
	(void) service;

	if (request == NULL || request->len > ESDM_RPC_MAX_MSG_SIZE) {
		GetRandomBytesFullResponse response =
					GET_RANDOM_BYTES_FULL_RESPONSE__INIT;
		response.ret = -(int32_t)ESDM_RPC_MAX_MSG_SIZE;
		closure (&response, closure_data);
	} else {
#if 0
		esdm_rpc_get_random_bytes_full_thread(request, closure,
						      closure_data);
#endif
		esdm_rpc_get_random_bytes_full_sync(request, closure,
						    closure_data);
	}
}
