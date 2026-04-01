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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "esdm.h"
#include "esdm_rpc_service.h"
#include "math_helper.h"
#include "unpriv_access.pb-c.h"

void esdm_rpc_status(UnprivAccess_Service *service,
		     const StatusRequest *request,
		     StatusResponse_Closure closure, void *closure_data)
{
	StatusResponse response = STATUS_RESPONSE__INIT;
	char *status;
	(void)service;

	if (request == NULL) {
		response.ret = -(int32_t)ESDM_RPC_MAX_MSG_SIZE;
		closure(&response, closure_data);
		return;
	}

	size_t alloc_size = min_uint32(request->maxlen, ESDM_RPC_MAX_MSG_SIZE);

	status = malloc(alloc_size);
	if (!status) {
		response.ret = -ENOMEM;
		closure(&response, closure_data);
		return;
	}

	esdm_status(status, alloc_size);
	response.ret = 0;
	response.buffer = status;
	closure(&response, closure_data);

	free(status);
}
