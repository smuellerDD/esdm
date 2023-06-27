/*
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

#include "esdm.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "logger.h"
#include "memset_secure.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

void esdm_rpc_get_seed(UnprivAccess_Service *service,
		       const GetSeedRequest *request,
		       GetSeedResponse_Closure closure,
		       void *closure_data)
{
	GetSeedResponse response = GET_SEED_RESPONSE__INIT;
	uint64_t rndval[ESDM_RPC_MAX_DATA / sizeof(uint64_t)];
	(void) service;

	if (request == NULL || request->len > sizeof(rndval)) {
		response.ret = -(int32_t)sizeof(rndval);
		closure(&response, closure_data);
	} else {
		/* TODO: make 280 dependent on output size */
		memset(rndval, 0, 280);
		response.ret = esdm_get_seed(rndval, request->len,
					     request->flags |
					     ESDM_GET_SEED_NONBLOCK);

		if (response.ret >= 0) {
			esdm_test_shm_status_add_rpc_server_written(rndval[0]);
			response.randval.data = (uint8_t *)rndval;
			response.randval.len = rndval[0] + sizeof(uint64_t);
		} else if (response.ret == -EMSGSIZE) {
			response.randval.data = (uint8_t *)rndval;
			response.randval.len = sizeof(uint64_t);
		}

		closure(&response, closure_data);

		memset_secure(rndval, 0, sizeof(rndval));
	}
}
