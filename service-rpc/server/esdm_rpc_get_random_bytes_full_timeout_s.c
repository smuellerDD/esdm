/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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
#include "esdm_logger.h"
#include "memset_secure.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

void esdm_rpc_get_random_bytes_full_timeout(
	UnprivAccess_Service *service,
	const GetRandomBytesFullTimeoutRequest *request,
	GetRandomBytesFullTimeoutResponse_Closure closure, void *closure_data)
{
	GetRandomBytesFullTimeoutResponse response =
		GET_RANDOM_BYTES_FULL_TIMEOUT_RESPONSE__INIT;
	uint8_t rndval[ESDM_RPC_MAX_DATA];

	(void)service;

	if (request == NULL || request->len > sizeof(rndval)) {
		response.ret = -(int32_t)sizeof(rndval);
		closure(&response, closure_data);
	} else {
		struct timespec ts = {
			.tv_sec = (time_t)request->tv_sec,
			.tv_nsec = request->tv_nsec,
		};

		response.ret = esdm_get_random_bytes_full_timeout(
			rndval, request->len, &ts);

		if (response.ret > 0) {
			esdm_test_shm_status_add_rpc_server_written(
				(size_t)response.ret);
			response.randval.data = rndval;
			response.randval.len = (size_t)response.ret;
		}
		closure(&response, closure_data);

		memset_secure(rndval, 0, sizeof(rndval));
	}
}
