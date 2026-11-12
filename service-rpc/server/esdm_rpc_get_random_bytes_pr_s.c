/*
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
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>

#include "esdm.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

/*
 * One PR request is served at a time; the others get -EAGAIN and retry later,
 * so a privileged consumer (the kernel seeder in PR mode) would rarely win
 * against unprivileged clients hammering PR. Waiting would block the worker's
 * event loop, so a privileged request that lost reserves the next turn:
 * unprivileged ones are turned away long enough for its retry to come.
 */
#define ESDM_RPCS_PR_PRIV_RESERVE_NS (3LL * 1000000000LL)
static atomic_llong esdm_rpcs_pr_priv_reserved_until = 0;

static long long esdm_rpcs_pr_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static ssize_t esdm_rpcs_pr_get(uint8_t *buf, size_t len, void *closure_data)
{
	bool privileged = esdm_rpc_client_is_privileged(closure_data);
	long long now = esdm_rpcs_pr_now_ns();
	ssize_t ret;

	if (!privileged && now < atomic_load(&esdm_rpcs_pr_priv_reserved_until))
		return -EAGAIN;

	ret = esdm_get_random_bytes_pr_noblock(buf, len);

	if (privileged)
		atomic_store(&esdm_rpcs_pr_priv_reserved_until,
			     ret == -EAGAIN ?
				     now + ESDM_RPCS_PR_PRIV_RESERVE_NS :
				     0);

	return ret;
}

void esdm_rpc_get_random_bytes_pr(UnprivAccess_Service *service,
				  const GetRandomBytesRequest *request,
				  RandValResponse_Closure closure,
				  void *closure_data)
{
	RandValResponse response = RAND_VAL_RESPONSE__INIT;
	uint8_t rndval[ESDM_RPC_MAX_DATA];
	(void)service;

	if (request == NULL || request->len > ESDM_RPC_MAX_PR_REQUEST_SIZE) {
		response.ret = -ESDM_RPC_MAX_PR_REQUEST_SIZE;
		closure(&response, closure_data);
	} else {
		response.ret = (int)esdm_rpcs_pr_get(rndval, request->len,
						     closure_data);

		if (response.ret > 0) {
			esdm_test_shm_status_add_rpc_server_written(
				(size_t)response.ret);
			response.randval.data = rndval;
			response.randval.len = (size_t)response.ret;
		}
		closure(&response, closure_data);

		/*
		 * Only the first request->len bytes can ever hold generated
		 * secret data (request->len is bounded by
		 * ESDM_RPC_MAX_PR_REQUEST_SIZE above). Avoid wiping the whole
		 * ~64KB buffer on every call.
		 */
		memset_secure(rndval, 0, (size_t)request->len);
	}
}
