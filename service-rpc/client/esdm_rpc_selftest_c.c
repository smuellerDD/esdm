/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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
#include <stdio.h>

#include "esdm_rpc_client_helper.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "esdm_logger.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_selftest_buf {
	int ret;
	struct esdm_rpcc_selftest_result result;
};

static void esdm_rpcc_selftest_cb(const SelftestResponse *response,
				  void *closure_data)
{
	struct esdm_selftest_buf *buffer =
		(struct esdm_selftest_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);
	buffer->ret = response->ret;
	buffer->result.crypto_state =
		(enum esdm_rpcc_selftest_state)response->crypto_state;
	buffer->result.es_state =
		(enum esdm_rpcc_selftest_state)response->es_state;
	buffer->result.es_sources = response->es_sources;
	buffer->result.es_failures = response->es_failures;
}

DSO_PUBLIC
int esdm_rpcc_selftest_int(struct esdm_rpcc_selftest_result *result,
			   void *int_data)
{
	EmptyRequest msg = EMPTY_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	/*
	 * Initialize every field: the callback does not run at all on a
	 * transport failure and returns early on an error response, so what is
	 * handed to the caller below would otherwise be indeterminate.
	 */
	struct esdm_selftest_buf buffer = {
		.ret = -ETIMEDOUT,
		.result = {
			.crypto_state = esdm_rpcc_selftest_undone,
			.es_state = esdm_rpcc_selftest_undone,
			.es_sources = 0,
			.es_failures = 0,
		},
	};
	int ret = 0;

	CKINT(esdm_rpcc_get_priv_service(&rpc_conn, int_data));

	priv_access__rpc_selftest(&rpc_conn->service, &msg,
				  esdm_rpcc_selftest_cb, &buffer);

	/*
	 * The callback only runs once a response was received - without one
	 * buffer.ret still holds the placeholder set above, which would
	 * report every transport failure as a timeout.
	 */
	ret = esdm_rpcc_last_error(rpc_conn);
	if (!ret)
		ret = buffer.ret;

out:
	if (result)
		*result = buffer.result;
	esdm_rpcc_put_priv_service(rpc_conn);
	return ret;
}

DSO_PUBLIC
int esdm_rpcc_selftest(struct esdm_rpcc_selftest_result *result)
{
	return esdm_rpcc_selftest_int(result, NULL);
}
