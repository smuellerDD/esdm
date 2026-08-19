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
#include "esdm_logger.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_get_drng_status_json_buf {
	int ret;
	char *buf;
	size_t buflen;
};

static void esdm_rpcc_drng_status_json_cb(const StatusResponse *response,
					  void *closure_data)
{
	struct esdm_get_drng_status_json_buf *buffer =
		(struct esdm_get_drng_status_json_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);
	buffer->ret = response->ret;
	if (response->ret < 0)
		return;
	if (!response->buffer || !buffer->buflen || !buffer->buf) {
		buffer->ret = -EFAULT;
		return;
	}

	/* Not truncated into the caller's buffer either - see the server */
	if (snprintf(buffer->buf, buffer->buflen, "%s", response->buffer) >=
	    (int)buffer->buflen) {
		buffer->buf[0] = '\0';
		buffer->ret = -EMSGSIZE;
	}
}

/* Ask for one DRNG instance, either the one of @node or the PR instance */
static int esdm_rpcc_drng_status_json_one(uint32_t node, bool pr, char *buf,
					  size_t buflen, void *int_data)
{
	DrngStatusRequest msg = DRNG_STATUS_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_get_drng_status_json_buf buffer = {
		.ret = -ETIMEDOUT,
		.buf = buf,
		.buflen = buflen,
	};
	int ret;

	if (buf && buflen)
		buf[0] = '\0';

	CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));

	msg.maxlen = ESDM_RPC_MAX_DATA;
	msg.node = node;
	msg.prediction_resistance = pr;
	unpriv_access__rpc_drng_status_json(&rpc_conn->service, &msg,
					    esdm_rpcc_drng_status_json_cb,
					    &buffer);

	/*
	 * The callback only runs once a response was received - without one
	 * buffer.ret still holds the placeholder set above, which would
	 * report every transport failure as a timeout.
	 */
	ret = esdm_rpcc_last_error(rpc_conn);
	if (!ret)
		ret = buffer.ret;

out:
	esdm_rpcc_put_unpriv_service(rpc_conn);
	return ret;
}

DSO_PUBLIC
int esdm_rpcc_drng_status_json_int(uint32_t node, char *buf, size_t buflen,
				   void *int_data)
{
	return esdm_rpcc_drng_status_json_one(node, false, buf, buflen,
					      int_data);
}

DSO_PUBLIC
int esdm_rpcc_drng_status_json(uint32_t node, char *buf, size_t buflen)
{
	return esdm_rpcc_drng_status_json_int(node, buf, buflen, NULL);
}

DSO_PUBLIC
int esdm_rpcc_drng_status_pr_json_int(char *buf, size_t buflen, void *int_data)
{
	return esdm_rpcc_drng_status_json_one(0, true, buf, buflen, int_data);
}

DSO_PUBLIC
int esdm_rpcc_drng_status_pr_json(char *buf, size_t buflen)
{
	return esdm_rpcc_drng_status_pr_json_int(buf, buflen, NULL);
}
