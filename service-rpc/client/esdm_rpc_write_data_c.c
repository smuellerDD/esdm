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
#include <stdio.h>

#include "esdm_rpc_client.h"
#include "esdm_rpc_client_helper.h"
#include "esdm_rpc_service.h"
#include "math_helper.h"
#include "logger.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_write_data_buf {
	int ret;
};

static void
esdm_rpcc_write_data_cb(const WriteDataResponse *response, void *closure_data)
{
	struct esdm_write_data_buf *buffer =
			(struct esdm_write_data_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);
	buffer->ret = response->ret;
}

DSO_PUBLIC
int esdm_rpcc_write_data_int(const uint8_t *data_buf, size_t data_buf_len,
			     void *int_data)
{
	WriteDataRequest msg = WRITE_DATA_REQUEST__INIT;
	struct esdm_rpc_client_connection *rpc_conn = NULL;
	struct esdm_write_data_buf buffer;
	int ret = 0;

	CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));

	while (data_buf_len) {
		size_t todo = min_size(data_buf_len, ESDM_RPC_MAX_DATA);

		buffer.ret = -ETIMEDOUT;

		//TODO unconstify
		msg.data.data = (uint8_t *)data_buf;
		msg.data.len = todo;

		unpriv_access__rpc_write_data(&rpc_conn->service, &msg,
					      esdm_rpcc_write_data_cb, &buffer);

		ret = buffer.ret;
		if (ret)
			goto out;

		esdm_test_shm_status_add_rpc_client_written(todo);
		data_buf_len -= todo;
		data_buf += todo;
	}

out:
	esdm_rpcc_put_unpriv_service(rpc_conn);
	return ret;
}

DSO_PUBLIC
int esdm_rpcc_write_data(const uint8_t *data_buf, size_t data_buf_len)
{
	return esdm_rpcc_write_data_int(data_buf, data_buf_len, NULL);
}
