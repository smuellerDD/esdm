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
#include <string.h>
#include <sys/types.h>

#include "esdm_rpc_client_helper.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_service.h"
#include "math_helper.h"
#include "esdm_logger.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_get_random_bytes_pr_noblock_buf {
	ssize_t ret;
	uint8_t *buf;
	size_t buflen;
};

static void
esdm_rpcc_get_random_bytes_pr_noblock_cb(const RandValResponse *response,
					 void *closure_data)
{
	struct esdm_get_random_bytes_pr_noblock_buf *buffer =
		(struct esdm_get_random_bytes_pr_noblock_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);

	if (response->ret <= 0) {
		buffer->ret = response->ret;
		return;
	}

	if (!response->randval.data || !response->randval.len) {
		buffer->ret = -EFAULT;
		return;
	}

	buffer->ret = (ssize_t)min_size(response->randval.len, buffer->buflen);
	memcpy(buffer->buf, response->randval.data, (size_t)buffer->ret);

	/* Zeroization of response is handled in esdm_rpc_client_read_handler */
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_pr_noblock_int(uint8_t *buf, size_t buflen,
						  void *int_data)
{
	GetRandomBytesRequest msg = GET_RANDOM_BYTES_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_get_random_bytes_pr_noblock_buf buffer;
	ssize_t ret = 0;

	if (!buflen)
		return 0;

	/* One chunk, see esdm_rpcc_get_random_bytes_pr_int() for the size */
	buffer.ret = -ETIMEDOUT;
	buffer.buf = buf;
	buffer.buflen = min_size(buflen, ESDM_RPC_MAX_PR_REQUEST_SIZE);
	msg.len = buffer.buflen;

	CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));

	unpriv_access__rpc_get_random_bytes_pr(
		&rpc_conn->service, &msg,
		esdm_rpcc_get_random_bytes_pr_noblock_cb, &buffer);

	/* See esdm_rpcc_get_random_bytes_pr_int() */
	ret = esdm_rpcc_last_error(rpc_conn);
	if (ret)
		goto out;

	/*
	 * No entropy right now: ask again later, as when not seeded or with
	 * another prediction resistant request in flight.
	 */
	ret = buffer.ret ? buffer.ret : -EAGAIN;
	if (ret > 0)
		esdm_test_shm_status_add_rpc_client_written((size_t)ret);

out:
	esdm_rpcc_put_unpriv_service(rpc_conn);
	return ret;
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_pr_noblock(uint8_t *buf, size_t buflen)
{
	return esdm_rpcc_get_random_bytes_pr_noblock_int(buf, buflen, NULL);
}
