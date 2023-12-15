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

struct esdm_get_seed_buf {
	ssize_t ret;
	uint8_t *buf;
	size_t buflen;
};

static void esdm_rpcc_get_seed_cb(const GetSeedResponse *response,
				  void *closure_data)
{
	struct esdm_get_seed_buf *buffer =
		(struct esdm_get_seed_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);

	buffer->ret = response->ret;
	buffer->buflen = min_size(response->randval.len, buffer->buflen);
	memcpy(buffer->buf, response->randval.data, buffer->buflen);

	/* Zeroization of response is handled in esdm_rpc_client_read_handler */
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_seed_int(uint8_t *buf, size_t buflen, unsigned int flags,
			       void *int_data)
{
	GetSeedRequest msg = GET_SEED_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_get_seed_buf buffer;
	ssize_t ret = 0;
	int noblock = flags & ESDM_GET_SEED_NONBLOCK;

	CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));

	buffer.ret = -ETIMEDOUT;
	buffer.buf = buf;
	buffer.buflen = buflen;

	msg.len = buflen;
	msg.flags = flags;

	for (;;) {
		unpriv_access__rpc_get_seed(&rpc_conn->service, &msg,
					    esdm_rpcc_get_seed_cb, &buffer);

		ret = buffer.ret;
		if (ret >= 0)
			esdm_test_shm_status_add_rpc_client_written(
				buffer.buflen);
		if (noblock || ret != -EAGAIN)
			break;

		/*
		 * The server-side always invokes the command non-blocking.
		 * Thus, we need to loop, in case the caller did not request
		 * non-blocking and ESDM cannot deliver data.
		 */
		nanosleep(&esdm_client_poll_ts, NULL);
	}

out:
	esdm_rpcc_put_unpriv_service(rpc_conn);
	return ret;
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_seed(uint8_t *buf, size_t buflen, unsigned int flags)
{
	return esdm_rpcc_get_seed_int(buf, buflen, flags, NULL);
}
