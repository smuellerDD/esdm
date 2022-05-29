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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "logger.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_get_random_bytes_min_buf {
	ssize_t ret;
	uint8_t *buf;
	size_t buflen;
};

static void
esdm_rpcc_get_random_bytes_min_cb(const GetRandomBytesMinResponse *response,
				  void *closure_data)
{
	struct esdm_get_random_bytes_min_buf *buffer =
			(struct esdm_get_random_bytes_min_buf *)closure_data;

	if (!response) {
		logger(LOGGER_DEBUG, LOGGER_C_RPC,
		       "missing data - connection interrupted\n");
		buffer->ret = -EINTR;
		return;
	}

	if (response->ret < 0) {
		buffer->ret = response->ret;
		return;
	}

	buffer->ret = min_t(ssize_t, response->randval.len, buffer->buflen);
	memcpy(buffer->buf, response->randval.data, (size_t)buffer->ret);
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_min(uint8_t *buf, size_t buflen)
{
	GetRandomBytesMinRequest msg = GET_RANDOM_BYTES_FULL_REQUEST__INIT;
	struct esdm_rpc_client_connection *rpc_conn;
	struct esdm_get_random_bytes_min_buf buffer;
	size_t maxbuflen = buflen, orig_buflen = buflen;
	ssize_t ret = 0;

	CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn));

	while (buflen) {
		buffer.ret = -ETIMEDOUT;
		buffer.buf = buf;
		buffer.buflen = buflen;

		msg.len = maxbuflen;
		unpriv_access__rpc_get_random_bytes_min(
			&rpc_conn->service, &msg,
			esdm_rpcc_get_random_bytes_min_cb, &buffer);

		if (buffer.ret < -255) {
			maxbuflen = (size_t)(-buffer.ret);
			continue;
		} else if (buffer.ret < 0) {
			ret = buffer.ret;
			goto out;
		}

		buflen -= (size_t)buffer.ret;
		buf += buffer.ret;
	}

out:
	return (ret < 0) ? ret : (ssize_t)orig_buflen;
}
