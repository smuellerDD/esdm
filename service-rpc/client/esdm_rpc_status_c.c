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

#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"
#include "esdm_rpc_client_dispatcher.h"
#include "visibility.h"

struct esdm_get_status_buf {
	protobuf_c_boolean is_done;
	int ret;
	char *buf;
	size_t buflen;
};

static void esdm_rpcc_status_cb(const StatusResponse *response,
			        void *closure_data)
{
	struct esdm_get_status_buf *buffer =
				(struct esdm_get_status_buf *)closure_data;
	if (!response) {
		logger(LOGGER_DEBUG, LOGGER_C_RPC,
		       "missing data - connection interrupted\n");
		buffer->ret = -EINTR;
		goto out;
	}

	buffer->ret = response->ret;
	if (response->ret < 0)
		goto out;

	snprintf(buffer->buf, buffer->buflen, "%s", response->buffer);

out:
	buffer->is_done = 1;
}

DSO_PUBLIC
int esdm_rpcc_status(char *buf, size_t buflen)
{
	StatusRequest msg = STATUS_REQUEST__INIT;
	struct esdm_dispatcher *disp;
	struct esdm_get_status_buf buffer = {
		.is_done = 0,
		.ret = -ETIMEDOUT,
		.buf = buf,
		.buflen = buflen,
	};
	int ret = 0;

	ret = esdm_disp_get_unpriv(&disp);
	if (ret)
		return ret;

	msg.maxlen = ESDM_RPC_MAX_MSG_SIZE;
	unpriv_access__rpc_status(disp->service, &msg,
				  esdm_rpcc_status_cb, &buffer);
	while (!buffer.is_done)
		protobuf_c_rpc_dispatch_run(disp->dispatch);

	ret = buffer.ret;

	esdm_disp_put_unpriv(disp);
	return ret;
}
