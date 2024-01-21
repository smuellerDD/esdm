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
#include <string.h>

#include "esdm_logger.h"
#include "esdm_rpc_protocol_helper.h"
#include "esdm_rpc_service.h"

static int esdm_rpc_write_data_to_buf(struct esdm_rpc_write_data_buf *write_buf,
				      const uint8_t *data, size_t len)
{
	if (write_buf->dst_written + len > (ESDM_RPC_MAX_MSG_SIZE))
		return -EOVERFLOW;

	memcpy(write_buf->dst_buf + write_buf->dst_written, data, len);
	write_buf->dst_written += len;

	esdm_logger(LOGGER_DEBUG2, LOGGER_C_RPC, "%zu bytes written\n", len);

	return 0;
}

void esdm_rpc_append_data(ProtobufCBuffer *buffer, size_t len,
			  const uint8_t *data)
{
	struct esdm_rpc_write_data_buf *write_buf =
		(struct esdm_rpc_write_data_buf *)buffer;
	int ret = esdm_rpc_write_data_to_buf(write_buf, data, len);

	if (ret < 0)
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Submission of payload data failed with error %d\n",
			    ret);
}
