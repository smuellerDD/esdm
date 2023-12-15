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

#include "esdm_rpc_client_helper.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "esdm_logger.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_poolsize_buf {
	int ret;
	unsigned int poolsize;
};

static void esdm_rpcc_get_poolsize_cb(const GetPoolsizeResponse *response,
				      void *closure_data)
{
	struct esdm_poolsize_buf *buffer =
		(struct esdm_poolsize_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);
	buffer->ret = response->ret;
	buffer->poolsize = response->poolsize;
}

DSO_PUBLIC
int esdm_rpcc_get_poolsize_int(unsigned int *poolsize, void *int_data)
{
	GetPoolsizeRequest msg = GET_POOLSIZE_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_poolsize_buf buffer;
	int ret = 0;

	CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));

	buffer.ret = -ETIMEDOUT;

	unpriv_access__rpc_get_poolsize(&rpc_conn->service, &msg,
					esdm_rpcc_get_poolsize_cb, &buffer);

	ret = buffer.ret;
	if (poolsize)
		*poolsize = buffer.poolsize;

out:
	esdm_rpcc_put_unpriv_service(rpc_conn);
	return ret;
}

DSO_PUBLIC
int esdm_rpcc_get_poolsize(unsigned int *poolsize)
{
	return esdm_rpcc_get_poolsize_int(poolsize, NULL);
}
