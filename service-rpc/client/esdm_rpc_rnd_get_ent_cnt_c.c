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
#include "helper.h"
#include "logger.h"
#include "visibility.h"

struct esdm_rnd_get_ent_cnt_buf {
	protobuf_c_boolean is_done;
	int ret;
	unsigned int entcnt;
};

static void
esdm_rpcc_rnd_get_ent_cnt_cb(const RndGetEntCntResponse *response,
			     void *closure_data)
{
	struct esdm_rnd_get_ent_cnt_buf *buffer =
			(struct esdm_rnd_get_ent_cnt_buf *)closure_data;

	if (!response) {
		logger(LOGGER_DEBUG, LOGGER_C_RPC,
		       "missing data - connection interrupted\n");
		buffer->ret = -EINTR;
		goto out;
	}

	buffer->ret = response->ret;
	buffer->entcnt = response->entcnt;

out:
	buffer->is_done = 1;
}

DSO_PUBLIC
int esdm_rpcc_rnd_get_ent_cnt(unsigned int *entcnt)
{
	RndGetEntCntRequest msg = RND_GET_ENT_CNT_REQUEST__INIT;
	struct esdm_dispatcher *disp;
	struct esdm_rnd_get_ent_cnt_buf buffer;
	int ret = 0;

	ret = esdm_disp_get_unpriv(&disp);
	if (ret)
		return ret;

	buffer.is_done = 0;
	buffer.ret = -ETIMEDOUT;

	unpriv_access__rpc_rnd_get_ent_cnt(disp->service, &msg,
					   esdm_rpcc_rnd_get_ent_cnt_cb,
					   &buffer);
	while (!buffer.is_done)
		protobuf_c_rpc_dispatch_run(disp->dispatch);

	ret = buffer.ret;
	if (entcnt)
		*entcnt = buffer.entcnt;

	esdm_disp_put_unpriv(disp);
	return ret;
}
