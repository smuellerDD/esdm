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
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_rnd_add_to_ent_cnt_buf {
	int ret;
};

static void
esdm_rpcc_rnd_add_to_ent_cnt_cb(const RndAddToEntCntResponse *response,
			        void *closure_data)
{
	struct esdm_rnd_add_to_ent_cnt_buf *buffer =
			(struct esdm_rnd_add_to_ent_cnt_buf *)closure_data;

	if (IS_ERR(response)) {
		logger(LOGGER_DEBUG, LOGGER_C_RPC,
		       "missing data - connection interrupted\n");
		buffer->ret = (int)PTR_ERR(response);
		return;
	}

	buffer->ret = response->ret;
}

DSO_PUBLIC
int esdm_rpcc_rnd_add_to_ent_cnt_int(unsigned int entcnt, void *int_data)
{
	RndAddToEntCntRequest msg = RND_ADD_TO_ENT_CNT_REQUEST__INIT;
	struct esdm_rpc_client_connection *rpc_conn;
	struct esdm_rnd_add_to_ent_cnt_buf buffer;
	int ret = 0;

	CKINT(esdm_rpcc_get_priv_service(&rpc_conn, int_data));

	buffer.ret = -ETIMEDOUT;

	msg.entcnt = entcnt;
	priv_access__rpc_rnd_add_to_ent_cnt(&rpc_conn->service, &msg,
				esdm_rpcc_rnd_add_to_ent_cnt_cb, &buffer);

	ret = buffer.ret;

out:
	return ret;
}

DSO_PUBLIC
int esdm_rpcc_rnd_add_to_ent_cnt(unsigned int entcnt)
{
	return esdm_rpcc_rnd_add_to_ent_cnt_int(entcnt, NULL);
}
