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

#include "esdm.h"
#include "esdm_rpc_privileges.h"
#include "esdm_rpc_service.h"
#include "priv_access.pb-c.h"

void esdm_rpc_rnd_add_to_ent_cnt(PrivAccess_Service *service,
				 const RndAddToEntCntRequest *request,
				 RndAddToEntCntResponse_Closure closure,
				 void *closure_data)
{
	RndAddToEntCntResponse response = RND_ADD_TO_ENT_CNT_RESPONSE__INIT;
	(void)service;

	if (request == NULL) {
		response.ret = -EFAULT;
		closure (&response, closure_data);
	} else if (!esdm_rpc_client_is_privileged(closure_data)) {
		response.ret = -EPERM;
		closure (&response, closure_data);
	} else {
		uint32_t ent_count_bits = esdm_get_aux_ent() + request->entcnt;
		uint32_t digestsize_bits = esdm_get_digestsize();

		if (ent_count_bits > digestsize_bits)
			ent_count_bits = digestsize_bits;
		esdm_pool_set_entropy(ent_count_bits);

		response.ret = 0;
		closure (&response, closure_data);
	}
}
