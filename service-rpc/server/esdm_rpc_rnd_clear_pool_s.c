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
#include "esdm_es_aux.h"
#include "esdm_rpc_privileges.h"
#include "esdm_rpc_service.h"
#include "priv_access.pb-c.h"

void esdm_rpc_rnd_clear_pool(PrivAccess_Service *service,
			     const RndClearPoolRequest *request,
			     RndClearPoolResponse_Closure closure,
			     void *closure_data)
{
	RndClearPoolResponse response = RND_CLEAR_POOL_RESPONSE__INIT;
	(void)request;
	(void)service;

	if (!esdm_rpc_client_is_privileged(closure_data)) {
		response.ret = -EPERM;
		closure(&response, closure_data);
	} else {
		esdm_pool_set_entropy(0);
		response.ret = 0;
		closure (&response, closure_data);
	}
}
