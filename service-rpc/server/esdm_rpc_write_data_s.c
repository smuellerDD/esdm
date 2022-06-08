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

#include "esdm_es_aux.h"
#include "esdm_rpc_service.h"
#include "memset_secure.h"
#include "test_pertubation.h"
#include "unpriv_access.pb-c.h"

void esdm_rpc_write_data(UnprivAccess_Service *service,
			 const WriteDataRequest *request,
			 WriteDataResponse_Closure closure,
			 void *closure_data)
{
	WriteDataResponse response = WRITE_DATA_RESPONSE__INIT;
	(void)service;

	if (request == NULL || request->data.data == NULL) {
		response.ret = -EFAULT;
		closure (&response, closure_data);
	} else {
		esdm_test_shm_status_add_rpc_server_written(request->data.len);
		response.ret = esdm_pool_insert_aux(request->data.data,
						    request->data.len, 0);
		memset_secure(request->data.data, 0, request->data.len);

		/*
		 * And now force a reseed to ensure the data is properly
		 * dispersed into the DRNGs.
		 */
		esdm_drng_force_reseed();

		closure (&response, closure_data);
	}
}
