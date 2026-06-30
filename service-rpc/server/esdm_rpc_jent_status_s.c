/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
#include <stdlib.h>
#include <string.h>

#include "esdm.h"
#include "esdm_rpc_service.h"
#include "math_helper.h"
#include "unpriv_access.pb-c.h"
#include "esdm_es_jent.h"

void esdm_rpc_jent_status(UnprivAccess_Service *service,
			  const StatusRequest *request,
			  StatusResponse_Closure closure,
			  void *closure_data)
{
	StatusResponse response = STATUS_RESPONSE__INIT;
	char *status;
	int ret;
	(void)service;

	if (request == NULL) {
		response.ret = -(int32_t)ESDM_RPC_MAX_DATA;
		closure(&response, closure_data);
		return;
	}

	/*
	 * Use calloc so the buffer is always NUL-terminated: esdm_jent_status()
	 * leaves it untouched when the Jitter RNG is not (yet) initialized, and
	 * the buffer is subsequently packed as a string (strlen). A malloc'd
	 * buffer would otherwise leak uninitialized process heap to the
	 * unprivileged client and could be read out of bounds.
	 */
	status = calloc(1, ESDM_RPC_MAX_DATA);
	if (!status) {
		response.ret = -ENOMEM;
		closure(&response, closure_data);
		return;
	}

	ret = esdm_jent_status(status,
			       min_uint32(request->maxlen, ESDM_RPC_MAX_DATA));
	if (ret < 0) {
		/* Propagate the error; leave response.buffer at its "" default. */
		response.ret = ret;
	} else {
		response.ret = 0;
		response.buffer = status;
	}
	closure(&response, closure_data);

	free(status);
}
