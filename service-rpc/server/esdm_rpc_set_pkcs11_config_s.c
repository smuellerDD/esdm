/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

#include "esdm_es_pkcs11.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "memset_secure.h"
#include "priv_access.pb-c.h"

void esdm_rpc_set_pkcs11_config(PrivAccess_Service *service,
				const SetPkcs11ConfigRequest *request,
				SetPkcs11ConfigResponse_Closure closure,
				void *closure_data)
{
	SetPkcs11ConfigResponse response = SET_PKCS11_CONFIG_RESPONSE__INIT;
	int ret = 0;
	(void)service;

	if (request == NULL) {
		response.ret = -EFAULT;
		closure(&response, closure_data);
		return;
	}

	if (!esdm_rpc_client_is_privileged(closure_data)) {
		response.ret = -EPERM;
		closure(&response, closure_data);
		return;
	}

	/*
	 * Apply the token label first so that any subsequent PIN-based login
	 * targets the freshly opened slot. If applying the label fails, do not
	 * touch the PIN.
	 */
	if (request->set_token_label) {
		if (request->token_label == NULL) {
			response.ret = -EINVAL;
			closure(&response, closure_data);
			return;
		}

		ret = esdm_es_pkcs11_set_token_label(request->token_label);
		if (ret != 0)
			goto out;
	}

	if (request->set_pin) {
		if (request->pin == NULL) {
			response.ret = -EINVAL;
			closure(&response, closure_data);
			return;
		}

		ret = esdm_es_pkcs11_set_pin(request->pin);
	}

out:
	response.ret = ret;
	closure(&response, closure_data);

	/*
	 * Best-effort scrubbing of the in-memory copy of the PIN held by the
	 * decoded request. The protobuf-c allocator will free the buffer next.
	 */
	if (request->set_pin && request->pin != NULL)
		memset_secure(request->pin, 0, strlen(request->pin));
}
