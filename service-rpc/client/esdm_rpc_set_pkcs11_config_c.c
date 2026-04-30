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

#include "esdm_rpc_client_helper.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "esdm_logger.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_set_pkcs11_config_buf {
	int ret;
};

static void
esdm_rpcc_set_pkcs11_config_cb(const SetPkcs11ConfigResponse *response,
			       void *closure_data)
{
	struct esdm_set_pkcs11_config_buf *buffer =
		(struct esdm_set_pkcs11_config_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);
	buffer->ret = response->ret;
}

DSO_PUBLIC
int esdm_rpcc_set_pkcs11_config_int(const char *token_label, const char *pin,
				    void *int_data)
{
	SetPkcs11ConfigRequest msg = SET_PKCS11_CONFIG_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_set_pkcs11_config_buf buffer;
	int ret = 0;

	if (token_label) {
		msg.set_token_label = true;
		msg.token_label = (char *)token_label;
	}
	if (pin) {
		msg.set_pin = true;
		msg.pin = (char *)pin;
	}

	if (!msg.set_token_label && !msg.set_pin)
		return -EINVAL;

	CKINT(esdm_rpcc_get_priv_service(&rpc_conn, int_data));

	buffer.ret = -ETIMEDOUT;

	priv_access__rpc_set_pkcs11_config(&rpc_conn->service, &msg,
					   esdm_rpcc_set_pkcs11_config_cb,
					   &buffer);

	ret = buffer.ret;

out:
	esdm_rpcc_put_priv_service(rpc_conn);
	return ret;
}

DSO_PUBLIC
int esdm_rpcc_set_pkcs11_config(const char *token_label, const char *pin)
{
	return esdm_rpcc_set_pkcs11_config_int(token_label, pin, NULL);
}
