/*
 * Error reporting shared by the ESDM OpenSSL providers
 *
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

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdarg.h>
#include <stdio.h>

#include "prov_error.h"

/*
 * The upcalls are the same for every load of a module, as is the core handle
 * for all practical purposes; the handle is kept only as a fallback for the
 * few call sites without a context to take one from.
 */
static OSSL_FUNC_core_new_error_fn *c_new_error;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
static OSSL_FUNC_core_vset_error_fn *c_vset_error;
static OSSL_FUNC_core_get_params_fn *c_get_params;
static const OSSL_CORE_HANDLE *esdm_prov_core_handle;

void esdm_prov_init_error_reporting(const OSSL_DISPATCH *in,
				    const OSSL_CORE_HANDLE *handle)
{
	for (; in != NULL && in->function_id != 0; in++) {
		switch (in->function_id) {
		case OSSL_FUNC_CORE_NEW_ERROR:
			c_new_error = OSSL_FUNC_core_new_error(in);
			break;
		case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
			c_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
			break;
		case OSSL_FUNC_CORE_VSET_ERROR:
			c_vset_error = OSSL_FUNC_core_vset_error(in);
			break;
		case OSSL_FUNC_CORE_GET_PARAMS:
			c_get_params = OSSL_FUNC_core_get_params(in);
			break;
		}
	}

	esdm_prov_core_handle = handle;
}

const char *esdm_prov_get_conf_param(const OSSL_CORE_HANDLE *handle,
				     const char *name)
{
	char *value = NULL;
	OSSL_PARAM request[2];

	if (c_get_params == NULL || handle == NULL || name == NULL)
		return NULL;

	/*
	 * Configuration parameters are handed out as UTF8 pointers into
	 * libcrypto's own storage - see OSSL_PROVIDER_get_conf_parameters().
	 */
	request[0] = OSSL_PARAM_construct_utf8_ptr(name, &value, 0);
	request[1] = OSSL_PARAM_construct_end();

	if (!c_get_params(handle, request))
		return NULL;

	return value;
}

static void esdm_prov_set_error(const OSSL_CORE_HANDLE *handle, uint32_t reason,
				const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	c_vset_error(handle, reason, fmt, args);
	va_end(args);
}

void esdm_prov_raise_error(const OSSL_CORE_HANDLE *handle,
			   enum esdm_logger_class logger_class, uint32_t reason,
			   const char *file, int line, const char *func,
			   const char *fmt, ...)
{
	char msg[256];
	va_list args;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	esdm_logger(LOGGER_ERR, logger_class, "%s\n", msg);

	if (handle == NULL)
		handle = esdm_prov_core_handle;
	if (c_new_error == NULL || c_vset_error == NULL || handle == NULL)
		return;

	c_new_error(handle);
	if (c_set_error_debug != NULL)
		c_set_error_debug(handle, file, line, func);
	esdm_prov_set_error(handle, reason, "%s", msg);
}
