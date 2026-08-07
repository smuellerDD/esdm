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

#ifndef ESDM_OPENSSL_PROVIDER_ERROR_H
#define ESDM_OPENSSL_PROVIDER_ERROR_H

#include <openssl/core_dispatch.h>
#include <stdint.h>

#include "esdm_logger.h"

/**
 * @brief Pick up the error reporting upcalls handed over by libcrypto
 *
 * Without them a provider failure surfaces as nothing but the caller's generic
 * message - e.g. "evp_rand_generate_locked:generate error". Call this first
 * thing in OSSL_provider_init(), before anything can fail.
 *
 * @param [in] in Dispatch table libcrypto passed to OSSL_provider_init()
 * @param [in] handle Core handle, kept as a fallback for the few call sites
 *		      that have no context to take one from
 */
void esdm_prov_init_error_reporting(const OSSL_DISPATCH *in,
				    const OSSL_CORE_HANDLE *handle);

/**
 * @brief Look up a provider parameter supplied through the OpenSSL config
 *
 * Keys of a provider's configuration section that OpenSSL does not consume
 * itself (everything besides module, path, activate, identity and soft_load)
 * are handed to the provider - this is how it reads openssl.cnf.
 *
 * @param [in] handle Core handle passed to OSSL_provider_init()
 * @param [in] name Name of the configuration key
 *
 * @return Value of the parameter or NULL when it was not configured. The
 *	   string is owned by libcrypto and lives as long as the provider.
 */
const char *esdm_prov_get_conf_param(const OSSL_CORE_HANDLE *handle,
				     const char *name);

/**
 * @brief Report a failure to the OpenSSL error stack and the ESDM logger
 *
 * Applications see the former via ERR_print_errors() - the openssl(1) commands
 * print it automatically - while the latter gives an application that raised
 * the ESDM verbosity the same detail without draining the error stack.
 *
 * Use the ESDM_PROV_ERR() macro rather than calling this directly.
 */
void esdm_prov_raise_error(const OSSL_CORE_HANDLE *handle,
			   enum esdm_logger_class logger_class, uint32_t reason,
			   const char *file, int line, const char *func,
			   const char *fmt, ...)
	__attribute__((format(printf, 7, 8)));

/*
 * Report an error of @reason. Define ESDM_PROV_LOGGER_CLASS before including
 * this header to direct the logger half at a specific subsystem.
 */
#ifndef ESDM_PROV_LOGGER_CLASS
#define ESDM_PROV_LOGGER_CLASS LOGGER_C_ANY
#endif

#define ESDM_PROV_ERR(handle, reason, ...)                                     \
	esdm_prov_raise_error(handle, ESDM_PROV_LOGGER_CLASS, reason,          \
			      __FILE__, __LINE__, OPENSSL_FUNC, __VA_ARGS__)

#endif /* ESDM_OPENSSL_PROVIDER_ERROR_H */
