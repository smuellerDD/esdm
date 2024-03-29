/*
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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

#ifndef ESDM_OPENSSL_RNG_PROVIDER_COMMON_H
#define ESDM_OPENSSL_RNG_PROVIDER_COMMON_H

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#define ESDM_PROV_NAME "ESDM RNG Provider"
#define ESDM_PROV_VERSION VERSION
#define ESDM_PROV_BUILDINFO VERSION

struct esdm_provider_ctx {
	const OSSL_CORE_HANDLE *core;
	OSSL_LIB_CTX *libctx;
};

struct esdm_rand_ctx {
	const OSSL_CORE_HANDLE *core;
	CRYPTO_RWLOCK *lock;
};

extern const OSSL_DISPATCH esdm_rand_functions[];
extern const OSSL_ALGORITHM esdm_rands[];

#endif /* ESDM_OPENSSL_RNG_PROVIDER_COMMON_H */