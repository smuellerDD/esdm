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