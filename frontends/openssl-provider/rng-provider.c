#include "common.h"

/* direct all pre-defined OpenSSL RAND implementations to ESDM */
const OSSL_ALGORITHM esdm_rands[] = {
	{"CTR-DRBG", "provider=esdm", esdm_rand_functions, NULL},
	{"HASH-DRBG", "provider=esdm", esdm_rand_functions, NULL},
	{"HMAC-DRBG", "provider=esdm", esdm_rand_functions, NULL},
	{"SEED-SRC", "provider=esdm", esdm_rand_functions, NULL},
	{NULL, NULL, NULL, NULL}
};
