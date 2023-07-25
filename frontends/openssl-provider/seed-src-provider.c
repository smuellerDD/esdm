#include "common.h"

/* direct only seed source implementations to ESDM */
const OSSL_ALGORITHM esdm_rands[] = {
	{"SEED-SRC", "provider=esdm", esdm_rand_functions, NULL},
	{NULL, NULL, NULL, NULL}
};