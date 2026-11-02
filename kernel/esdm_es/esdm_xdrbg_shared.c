// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * The XDRBG-256 of the ESDM, the DRBG of the module where the kernel provides
 * SHAKE256 (esdm_drbg_kcapi.c)
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 */

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_CRYPTO_LIB_SHA3)
#include "../../esdm/crypto/esdm_xdrbg.c"
#endif
