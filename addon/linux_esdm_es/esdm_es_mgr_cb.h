/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 *
 * Definition of an entropy source.
 */

#ifndef _ESDM_ES_MGR_CB_H
#define _ESDM_ES_MGR_CB_H

#include <linux/slab.h>

#include "esdm_definitions.h"
#include "esdm_hash_kcapi.h"

enum esdm_internal_es {
	esdm_int_es_irq, /* Interrupt entropy source */
	esdm_int_es_sched, /* Scheduler entropy source */
	esdm_int_es_last, /* MUST be the last entry */
};

struct entropy_buf {
	u8 e[ESDM_DRNG_INIT_SEED_SIZE_BYTES];
	u32 e_bits;
};

void esdm_reset_state(enum esdm_internal_es es);

/*
 * struct esdm_es_cb - callback defining an entropy source
 * @name: Name of the entropy source.
 * @get_ent: Fetch entropy into the entropy_buf. The ES shall only deliver
 *	     data if its internal initialization is complete, including any
 *	     SP800-90B startup testing or similar.
 * @curr_entropy: Return amount of currently available entropy.
 * @max_entropy: Maximum amount of entropy the entropy source is able to
 *		 maintain.
 * @state: Buffer with human-readable ES state.
 * @reset: Reset entropy source (drop all entropy and reinitialize).
 *	   This callback may be NULL.
 */
struct esdm_es_cb {
	const char *name;
	void (*get_ent)(struct entropy_buf *eb, u32 requested_bits);
	u32 (*curr_entropy)(u32 requested_bits);
	u32 (*max_entropy)(void);
	void (*state)(unsigned char *buf, size_t buflen);
	void (*reset)(void);
	void (*set_entropy_rate)(u32 rate);
};

/* Cap to maximum entropy that can ever be generated with given hash */
#define esdm_cap_requested(__digestsize_bits, __requested_bits)                                           \
	do {                                                                                              \
		if (__digestsize_bits < __requested_bits) {                                               \
			pr_debug(                                                                         \
				"Cannot satisfy requested entropy %u due to insufficient hash size %u\n", \
				__requested_bits, __digestsize_bits);                                     \
			__requested_bits = __digestsize_bits;                                             \
		}                                                                                         \
	} while (0)

#endif /* _ESDM_ES_MGR_CB_H */
