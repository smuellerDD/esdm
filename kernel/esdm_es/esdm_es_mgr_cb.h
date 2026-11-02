/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * Definition of an entropy source.
 */

#ifndef _ESDM_ES_MGR_CB_H
#define _ESDM_ES_MGR_CB_H

#include <linux/slab.h>

#include "esdm_definitions.h"

enum esdm_internal_es {
	esdm_int_es_irq, /* Interrupt entropy source */
	esdm_int_es_sched, /* Scheduler entropy source */
	esdm_int_es_last, /* MUST be the last entry */
};

struct entropy_buf {
	u8 e[ESDM_DRNG_INIT_SEED_SIZE_BYTES];
	u32 e_bits;
};

/* The IOCTLs reading the entropy buffer, see kernel/shared/esdm_es_ioctl.h */
#define ESDM_IRQ_ENT_BUF ESDM_IRQ_ENT_BUF_IOCTL(struct entropy_buf)
#define ESDM_SCHED_ENT_BUF ESDM_SCHED_ENT_BUF_IOCTL(struct entropy_buf)

void esdm_reset_state(enum esdm_internal_es es);

/*
 * struct esdm_es_conf - configuration of an entropy source by one opener of
 *			 /dev/esdm_es, set with ESDM_IRQ_CONF / ESDM_SCHED_CONF
 * @requested_bits: The entropy in bits a read of the entropy buffer asks for.
 * @entropy_rate: The number of events credited with
 *		  ESDM_DRNG_SECURITY_STRENGTH_BITS of entropy, 0 for the rate
 *		  the module was loaded with. The entropy source never credits
 *		  more than that, whatever is set here.
 *
 * Every descriptor of the device holds its own: the ESDMs that open it, e.g.
 * a server and a test program, or two test programs, may credit the same
 * source differently, and one of them configuring the source must not change
 * what the others read from it.
 */
struct esdm_es_conf {
	u32 requested_bits;
	u32 entropy_rate;
};

/*
 * struct esdm_es_cb - callback defining an entropy source
 * @name: Name of the entropy source.
 * @get_ent: Fetch entropy into the entropy_buf, credited by the given entropy
 *	     rate (see struct esdm_es_conf). The ES shall only deliver data if
 *	     its internal initialization is complete, including any SP800-90B
 *	     startup testing or similar.
 * @curr_entropy: Return amount of currently available entropy, credited by the
 *		  given entropy rate.
 * @max_entropy: Maximum amount of entropy the entropy source is able to
 *		 maintain.
 * @state_json: Buffer with the ES state as a JSON object, the available
 *		entropy credited by the given entropy rate. The ESDM server
 *		embeds the object verbatim in its JSON status document.
 * @reset: Reset entropy source (drop all entropy and reinitialize).
 *	   This callback may be NULL.
 */
struct esdm_es_cb {
	const char *name;
	void (*get_ent)(struct entropy_buf *eb, u32 requested_bits,
			u32 entropy_rate);
	u32 (*curr_entropy)(u32 entropy_rate);
	u32 (*max_entropy)(void);
	void (*state_json)(unsigned char *buf, size_t buflen, u32 entropy_rate);
	void (*reset)(void);
};

/* Cap to maximum entropy that can ever be generated with given DRBG */
#define esdm_cap_requested(__drbg_sec_strength_bits, __requested_bits)                                                 \
	do {                                                                                                           \
		if (__drbg_sec_strength_bits < __requested_bits) {                                                     \
			pr_debug(                                                                                      \
				"Cannot satisfy requested entropy %u due to insufficient DRBG security strength %u\n", \
				__requested_bits, __drbg_sec_strength_bits);                                           \
			__requested_bits = __drbg_sec_strength_bits;                                                   \
		}                                                                                                      \
	} while (0)

#endif /* _ESDM_ES_MGR_CB_H */
