/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 *
 * Definition of an entropy source.
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

#ifndef _ESDM_ES_MGR_CB_H
#define _ESDM_ES_MGR_CB_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "bool.h"
#include "config.h"
#include "esdm.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"

enum esdm_internal_es {
#ifdef ESDM_ES_IRQ
	esdm_int_es_irq, /* IRQ-based entropy source */
#endif
#ifdef ESDM_ES_SCHED
	esdm_int_es_sched, /* Scheduler entropy source */
#endif
	esdm_int_es_last, /* MUST be the last entry */
};

enum esdm_external_es {
	esdm_ext_link = esdm_int_es_last - 1, /* Link entry */
#ifdef ESDM_ES_JENT
	esdm_ext_es_jitter, /* Jitter RNG */
#endif
#ifdef ESDM_ES_CPU
	esdm_ext_es_cpu, /* CPU-based, e.g. RDSEED */
#endif
#ifdef ESDM_ES_KERNEL_RNG
	esdm_ext_es_krng, /* random.c */
#endif
#ifdef ESDM_ES_HWRAND
	esdm_ext_es_hwrand, /* Linux /dev/hwrng */
#endif
#ifdef ESDM_ES_JENT_KERNEL
	esdm_ext_es_jent_kernel, /* Linux jitterentropy in kernel */
#endif
	esdm_ext_es_aux, /* MUST BE LAST ES! */
	esdm_ext_es_last /* MUST be the last entry */
};

enum esdm_es_data_size {
	esdm_es_data_equal, /* Equal to ESDM's data size */
	esdm_es_data_large, /* Large buffer (256 + oversample) */
	esdm_es_data_small /* Small buffer (256) */
};

/* Small buffer for entropy data */
struct entropy_es_small {
	uint8_t e[ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	uint32_t e_bits;
};

/* Large buffer for entropy data */
#define ESDM_DRNG_OVERSAMPLE_SEED_SIZE_BYTES                                   \
	(ESDM_DRNG_SECURITY_STRENGTH_BYTES + 16)
struct entropy_es_large {
	uint8_t e[ESDM_DRNG_OVERSAMPLE_SEED_SIZE_BYTES];
	uint32_t e_bits;
};

struct entropy_es {
	uint8_t e[ESDM_DRNG_INIT_SEED_SIZE_BYTES];
	uint32_t e_bits;
};

struct entropy_buf {
	struct entropy_es entropy_es[esdm_ext_es_last];
	time_t now;
};

/*
 * struct esdm_es_cb - callback defining an entropy source
 * @name: Name of the entropy source.
 * @init: Initialize the entropy source - may be NULL
 * @monitor_es: Check the ES for new entropy - may be NULL
 * @fini: Deinitialize the entropy source - may be NULL
 * @get_ent: Fetch entropy into the entropy_buf. The ES shall only deliver
 *	     data if its internal initialization is complete, including any
 *	     SP800-90B startup testing or similar.
 * @curr_entropy: Return amount of currently available entropy in bits.
 * @max_entropy: Maximum amount of entropy the entropy source is able to
 *		 maintain.
 * @state: Buffer with human-readable ES state.
 * @reset: Reset entropy source (drop all entropy and reinitialize).
 *	   This callback may be NULL.
 * @active: Is ES active.
 * @switch_hash: callback to switch from an old hash callback definition to
 *		 a new one. This callback may be NULL.
 */
struct esdm_es_cb {
	const char *name;
	int (*init)(void);
	int (*monitor_es)(void);
	void (*fini)(void);
	void (*get_ent)(struct entropy_es *eb, uint32_t requested_bits,
			bool fully_seeded);
	uint32_t (*curr_entropy)(uint32_t requested_bits);
	uint32_t (*max_entropy)(void);
	void (*state)(char *buf, size_t buflen);
	void (*reset)(void);
	bool (*active)(void);
	int (*switch_hash)(struct esdm_drng *drng, int node,
			   const struct esdm_hash_cb *new_cb,
			   const struct esdm_hash_cb *old_cb);
};

/* Reseed is desired */
bool esdm_es_reseed_wanted(void);

/* Allow entropy sources to tell the ES manager that new entropy is there */
void esdm_es_add_entropy(void);

/* Read entropy from in-kernel entroy sources */
void esdm_kernel_read(struct entropy_es *eb_es, int fd, unsigned int ioctl_cmd,
		      enum esdm_es_data_size data_size, const char *name);

/* Set the requested bit size */
void esdm_kernel_set_requested_bits(uint32_t *configured_bits,
				    uint32_t requested_bits, int fd,
				    unsigned int ioctl_cmd);

/* Cap to maximum entropy that can ever be generated with given hash */
#define esdm_cap_requested(__digestsize_bits, __requested_bits)                                          \
	do {                                                                                             \
		if (__digestsize_bits < __requested_bits) {                                              \
			logger(LOGGER_DEBUG, LOGGER_C_ANY,                                               \
			       "Cannot satisfy requested entropy %u due to insufficient hash size %u\n", \
			       __requested_bits, __digestsize_bits);                                     \
			__requested_bits = __digestsize_bits;                                            \
		}                                                                                        \
	} while (0)

/* Kernel entropy sources */
#define ESDM_ES_MGR_REQ_BITS_MASK 0x1ff
#define ESDM_ES_MGR_RESET_BIT 0x80000000

#endif /* _ESDM_ES_MGR_CB_H */
