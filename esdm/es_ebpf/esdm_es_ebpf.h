/*
 * ESDM eBPF-based entropy sources: user space infrastructure
 *
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
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

#ifndef _ESDM_ES_EBPF_H
#define _ESDM_ES_EBPF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "esdm_es_ebpf_shared.h"

struct bpf_map;
struct bpf_object;
struct bpf_program;
struct ring_buffer;
struct entropy_es;

/* State of one eBPF-based entropy source */
struct esdm_ebpf_es {
	const char *name;

	/* Entropy rate in bits per 256 events, from the ESDM configuration */
	uint32_t (*entropy_rate)(void);

	/*
	 * SP800-90B oversampling rate of this source: the events required per
	 * bit of entropy (H = 1 / OSR), configured at build time. It
	 * parameterizes the health test cutoffs of the eBPF program.
	 */
	uint32_t osr;

	/* Borrowed from the source-specific skeleton, owned by the glue */
	struct bpf_object *obj;
	struct ring_buffer *rb;
	/* Size of the ring buffer, i.e. what a wipe of it has to cover */
	uint32_t rb_size;
	/*
	 * Program overwriting the ring buffer on zeroization, NULL if the
	 * kernel does not support it. While it runs, the consumption of the
	 * ring buffer discards what it finds: the entropy source is being torn
	 * down, and the filler records are of no interest either.
	 */
	struct bpf_program *wipe_prog;
	bool wiping;
	struct bpf_map *status_map;
	/* Per-CPU state of the programs, read whole into ->cpu_state */
	struct bpf_map *state_map;
	struct esdm_ebpf_percpu_state *cpu_state;
	size_t cpu_state_sz;
	unsigned int nr_cpus;

	bool loaded;

	/* Events the running fetch inserted into the pool, and its bound */
	uint32_t ingested;
	uint64_t fetch_target;

	/*
	 * Events fetched from the ring buffer over the lifetime of the source,
	 * and the ones the programs deposited but nobody has fetched yet - the
	 * entropy the source can still extract without waiting for new events.
	 */
	uint64_t consumed_events;
	uint64_t pending_events;
	/* Events the programs deposited over that lifetime, as last read */
	uint64_t submitted_events;

	/* CPUs whose SP800-90B startup test has completed */
	unsigned int startup_done_cpus;

	/* SP800-90B health state */
	bool health_enabled;
	bool perm_failure;
	uint32_t reset_gen;
	uint64_t health_failures;

	/* Conditioning pool: digest states (internal and output) */
	void *pool_state;
	void *pool_out;
	bool pool_initialized;

	/* Events whose entropy is present in the conditioning pool */
	uint64_t credited_events;
};

/*
 * Oversampling rate of the entropy source, guarding against an unset value:
 * an OSR of 0 is no meaningful assessment and is treated as the strictest
 * setting of 1, just as the health test cutoff computation does.
 */
static inline uint32_t esdm_ebpf_osr(const struct esdm_ebpf_es *es)
{
	return es->osr ? es->osr : 1;
}

/* Is the kernel exposing BTF data required for CO-RE program loading? */
bool esdm_ebpf_btf_available(void);

/*
 * Does the monotonic clock read by the eBPF programs offer a high resolution?
 * Without one the collected time stamps carry no entropy, so the entropy
 * sources are not enabled at all.
 */
bool esdm_ebpf_highres_timer(void);

/* Route libbpf log output into the ESDM logger (idempotent) */
void esdm_ebpf_setup_logging(void);

/*
 * Compute the SP800-90B RCT and APT cutoff values for the given oversampling
 * rate, i.e. for a min-entropy of 1 / OSR bits per event. An OSR of 0 is
 * treated as the most conservative OSR of 1.
 */
void esdm_ebpf_health_cutoffs(uint32_t osr, struct esdm_ebpf_config *cfg);

/*
 * Fill the eBPF program configuration prior to loading the program: health
 * test enablement and cutoffs.
 */
void esdm_ebpf_fill_config(struct esdm_ebpf_es *es,
			   struct esdm_ebpf_config *cfg);

/*
 * Prepare an opened but not yet loaded eBPF object: fill the configuration,
 * bring in the ring buffer wipe and size the ring buffer and the per-CPU timer
 * map.
 *
 * Everything this touches is a property of the object itself or the kernel's
 * support for the wipe, so a failure here is not the "kernel too old, run
 * without this entropy source" case the load and attach steps have to allow
 * for. It means the source could only run in a state where the raw samples it
 * collects cannot be erased again - the caller must fail its initialization
 * and let that take the ESDM down, rather than carrying on without the source.
 */
int esdm_ebpf_prepare(struct esdm_ebpf_es *es, struct bpf_object *obj,
		      struct esdm_ebpf_config *cfg);

/*
 * Complete the initialization of an eBPF entropy source whose skeleton has
 * been loaded and attached by the caller: allocate the conditioning pool,
 * locate the ring buffer map and set up the ring buffer consumer.
 */
int esdm_ebpf_init_es(struct esdm_ebpf_es *es, struct bpf_object *obj);

/*
 * Ingest deposited events, up to the number the conditioning pool still has
 * room to credit. Never blocks and never drains more than that, so the events
 * beyond it stay in the ring buffer for the next call.
 */
int esdm_ebpf_consume(struct esdm_ebpf_es *es);

/*
 * Fetch the collected events only while the source has room for their entropy.
 * This is the periodic variant for the seed monitor: it stops asking once the
 * conditioning pool delivers all one extraction can yield, so a source nobody
 * draws from stops moving events into user space altogether.
 */
int esdm_ebpf_refill(struct esdm_ebpf_es *es);

/* Currently available entropy in bits */
uint32_t esdm_ebpf_avail_entropy(struct esdm_ebpf_es *es);

/* Maximum amount of entropy the conditioning pool can maintain in bits */
uint32_t esdm_ebpf_max_entropy(struct esdm_ebpf_es *es);

/*
 * Extract entropy from the conditioning pool into the seed buffer with
 * backtracking resistance applied to the pool.
 */
void esdm_ebpf_get_ent(struct esdm_ebpf_es *es, struct entropy_es *eb_es,
		       uint32_t requested_bits);

/* Drop all collected entropy */
void esdm_ebpf_pool_reset(struct esdm_ebpf_es *es);

/*
 * Erase every raw sample the entropy source holds: the collection buffers of
 * the eBPF programs, the events they handed over but nobody fetched, and the
 * user space copy of the per-CPU state.
 *
 * The caller must have detached the programs beforehand - a program still
 * collecting would refill what this erases. Called by esdm_ebpf_fini_es().
 */
void esdm_ebpf_zeroize(struct esdm_ebpf_es *es);

/* Release all user space resources; the skeleton is destroyed by the glue */
void esdm_ebpf_fini_es(struct esdm_ebpf_es *es);

#endif /* _ESDM_ES_EBPF_H */
