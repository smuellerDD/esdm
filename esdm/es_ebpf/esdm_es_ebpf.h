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

#include "bool.h"
#include "esdm_es_ebpf_shared.h"

struct bpf_map;
struct bpf_object;
struct ring_buffer;
struct entropy_es;

/* State of one eBPF-based entropy source */
struct esdm_ebpf_es {
	const char *name;

	/* Entropy rate in bits per 256 events, from the ESDM configuration */
	uint32_t (*entropy_rate)(void);

	/* Borrowed from the source-specific skeleton, owned by the glue */
	struct bpf_object *obj;
	struct ring_buffer *rb;
	struct bpf_map *status_map;

	bool loaded;

	/* Per-CPU cycle counter perf event fds (tier 2), -1 if unused */
	int *perf_fds;
	unsigned int nr_cpus;
	/* Timestamp tier: 2 = CPU cycle counter, 3 = monotonic clock */
	int tier;
	/* Is the in-program flush timer active? */
	bool flush_timer;

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

	/* Statistics maintained on ring buffer ingest */
	uint64_t total_events;
	uint64_t batches_dropped;
};

/* Is the kernel exposing BTF data required for CO-RE program loading? */
bool esdm_ebpf_btf_available(void);

/* Route libbpf log output into the ESDM logger (idempotent) */
void esdm_ebpf_setup_logging(void);

/*
 * Compute the SP800-90B RCT and APT cutoff values for the given entropy rate
 * (entropy bits per 256 events). An entropy rate of 0 (uncredited source)
 * yields the most conservative cutoffs.
 */
void esdm_ebpf_health_cutoffs(uint32_t entropy_rate,
			      struct esdm_ebpf_config *cfg);

/*
 * Fill the eBPF program configuration prior to loading the program: health
 * test enablement and cutoffs, timestamp mechanism and flush deadline.
 */
void esdm_ebpf_fill_config(struct esdm_ebpf_es *es,
			   struct esdm_ebpf_config *cfg);

/*
 * Prepare an opened but not yet loaded eBPF object: fill the configuration,
 * probe the CPU cycle counter availability (tier 2) and size the per-CPU
 * maps. When enable_flush_timer is false, the bpf_timer based flushing of
 * partial batches is compiled out (fallback for kernels rejecting bpf_timer
 * usage in tracing programs).
 */
int esdm_ebpf_prepare(struct esdm_ebpf_es *es, struct bpf_object *obj,
		      struct esdm_ebpf_config *cfg, bool enable_flush_timer);

/*
 * Complete the initialization of an eBPF entropy source whose skeleton has
 * been loaded and attached by the caller: allocate the conditioning pool,
 * locate the ring buffer map and set up the ring buffer consumer.
 */
int esdm_ebpf_init_es(struct esdm_ebpf_es *es, struct bpf_object *obj);

/* Drain all pending ring buffer records (non-blocking) */
int esdm_ebpf_consume(struct esdm_ebpf_es *es);

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

/* Release all user space resources; the skeleton is destroyed by the glue */
void esdm_ebpf_fini_es(struct esdm_ebpf_es *es);

#endif /* _ESDM_ES_EBPF_H */
