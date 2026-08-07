/*
 * ESDM eBPF-based entropy sources: user space infrastructure
 *
 * Common code of the eBPF-based scheduler and interrupt entropy sources:
 * ring buffer consumption, conditioning pool, entropy accounting and libbpf
 * integration.
 *
 * The conditioning pool follows the construction of the auxiliary pool
 * (esdm_es_aux.c): the collected event data is inserted into two hash states
 * (an internal state and an output state, domain separated) using the hash of
 * the configured crypto backend. On extraction, the internal state is fed
 * back into both re-initialized hash states which provides backtracking
 * resistance.
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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_ebpf.h"
#include "esdm_es_mgr_cb.h"
#include "esdm_logger.h"
#include "math_helper.h"
#include "memset_secure.h"
#include "ret_checkers.h"

#define ESDM_EBPF_BTF_PATH "/sys/kernel/btf/vmlinux"
#define ESDM_EBPF_RB_MAP_NAME "esdm_ebpf_rb"
#define ESDM_EBPF_STATUS_MAP_NAME "esdm_ebpf_status_map"
#define ESDM_EBPF_PERF_MAP_NAME "esdm_ebpf_perf"
#define ESDM_EBPF_TIMERS_MAP_NAME "esdm_ebpf_timers"

/* The entropy rate denominates entropy bits per this number of events */
#define ESDM_EBPF_RATE_EVENTS 256

/* Domain separation strings for the two hash states, padded to same length */
#define ESDM_EBPF_POOL_DS_STATE "STATE0"
#define ESDM_EBPF_POOL_DS_OUTPUT "OUTPUT"

bool esdm_ebpf_btf_available(void)
{
	return access(ESDM_EBPF_BTF_PATH, R_OK) == 0;
}

static int esdm_ebpf_libbpf_print(enum libbpf_print_level level,
				  const char *format, va_list args)
{
	enum esdm_logger_verbosity severity;
	char buf[512];

	switch (level) {
	case LIBBPF_WARN:
		severity = LOGGER_WARN;
		break;
	case LIBBPF_INFO:
		severity = LOGGER_VERBOSE;
		break;
	case LIBBPF_DEBUG:
	default:
		severity = LOGGER_DEBUG;
		break;
	}

	vsnprintf(buf, sizeof(buf), format, args);
	esdm_logger(severity, LOGGER_C_ES, "libbpf: %s", buf);

	return 0;
}

void esdm_ebpf_setup_logging(void)
{
	libbpf_set_print(esdm_ebpf_libbpf_print);
}

/****************************** Health tests **********************************/

/*
 * APT cutoff tables of the ESDM Linux kernel add-on
 * (addon/linux_esdm_es/esdm_health.h), indexed by OSR - 1: binomial
 * distribution quantiles for the APT window size of 512 with alpha = 2^-30
 * (intermittent) and alpha = 2^-60 (permanent) for H = 1/OSR bits per
 * sample. OSR values of 15 and above use the window size as cutoff per FIPS
 * 140-2 IG 9.8.
 */
static const uint16_t esdm_ebpf_apt_cutoffs[15] = { 325, 422, 459, 477, 488,
						    494, 499, 502, 505, 507,
						    508, 509, 510, 511, 512 };
static const uint16_t esdm_ebpf_apt_cutoffs_permanent[15] = {
	355, 447, 479, 494, 502, 507, 510, 512,
	512, 512, 512, 512, 512, 512, 512
};

void esdm_ebpf_health_cutoffs(uint32_t entropy_rate,
			      struct esdm_ebpf_config *cfg)
{
	uint32_t osr;

	/*
	 * The oversampling rate is the number of events required per bit of
	 * entropy: OSR = 256 / rate for an entropy rate of "rate" bits per
	 * 256 events. The integer division rounds down which underestimates
	 * the OSR and thus yields more conservative (stricter) cutoffs.
	 *
	 * An uncredited source (rate 0) is health tested with the strictest
	 * cutoffs of OSR 1 (H = 1 bit per event).
	 */
	if (entropy_rate == 0 || entropy_rate > ESDM_EBPF_RATE_EVENTS)
		osr = 1;
	else
		osr = ESDM_EBPF_RATE_EVENTS / entropy_rate;

	/*
	 * RCT cutoff per SP800-90B section 4.4.1 with alpha = 2^-30 (FIPS
	 * 140-2 IG 9.8): C = 1 + 30 / H where H = 1 / OSR; the counter of the
	 * implementation starts at zero, hence the +1 is dropped.
	 */
	cfg->rct_cutoff = 30 * osr;
	cfg->rct_cutoff_permanent = 60 * osr;

	if (osr > 15)
		osr = 15;
	cfg->apt_cutoff = esdm_ebpf_apt_cutoffs[osr - 1];
	cfg->apt_cutoff_permanent = esdm_ebpf_apt_cutoffs_permanent[osr - 1];
}

void esdm_ebpf_fill_config(struct esdm_ebpf_es *es,
			   struct esdm_ebpf_config *cfg)
{
	/* Health tests are only requested in FIPS mode */
	es->health_enabled = !!esdm_config_fips_enabled();

	cfg->health_enabled = es->health_enabled;
	esdm_ebpf_health_cutoffs(es->entropy_rate(), cfg);
	cfg->use_perf_counter = 0;
	cfg->flush_timer_enabled = 0;
	cfg->raw_sampling = 0;
	cfg->flush_deadline_ns = 250UL * 1000UL * 1000UL;
}

/****************************** Timestamp tiers *******************************/

static void esdm_ebpf_perf_close(struct esdm_ebpf_es *es)
{
	unsigned int cpu;

	if (!es->perf_fds)
		return;

	for (cpu = 0; cpu < es->nr_cpus; cpu++) {
		if (es->perf_fds[cpu] >= 0)
			close(es->perf_fds[cpu]);
	}
	free(es->perf_fds);
	es->perf_fds = NULL;
}

/*
 * Probe the availability of the CPU cycle counter through the perf
 * subsystem (timestamp tier 2). The probe is all-or-nothing across the
 * online CPUs: environments exposing the PMU only on a subset of the CPUs
 * fall back to the monotonic clock (tier 3) to keep the timestamp mechanism
 * - and thereby the entropy claim - uniform across the CPUs.
 */
static bool esdm_ebpf_perf_probe(struct esdm_ebpf_es *es)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(struct perf_event_attr),
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	unsigned int cpu, opened = 0;

	es->perf_fds = calloc(es->nr_cpus, sizeof(int));
	if (!es->perf_fds)
		return false;

	for (cpu = 0; cpu < es->nr_cpus; cpu++)
		es->perf_fds[cpu] = -1;

	for (cpu = 0; cpu < es->nr_cpus; cpu++) {
		int fd = (int)syscall(__NR_perf_event_open, &attr, -1, (int)cpu,
				      -1, PERF_FLAG_FD_CLOEXEC);

		if (fd < 0) {
			/* Tolerate offline CPUs */
			if (errno == ENODEV || errno == ENXIO)
				continue;

			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_ES,
				"%s ES: CPU cycle counter unavailable on CPU %u (%s), using monotonic clock\n",
				es->name, cpu, strerror(errno));
			esdm_ebpf_perf_close(es);
			return false;
		}

		es->perf_fds[cpu] = fd;
		opened++;
	}

	if (!opened) {
		esdm_ebpf_perf_close(es);
		return false;
	}

	return true;
}

int esdm_ebpf_prepare(struct esdm_ebpf_es *es, struct bpf_object *obj,
		      struct esdm_ebpf_config *cfg, bool enable_flush_timer)
{
	struct bpf_map *perf_map, *timers_map;
	int nr_cpus = libbpf_num_possible_cpus();
	int ret = 0;

	if (nr_cpus < 1)
		return -EINVAL;
	es->nr_cpus = (unsigned int)nr_cpus;

	esdm_ebpf_fill_config(es, cfg);

	if (esdm_ebpf_perf_probe(es)) {
		cfg->use_perf_counter = 1;
		es->tier = 2;
	} else {
		es->tier = 3;
	}

	cfg->flush_timer_enabled = enable_flush_timer;
	es->flush_timer = enable_flush_timer;

	perf_map = bpf_object__find_map_by_name(obj, ESDM_EBPF_PERF_MAP_NAME);
	CKNULL_LOG(perf_map, -EINVAL, "%s ES: perf map not found\n", es->name);
	CKINT(bpf_map__set_max_entries(perf_map, es->nr_cpus));

	timers_map =
		bpf_object__find_map_by_name(obj, ESDM_EBPF_TIMERS_MAP_NAME);
	CKNULL_LOG(timers_map, -EINVAL, "%s ES: timers map not found\n",
		   es->name);
	CKINT(bpf_map__set_max_entries(timers_map, es->nr_cpus));

	return 0;

out:
	esdm_ebpf_perf_close(es);
	return ret;
}

/******************************** Status map **********************************/

/* Read the status map maintained by the eBPF program */
static void esdm_ebpf_update_status(struct esdm_ebpf_es *es)
{
	struct esdm_ebpf_status status;
	uint32_t zero = 0;

	if (!es->status_map)
		return;

	if (bpf_map__lookup_elem(es->status_map, &zero, sizeof(zero), &status,
				 sizeof(status), 0))
		return;

	es->batches_dropped = status.batches_dropped;

	/*
	 * The sticky permanent failure flag in the status map is
	 * authoritative: it is set by the eBPF program even when the health
	 * event record could not be delivered through the ring buffer.
	 */
	if (status.permanent_failure && !es->perm_failure) {
		es->perm_failure = true;
		es->credited_events = 0;
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"%s ES: SP800-90B permanent health test failure - invalidating all existing entropy\n",
			es->name);
	}
}

/* Write the status map: bump the reset generation and clear the failure */
static void esdm_ebpf_write_status(struct esdm_ebpf_es *es)
{
	struct esdm_ebpf_status status = {
		.reset_gen = es->reset_gen,
	};
	uint32_t zero = 0;

	if (!es->status_map)
		return;

	if (bpf_map__update_elem(es->status_map, &zero, sizeof(zero), &status,
				 sizeof(status), 0)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "%s ES: cannot update status map: %s\n", es->name,
			    strerror(errno));
	}
}

/***************************** Conditioning pool ******************************/

/*
 * Initialize the two hash states with domain separation between the states
 * and between the entropy sources.
 */
static int esdm_ebpf_pool_init_states(struct esdm_ebpf_es *es,
				      const struct esdm_hash_cb *hash_cb)
{
	struct hash_ctx *shash = (struct hash_ctx *)es->pool_state;
	struct hash_ctx *ohash = (struct hash_ctx *)es->pool_out;
	int ret;

	CKINT(hash_cb->hash_init(shash));
	CKINT(hash_cb->hash_init(ohash));

	CKINT(hash_cb->hash_update(shash,
				   (const uint8_t *)ESDM_EBPF_POOL_DS_STATE,
				   sizeof(ESDM_EBPF_POOL_DS_STATE) - 1));
	CKINT(hash_cb->hash_update(ohash,
				   (const uint8_t *)ESDM_EBPF_POOL_DS_OUTPUT,
				   sizeof(ESDM_EBPF_POOL_DS_OUTPUT) - 1));

	/* Domain separation between the eBPF entropy sources */
	CKINT(hash_cb->hash_update(shash, (const uint8_t *)es->name,
				   strlen(es->name)));
	CKINT(hash_cb->hash_update(ohash, (const uint8_t *)es->name,
				   strlen(es->name)));

	es->pool_initialized = true;

out:
	return ret;
}

static int esdm_ebpf_pool_alloc(struct esdm_ebpf_es *es)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;
	int ret = 0;

	if (hash_cb->hash_alloc) {
		CKINT(hash_cb->hash_alloc(&es->pool_state));
		CKINT(hash_cb->hash_alloc(&es->pool_out));
	}

	CKINT(esdm_ebpf_pool_init_states(es, hash_cb));

	return 0;

out:
	if (es->pool_state && hash_cb->hash_dealloc) {
		hash_cb->hash_dealloc(es->pool_state);
		es->pool_state = NULL;
	}
	if (es->pool_out && hash_cb->hash_dealloc) {
		hash_cb->hash_dealloc(es->pool_out);
		es->pool_out = NULL;
	}
	es->pool_initialized = false;
	return ret;
}

static void esdm_ebpf_pool_dealloc(struct esdm_ebpf_es *es)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;

	if (hash_cb->hash_dealloc) {
		if (es->pool_state)
			hash_cb->hash_dealloc(es->pool_state);
		if (es->pool_out)
			hash_cb->hash_dealloc(es->pool_out);
	}
	es->pool_state = NULL;
	es->pool_out = NULL;
	es->pool_initialized = false;
}

/* Insert collected event data into the conditioning pool. */
static int esdm_ebpf_pool_insert(struct esdm_ebpf_es *es, const uint8_t *data,
				 size_t len)
{
	struct hash_ctx *shash = (struct hash_ctx *)es->pool_state;
	struct hash_ctx *ohash = (struct hash_ctx *)es->pool_out;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;
	int ret;

	if (!es->pool_initialized)
		return -EOPNOTSUPP;

	CKINT(hash_cb->hash_update(shash, data, len));
	CKINT(hash_cb->hash_update(ohash, data, len));

out:
	return ret;
}

/*
 * Entropy in bits attributable to the events whose data is present in the
 * conditioning pool, before capping and oversampling adjustment.
 */
static uint32_t esdm_ebpf_collected_entropy(struct esdm_ebpf_es *es)
{
	uint64_t ent_bits = es->credited_events * es->entropy_rate() /
			    ESDM_EBPF_RATE_EVENTS;

	return (uint32_t)min_uint64(ent_bits, UINT32_MAX);
}

uint32_t esdm_ebpf_avail_entropy(struct esdm_ebpf_es *es)
{
	uint32_t ent_bits;

	if (!es->loaded || !es->pool_initialized || es->perm_failure)
		return 0;

	ent_bits = min_uint32(esdm_get_digestsize(),
			      esdm_ebpf_collected_entropy(es));

	/* Consider oversampling rate due to pool conditioning */
	return esdm_reduce_by_osr(ent_bits);
}

uint32_t esdm_ebpf_max_entropy(struct esdm_ebpf_es *es)
{
	if (!es->loaded || !es->pool_initialized)
		return 0;

	return esdm_reduce_by_osr(esdm_get_digestsize());
}

void esdm_ebpf_get_ent(struct esdm_ebpf_es *es, struct entropy_es *eb_es,
		       uint32_t requested_bits)
{
	struct hash_ctx *shash = (struct hash_ctx *)es->pool_state;
	struct hash_ctx *ohash = (struct hash_ctx *)es->pool_out;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;
	uint32_t collected_ent_bits, requested_bits_osr, digestsize,
		digestsize_bits, rate = es->entropy_rate();
	uint8_t pool_state_digest[ESDM_MAX_DIGESTSIZE];
	uint8_t pool_out_digest[ESDM_MAX_DIGESTSIZE];

	eb_es->e_bits = 0;

	if (!es->pool_initialized)
		return;

	digestsize = hash_cb->hash_digestsize(shash);
	digestsize_bits = digestsize << 3;

	/* Cap to maximum entropy that can ever be generated with given hash */
	esdm_cap_requested(digestsize_bits, requested_bits);

	/* Ensure the memcpy() below cannot overflow the seed buffer. */
	requested_bits = min_uint32(requested_bits, ESDM_MAX_DIGESTSIZE << 3);
	requested_bits =
		min_uint32(requested_bits, ESDM_DRNG_INIT_SEED_SIZE_BITS);
	requested_bits_osr = requested_bits + esdm_compress_osr();

	collected_ent_bits =
		min_uint32(digestsize_bits, esdm_ebpf_collected_entropy(es));

	if (collected_ent_bits > requested_bits_osr) {
		/*
		 * More entropy is available than requested: only debit the
		 * events needed for the request and keep the remainder
		 * accounted in the pool. The event count is rounded up so
		 * that the accounting never overestimates the entropy of the
		 * remaining events.
		 */
		uint64_t events_used =
			((uint64_t)requested_bits_osr * ESDM_EBPF_RATE_EVENTS +
			 (rate - 1)) /
			rate;

		es->credited_events -=
			min_uint64(events_used, es->credited_events);
		collected_ent_bits = requested_bits_osr;
	} else {
		es->credited_events = 0;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "%s ES: obtained %u bits of entropy (%u bits requested)\n",
		    es->name, esdm_reduce_by_osr(collected_ent_bits),
		    requested_bits);

	/*
	 * 1) Hash into new state and output digests
	 * 2) re-initialize both hash states
	 * 3) feed the internal state digest back into both hash states for
	 *    backtracking resistance (the internal state is never output)
	 */
	if (hash_cb->hash_final(shash, pool_state_digest) ||
	    hash_cb->hash_final(ohash, pool_out_digest) ||
	    esdm_ebpf_pool_init_states(es, hash_cb) ||
	    esdm_ebpf_pool_insert(es, pool_state_digest, digestsize)) {
		es->pool_initialized = false;
	} else {
		/*
		 * Deliver the output digest even if no entropy is credited:
		 * the data still stirs the DRNG state.
		 */
		memcpy(eb_es->e, pool_out_digest, requested_bits >> 3);
		eb_es->e_bits = esdm_reduce_by_osr(collected_ent_bits);
	}

	memset_secure(pool_state_digest, 0, digestsize);
	memset_secure(pool_out_digest, 0, digestsize);
}

void esdm_ebpf_pool_reset(struct esdm_ebpf_es *es)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;

	es->credited_events = 0;
	es->total_events = 0;
	es->batches_dropped = 0;
	es->health_failures = 0;

	/*
	 * Clear a sticky permanent failure and announce a new reset
	 * generation: the eBPF program reinitializes its per-CPU state and
	 * restarts the SP800-90B startup test.
	 */
	es->perm_failure = false;
	if (es->loaded) {
		es->reset_gen++;
		esdm_ebpf_write_status(es);
	}

	if (es->pool_state && es->pool_out &&
	    esdm_ebpf_pool_init_states(es, hash_cb))
		es->pool_initialized = false;
}

/**************************** Ring buffer ingest ******************************/

static void esdm_ebpf_handle_batch(struct esdm_ebpf_es *es,
				   const struct esdm_ebpf_batch_rec *rec)
{
	if (rec->events > ESDM_EBPF_BATCH_EVENTS)
		return;

	if (esdm_ebpf_pool_insert(es, rec->data, rec->events))
		return;

	es->total_events += rec->events;

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"%s ES: batch of %u events from CPU %u (seq %llu, health 0x%x)\n",
		es->name, rec->events, rec->cpu, (unsigned long long)rec->seq,
		rec->health);

	/*
	 * SP800-90B fail-closed handling: a health test failure invalidates
	 * all collected entropy (the data itself remains in the pool as
	 * uncredited stirring input).
	 */
	if (rec->health &
	    (ESDM_EBPF_HEALTH_RCT_FAILURE | ESDM_EBPF_HEALTH_APT_FAILURE |
	     ESDM_EBPF_HEALTH_PERM_FAILURE)) {
		es->credited_events = 0;
		if (rec->health & ESDM_EBPF_HEALTH_PERM_FAILURE)
			es->perm_failure = true;
		return;
	}

	if (es->perm_failure)
		return;

	/*
	 * Credit the events only once the SP800-90B startup test of the
	 * originating CPU has completed - when health testing is disabled
	 * (non-FIPS mode), the events are credited unconditionally.
	 */
	if (es->health_enabled &&
	    !(rec->health & ESDM_EBPF_HEALTH_STARTUP_DONE))
		return;

	/*
	 * Cap the credited event counter: with the maximum entropy rate the
	 * cap still accounts for far more entropy than the pool can ever
	 * maintain, while the counter arithmetic cannot overflow.
	 */
	es->credited_events =
		min_uint64(es->credited_events + rec->events, UINT32_MAX);
}

static void esdm_ebpf_handle_health(struct esdm_ebpf_es *es,
				    const struct esdm_ebpf_health_rec *rec)
{
	const char *test =
		(rec->test == esdm_ebpf_health_test_rct) ? "RCT" : "APT";

	switch (rec->event) {
	case esdm_ebpf_health_startup_done:
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"%s ES: SP800-90B startup health tests on CPU %u completed\n",
			es->name, rec->cpu);
		break;
	case esdm_ebpf_health_intermittent_failure:
		es->health_failures++;
		es->credited_events = 0;
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"%s ES: SP800-90B %s health test failure on CPU %u - invalidating all existing entropy and initiating SP800-90B startup\n",
			es->name, test, rec->cpu);
		break;
	case esdm_ebpf_health_permanent_failure:
		es->health_failures++;
		es->credited_events = 0;
		es->perm_failure = true;
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"%s ES: SP800-90B permanent %s health test failure on CPU %u - invalidating all existing entropy\n",
			es->name, test, rec->cpu);
		break;
	default:
		break;
	}
}

static int esdm_ebpf_handle_record(void *ctx, void *data, size_t size)
{
	struct esdm_ebpf_es *es = ctx;
	__u32 type;

	if (size < sizeof(type))
		return 0;

	type = *(__u32 *)data;

	switch (type) {
	case esdm_ebpf_rec_batch:
		if (size >= sizeof(struct esdm_ebpf_batch_rec))
			esdm_ebpf_handle_batch(es, data);
		break;
	case esdm_ebpf_rec_health:
		if (size >= sizeof(struct esdm_ebpf_health_rec))
			esdm_ebpf_handle_health(es, data);
		break;
	default:
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "%s ES: unknown ring buffer record type %u\n",
			    es->name, type);
		break;
	}

	return 0;
}

/******************************** Lifecycle **********************************/

int esdm_ebpf_init_es(struct esdm_ebpf_es *es, struct bpf_object *obj)
{
	struct bpf_map *rb_map;
	int ret = 0;

	CKINT(esdm_ebpf_pool_alloc(es));

	rb_map = bpf_object__find_map_by_name(obj, ESDM_EBPF_RB_MAP_NAME);
	CKNULL_LOG(rb_map, -EINVAL, "%s ES: ring buffer map not found\n",
		   es->name);

	es->status_map =
		bpf_object__find_map_by_name(obj, ESDM_EBPF_STATUS_MAP_NAME);
	CKNULL_LOG(es->status_map, -EINVAL, "%s ES: status map not found\n",
		   es->name);

	es->rb = ring_buffer__new(bpf_map__fd(rb_map), esdm_ebpf_handle_record,
				  es, NULL);
	if (!es->rb) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "%s ES: cannot create ring buffer consumer: %s\n",
			    es->name, strerror(errno));
		goto out;
	}

	/* Populate the CPU cycle counter perf events (tier 2) */
	if (es->perf_fds) {
		struct bpf_map *perf_map = bpf_object__find_map_by_name(
			obj, ESDM_EBPF_PERF_MAP_NAME);
		uint32_t cpu;

		for (cpu = 0; perf_map && cpu < es->nr_cpus; cpu++) {
			if (es->perf_fds[cpu] < 0)
				continue;
			if (bpf_map__update_elem(perf_map, &cpu, sizeof(cpu),
						 &es->perf_fds[cpu],
						 sizeof(es->perf_fds[cpu]),
						 0)) {
				esdm_logger(
					LOGGER_WARN, LOGGER_C_ES,
					"%s ES: cannot set cycle counter for CPU %u: %s\n",
					es->name, cpu, strerror(errno));
			}
		}
	}

	/*
	 * Start the first reset generation which makes the eBPF program
	 * initialize its per-CPU health test state.
	 */
	es->reset_gen = 1;
	es->perm_failure = false;
	esdm_ebpf_write_status(es);

	es->obj = obj;
	es->loaded = true;

	return 0;

out:
	es->status_map = NULL;
	esdm_ebpf_pool_dealloc(es);
	return ret;
}

int esdm_ebpf_consume(struct esdm_ebpf_es *es)
{
	int ret;

	if (!es->loaded)
		return 0;

	ret = ring_buffer__consume(es->rb);
	if (ret < 0 && ret != -EINTR) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "%s ES: ring buffer consumption failed: %d\n",
			    es->name, ret);
		return ret;
	}

	esdm_ebpf_update_status(es);

	return 0;
}

void esdm_ebpf_fini_es(struct esdm_ebpf_es *es)
{
	if (es->rb) {
		ring_buffer__free(es->rb);
		es->rb = NULL;
	}

	esdm_ebpf_pool_dealloc(es);
	esdm_ebpf_perf_close(es);

	es->obj = NULL;
	es->status_map = NULL;
	es->loaded = false;
	es->perm_failure = false;
	es->total_events = 0;
	es->credited_events = 0;
	es->batches_dropped = 0;
	es->health_failures = 0;
}
