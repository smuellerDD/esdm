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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
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
#define ESDM_EBPF_STATE_MAP_NAME "esdm_ebpf_state"
#define ESDM_EBPF_TIMERS_MAP_NAME "esdm_ebpf_timers"

/*
 * The ring buffer is what holds the events until user space reads them, so it
 * is sized for the events an output block costs, with room for the next one to
 * accumulate while the current one is being spent. Beyond that the events are
 * of no use - the pool cannot credit them - so they are dropped rather than
 * buffered.
 */
#define ESDM_EBPF_RB_BLOCKS 2
#define ESDM_EBPF_RB_SIZE_MIN (64 * 1024)
#define ESDM_EBPF_RB_SIZE_MAX (4 * 1024 * 1024)

/*
 * Returned by the record handler once the conditioning pool cannot credit
 * another event. libbpf aborts the ring buffer consumption on a negative
 * callback return without advancing past the record that produced it, so the
 * event and everything behind it stay buffered for the next fetch.
 *
 * ring_buffer__consume_n() would express this directly, but it is a libbpf
 * 1.5 API and the distributions this has to build on are still on 1.3.
 */
#define ESDM_EBPF_FETCH_DONE (-ECANCELED)

/*
 * Deadline after which the flush timer hands a partially filled collection
 * buffer over. It only fires for a CPU that fell quiet before filling its
 * buffer, so it bounds how long a collected delta can sit unaccounted rather
 * than pacing the hand-over of a busy machine.
 */
#define ESDM_EBPF_FLUSH_DEADLINE_NS (250UL * 1000UL * 1000UL)

/*
 * Data one event contributes to the conditioning pool: its time delta (struct
 * esdm_ebpf_event_rec.delta). The entropy rate of the ESDM configuration
 * denominates entropy bits per ESDM_DRNG_SECURITY_STRENGTH_BITS bits of that
 * data, as it does for every other entropy source. Taken from the record so
 * that the accounting cannot drift away from what is actually inserted.
 */
#define ESDM_EBPF_EVENT_DATA_BITS                                              \
	((uint32_t)(sizeof(((struct esdm_ebpf_event_rec *)0)->delta[0]) << 3))

/* Monotonic-clock resolution probe */
#define ESDM_EBPF_CLOCK_PROBES 256
/*
 * Largest smallest-advance between two clock reads still accepted as a high
 * resolution clock. A TSC-backed clock advances by a few tens of nanoseconds
 * between back-to-back reads, a coarse source (e.g. a jiffies clock source in
 * a VM) by microseconds or more.
 */
#define ESDM_EBPF_HIGHRES_MAX_NS 1000

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
	/* libbpf prefixes log messages with libbpf itself,
	 * so they are already distinguished. */
	esdm_logger(severity, LOGGER_C_ES, "%s", buf);

	return 0;
}

void esdm_ebpf_setup_logging(void)
{
	static bool version_logged = false;

	libbpf_set_print(esdm_ebpf_libbpf_print);

	/*
	 * The version of the library actually loaded, not the one built
	 * against: which program constructs and helpers are available to the
	 * entropy sources is decided by it, so a report about them starts here.
	 * Both eBPF entropy sources come through here, one line is enough.
	 */
	if (!version_logged) {
		version_logged = true;
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
			    "eBPF entropy sources using libbpf %s\n",
			    libbpf_version_string());
	}
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

void esdm_ebpf_health_cutoffs(uint32_t osr, struct esdm_ebpf_config *cfg)
{
	/*
	 * The oversampling rate is the number of events required per bit of
	 * entropy, i.e. the health tests assess the events at a min-entropy of
	 * H = 1 / OSR. It is configured for the entropy source at build time
	 * (es_sched_ebpf_osr / es_irq_ebpf_osr) from the measurement of the
	 * deployment environment.
	 *
	 * An OSR of 0 is not a meaningful assessment; it is treated as the
	 * strictest setting of OSR 1 (H = 1 bit per event) rather than
	 * rejected, so that a misconfiguration cannot relax the health tests.
	 */
	if (!osr)
		osr = 1;

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
	#ifdef ESDM_AIS2031_NTG1_SEEDING_STRATEGY
	bool ntg1_seeding = true;
	#else
	bool ntg1_seeding = false;
	#endif
	uint32_t rate = es->entropy_rate(), osr = esdm_ebpf_osr(es);

	/* Health tests are only requested in FIPS or NTG.1 mode */
	es->health_enabled = !!esdm_config_fips_enabled() || ntg1_seeding;

	cfg->health_enabled = es->health_enabled;
	esdm_ebpf_health_cutoffs(osr, cfg);

	/*
	 * The oversampling rate states the assessed min-entropy of one event
	 * (H = 1 / OSR) while the entropy rate credits
	 * rate * ESDM_EBPF_EVENT_DATA_BITS / ESDM_DRNG_SECURITY_STRENGTH_BITS
	 * bits per event. A configuration crediting more than the assessment
	 * supports claims entropy the health tests are not parameterized for -
	 * the accounting caps it (esdm_ebpf_collected_entropy()), the
	 * configuration still deserves a complaint.
	 */
	if ((uint64_t)rate * ESDM_EBPF_EVENT_DATA_BITS * osr >
	    ESDM_DRNG_SECURITY_STRENGTH_BITS)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"%s ES: entropy rate of %u bits per %u data bits exceeds the %u bits per event the configured oversampling rate of %u supports - crediting is capped\n",
			es->name, rate, ESDM_DRNG_SECURITY_STRENGTH_BITS,
			ESDM_DRNG_SECURITY_STRENGTH_BITS /
				(ESDM_EBPF_EVENT_DATA_BITS * osr),
			osr);

	cfg->raw_sampling = 0;
	cfg->flush_deadline_ns = ESDM_EBPF_FLUSH_DEADLINE_NS;
}

/**************************** Timestamp mechanism *****************************/

/*
 * Estimate whether the monotonic clock - the time source read by the eBPF
 * program via bpf_ktime_get_ns() (CLOCK_MONOTONIC) - provides a high
 * resolution. This mirrors the kernel add-on, which does not register its
 * hooks without a high-resolution timer either (esdm_es_sched_module_init()):
 * a coarse clock source leaves the low-order bits of the time stamp constant,
 * so no timing entropy can be collected at all.
 *
 * clock_getres() reports the nominal 1 ns on virtually all systems regardless
 * of the true granularity, so the resolution is estimated as the smallest
 * non-zero advance observed between successive reads.
 */
bool esdm_ebpf_highres_timer(void)
{
	uint64_t min_delta = UINT64_MAX, prev;
	struct timespec ts;
	unsigned int i;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return false;
	prev = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

	for (i = 0; i < ESDM_EBPF_CLOCK_PROBES; i++) {
		uint64_t now;

		if (clock_gettime(CLOCK_MONOTONIC, &ts))
			return false;

		now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
		if (now > prev && now - prev < min_delta)
			min_delta = now - prev;
		prev = now;
	}

	/*
	 * A coarse source jumps by microseconds or more, or does not advance
	 * within the probe loop at all (min_delta stays at its initial value).
	 */
	return min_delta <= ESDM_EBPF_HIGHRES_MAX_NS;
}

/* Defined with the entropy accounting further down */
static uint64_t esdm_ebpf_events_per_block(struct esdm_ebpf_es *es);

/*
 * Size of the collection ring buffer: the smallest power of two that holds
 * ESDM_EBPF_RB_BLOCKS output blocks worth of event records, within the bounds
 * above. The ring buffer size must be a power of two multiple of the page
 * size, which the lower bound guarantees.
 */
static uint32_t esdm_ebpf_rb_size(struct esdm_ebpf_es *es)
{
	uint64_t want = (esdm_ebpf_events_per_block(es) * sizeof(__u64) +
			 (uint64_t)es->nr_cpus *
				 (ESDM_EBPF_EVENT_REC_LEN(0) +
				  ESDM_EBPF_RB_REC_OVERHEAD)) *
			ESDM_EBPF_RB_BLOCKS;
	uint32_t size = ESDM_EBPF_RB_SIZE_MIN;

	while (size < want && size < ESDM_EBPF_RB_SIZE_MAX)
		size <<= 1;

	return size;
}

/*
 * Bring the ring buffer wipe into this load.
 *
 * The time deltas the programs collect are the samples of an SP800-90B noise
 * source, and the ring buffer is the one place holding them that user space
 * cannot overwrite itself - only this program can, as its data pages are
 * mapped read-only and just the producer side may write them. A source that
 * cannot erase them once it is unloaded therefore must not run at all: both
 * ways this can fail abort the initialization rather than leaving the source
 * collecting into a buffer nobody is able to clear again.
 *
 * The wipe is a BPF_PROG_TYPE_SYSCALL program (Linux 5.14). A program type
 * the kernel does not know would fail the load of the whole object anyway;
 * probing it here only turns that into a diagnosable message.
 */
static int esdm_ebpf_prepare_wipe(struct esdm_ebpf_es *es,
				  struct bpf_object *obj)
{
	struct bpf_program *prog;
	int probe, control;

	es->wipe_prog = NULL;

	prog = bpf_object__find_program_by_name(obj, ESDM_EBPF_WIPE_PROG_NAME);
	if (!prog) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "%s ES: ring buffer wipe program not found\n",
			    es->name);
		return -ENOENT;
	}

	probe = libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_SYSCALL, NULL);
	if (probe == 1) {
		es->wipe_prog = prog;
		return 0;
	}

	/*
	 * The probe answers by loading a program of its own, so it fails for
	 * want of privileges exactly as it does for want of kernel support,
	 * and libbpf reports both as "not supported". Ask the same question
	 * about raw tracepoints, which these objects need anyway and which
	 * every kernel offering syscall programs has had for years: if that
	 * one cannot be answered either, the obstacle is this process rather
	 * than the kernel, and the load below fails in a way the caller may
	 * turn into a disabled entropy source. Only a kernel that has raw
	 * tracepoints but no syscall programs is genuinely too old to erase
	 * what this source collects.
	 */
	control = libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_RAW_TRACEPOINT,
					     NULL);
	if (control != 1) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"%s ES: cannot probe for BPF syscall program support (%d) - insufficient privileges, leaving the verdict to the program load\n",
			es->name, probe);
		es->wipe_prog = prog;
		return 0;
	}

	esdm_logger(
		LOGGER_ERR, LOGGER_C_ES,
		"%s ES: kernel does not support BPF syscall programs - the collected events cannot be erased from the ring buffer when the entropy source is unloaded\n",
		es->name);
	return -EOPNOTSUPP;
}

int esdm_ebpf_prepare(struct esdm_ebpf_es *es, struct bpf_object *obj,
		      struct esdm_ebpf_config *cfg)
{
	struct bpf_map *rb_map, *timers_map;
	int nr_cpus = libbpf_num_possible_cpus();
	int ret = 0;

	if (nr_cpus < 1)
		return -EINVAL;
	es->nr_cpus = (unsigned int)nr_cpus;

	esdm_ebpf_fill_config(es, cfg);
	CKINT(esdm_ebpf_prepare_wipe(es, obj));

	rb_map = bpf_object__find_map_by_name(obj, ESDM_EBPF_RB_MAP_NAME);
	CKNULL_LOG(rb_map, -EINVAL, "%s ES: ring buffer map not found\n",
		   es->name);
	es->rb_size = esdm_ebpf_rb_size(es);
	CKINT(bpf_map__set_max_entries(rb_map, es->rb_size));

	timers_map =
		bpf_object__find_map_by_name(obj, ESDM_EBPF_TIMERS_MAP_NAME);
	CKNULL_LOG(timers_map, -EINVAL, "%s ES: timers map not found\n",
		   es->name);
	CKINT(bpf_map__set_max_entries(timers_map, es->nr_cpus));

out:
	return ret;
}

/******************************** Status map **********************************/

/*
 * Read the per-CPU state the eBPF programs maintain. This is what tells user
 * space how much entropy is still to be had - the events deposited but not yet
 * fetched - and the SP800-90B health state, which arrives here directly rather
 * than behind however many events are still in the ring buffer.
 */
static void esdm_ebpf_update_status(struct esdm_ebpf_es *es)
{
	uint64_t events = 0, failures = 0;
	unsigned int i, startup_done = 0, test = 0;
	bool permanent = false;
	uint32_t zero = 0;

	if (!es->state_map || !es->cpu_state)
		return;

	if (bpf_map__lookup_elem(es->state_map, &zero, sizeof(zero),
				 es->cpu_state, es->cpu_state_sz, 0))
		return;

	for (i = 0; i < es->nr_cpus; i++) {
		const struct esdm_ebpf_percpu_state *cpu = &es->cpu_state[i];

		/*
		 * The deposited events are counted whatever generation they
		 * belong to: they physically sit in the ring buffer and the
		 * ingest has to account for every one of them.
		 */
		events += cpu->events;

		/*
		 * The health state of a CPU that has not observed the current
		 * reset generation yet describes the source before the reset -
		 * it clears the moment that CPU sees its next event.
		 */
		if (cpu->reset_gen != es->reset_gen)
			continue;

		failures += cpu->health_failures;
		startup_done += !!cpu->startup_done;
		if (cpu->permanent_failure) {
			permanent = true;
			test = cpu->health_test;
		} else if (cpu->health_failures) {
			test = cpu->health_test;
		}
	}

	/*
	 * The read hands out the whole per-CPU state, collection buffers
	 * included, so this buffer holds a copy of the raw samples of every
	 * CPU. What is of interest has been taken out of it above, so it is
	 * erased right away rather than left to sit until the next status read
	 * overwrites it. A read that fails leaves it as it is, which is what
	 * this made it: empty.
	 */
	memset_secure(es->cpu_state, 0, es->cpu_state_sz);

	es->submitted_events = events;
	es->pending_events = (events > es->consumed_events) ?
				     events - es->consumed_events :
				     0;

	if (startup_done != es->startup_done_cpus) {
		if (startup_done > es->startup_done_cpus)
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_ES,
				"%s ES: SP800-90B startup health tests completed on %u of %u CPUs\n",
				es->name, startup_done, es->nr_cpus);
		es->startup_done_cpus = startup_done;
	}

	/*
	 * SP800-90B fail-closed handling: a health test failure invalidates all
	 * collected entropy. The data itself stays in the pool as uncredited
	 * stirring input. A count that dropped is a reset having cleared the
	 * per-CPU counters, which is no new failure.
	 */
	if (failures > es->health_failures) {
		es->credited_events = 0;
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"%s ES: SP800-90B %s health test failure - invalidating all existing entropy\n",
			es->name,
			(test == esdm_ebpf_health_test_rct) ? "RCT" : "APT");
	}
	es->health_failures = failures;

	if (permanent && !es->perm_failure) {
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
	/*
	 * The full element is rewritten, intentionally clearing the sticky
	 * permanent_failure as part of the reset. This can race with a concurrent update by the eBPF program on
	 * another CPU (a permanent failure raised exactly at reset time may be
	 * lost); it self-heals as the next failing event re-raises the failure.
	 */
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

	/*
	 * The hash states have absorbed the collected event data, so they are
	 * erased before they are handed back rather than left to the backend to
	 * dispose of as it sees fit.
	 */
	if (hash_cb->hash_desc_zero) {
		if (es->pool_state)
			hash_cb->hash_desc_zero(es->pool_state);
		if (es->pool_out)
			hash_cb->hash_desc_zero(es->pool_out);
	}

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
 * Number of events whose entropy amounts to the given number of bits - the
 * inverse of esdm_ebpf_collected_entropy() below. That function takes the
 * smaller of what the entropy rate and what the oversampling rate yield, so
 * inverting it takes the larger of the two event counts. Both are rounded up
 * so the conversion never names fewer events than the bits actually cost.
 */
static uint64_t esdm_ebpf_events_for_bits(struct esdm_ebpf_es *es,
					  uint32_t bits)
{
	uint32_t rate = es->entropy_rate();
	uint64_t rate_bits, events_rate, events_osr;

	/* An uncredited source never accumulates creditable events */
	if (!rate)
		return 0;

	rate_bits = (uint64_t)rate * ESDM_EBPF_EVENT_DATA_BITS;
	events_rate = ((uint64_t)bits * ESDM_DRNG_SECURITY_STRENGTH_BITS +
		       rate_bits - 1) /
		      rate_bits;
	events_osr = (uint64_t)bits * esdm_ebpf_osr(es);

	return max_uint64(events_rate, events_osr);
}

/*
 * Events one output block costs: the conditioning hash must absorb a digest
 * worth of entropy plus the oversampling surcharge esdm_compress_osr() demands
 * in FIPS / SP800-90C / NTG.1 mode to emit one full digest of output, and an
 * event carries 1 / OSR bits of it.
 *
 * This is what an extraction fetches, and it is at the same time the ceiling
 * for the ingest: an extraction compresses everything the pool absorbed into
 * that single block, so events collected beyond it add data but no entropy -
 * a hash pool never carries more than its output size (SP800-90B section
 * 3.1.5.1 table 1), just as the auxiliary pool caps its counter on insert.
 */
static uint64_t esdm_ebpf_events_per_block(struct esdm_ebpf_es *es)
{
	return esdm_ebpf_events_for_bits(es, esdm_get_digestsize() +
						 esdm_compress_osr());
}

/*
 * Entropy in bits the given number of events is worth.
 */
static uint32_t esdm_ebpf_entropy_of(struct esdm_ebpf_es *es, uint64_t events)
{
	/*
	 * Every event inserts its time stamp into the conditioning pool, so the
	 * entropy rate - bits per ESDM_DRNG_SECURITY_STRENGTH_BITS bits of
	 * source data, as for every other entropy source - applies to
	 * credited_events * ESDM_EBPF_EVENT_DATA_BITS bits of data.
	 */
	uint64_t data_bits = events * ESDM_EBPF_EVENT_DATA_BITS;
	uint64_t ent_bits = data_bits * es->entropy_rate() /
			    ESDM_DRNG_SECURITY_STRENGTH_BITS;

	/*
	 * An event carries the assessed min-entropy of H = 1 / OSR and never
	 * more, whatever the configured entropy rate claims. Capping here
	 * rather than rejecting an inconsistent configuration keeps the
	 * accounting bounded by the measurement the health tests are
	 * parameterized with (esdm_ebpf_fill_config() warns about it).
	 */
	ent_bits = min_uint64(ent_bits, events / esdm_ebpf_osr(es));

	return (uint32_t)min_uint64(ent_bits, UINT32_MAX);
}

/*
 * Entropy in bits attributable to the events whose data is present in the
 * conditioning pool, before the extraction accounting of
 * esdm_ebpf_avail_entropy().
 */
static uint32_t esdm_ebpf_collected_entropy(struct esdm_ebpf_es *es)
{
	return esdm_ebpf_entropy_of(es, es->credited_events);
}

/*
 * Entropy in bits the source can hand out: what an extraction would deliver if
 * it ran now. That is not only what the conditioning pool has already absorbed
 * but also what the eBPF programs deposited and nobody has fetched yet, as an
 * extraction fetches those events before it emits its block.
 *
 * An extraction emits one block, so the collected entropy counts up to what
 * one block costs - a digest plus the oversampling surcharge, which
 * esdm_reduce_by_osr() takes off again to arrive at the bits the digest
 * actually delivers. Capping at the digest alone would clip the surcharge and
 * leave the source unable to report the full digest it can produce.
 */
uint32_t esdm_ebpf_avail_entropy(struct esdm_ebpf_es *es)
{
	if (!es->loaded || !es->pool_initialized || es->perm_failure)
		return 0;

	return esdm_reduce_by_osr(min_uint32(
		esdm_get_digestsize() + esdm_compress_osr(),
		esdm_ebpf_entropy_of(es, es->credited_events +
					     es->pending_events)));
}

uint32_t esdm_ebpf_max_entropy(struct esdm_ebpf_es *es)
{
	if (!es->loaded || !es->pool_initialized)
		return 0;

	/*
	 * Oversampling is already considered by adding
	 * esdm_compress_osr() in get_ent. Don't reduce here.
	 */
	return esdm_get_digestsize();
}

void esdm_ebpf_get_ent(struct esdm_ebpf_es *es, struct entropy_es *eb_es,
		       uint32_t requested_bits)
{
	struct hash_ctx *shash = (struct hash_ctx *)es->pool_state;
	struct hash_ctx *ohash = (struct hash_ctx *)es->pool_out;
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;
	uint32_t collected_ent_bits, requested_bits_osr, digestsize,
		digestsize_bits;
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

	/*
	 * Fetch what this one output block still costs, once and without
	 * waiting: the pool is emptied into the block below, so an extraction
	 * takes over from what the monitor topped it up to. A machine that has
	 * not produced the events by now is not going to within this call, and
	 * the extraction proceeds with the entropy it did collect.
	 */
	esdm_ebpf_consume(es);

	/*
	 * Only requested_bits of the block are handed to the caller, so the
	 * claim cannot exceed what those bits can hold: requested_bits plus the
	 * oversampling surcharge, which esdm_reduce_by_osr() takes off again
	 * below. Without this the source would claim a whole digest of entropy
	 * for the partial one it handed out.
	 *
	 * This is the only ceiling needed. A request is capped at the digest
	 * size above, and the ingest caps the pool at what one block costs
	 * (esdm_ebpf_events_per_block()), which is that same digest plus the
	 * same surcharge - so a full-size request meets neither limit before
	 * this one.
	 */
	collected_ent_bits = min_uint32(requested_bits_osr,
					esdm_ebpf_collected_entropy(es));
	es->credited_events = 0;

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

	/*
	 * Everything the programs have deposited so far belongs to the
	 * generation being left behind: the ingest inserts it as uncredited
	 * stirring input and drops its entropy on the generation mismatch. So
	 * it is not entropy this source can still deliver either - counting it
	 * as pending would have the reset report the very entropy it just
	 * invalidated.
	 *
	 * Written off by moving the consumed count up to what was deposited,
	 * rather than by zeroing the difference: the records are still in the
	 * ring buffer and will still be consumed, and a fetch that ran after a
	 * plain zeroing would count them a second time.
	 */
	esdm_ebpf_update_status(es);
	es->consumed_events = es->submitted_events;
	es->pending_events = 0;

	/*
	 * es->health_failures is deliberately left alone: it mirrors the
	 * counters of the programs, which clear them when they observe the new
	 * generation. Zeroing it here would make the next status read see the
	 * old count as a fresh failure.
	 *
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

static void esdm_ebpf_handle_events(struct esdm_ebpf_es *es,
				    const struct esdm_ebpf_event_rec *rec,
				    size_t len)
{
	size_t events = rec->events;

	/* Trust neither the count nor the length without the other */
	if (events > ESDM_EBPF_BATCH_EVENTS ||
	    len < ESDM_EBPF_EVENT_REC_LEN(events))
		return;

	/*
	 * Counted before anything can reject them: the eBPF programs count what
	 * they handed over, and the difference of the two is what is left in
	 * the ring buffer.
	 */
	es->consumed_events += events;
	es->ingested += (uint32_t)events;

	/* The deltas are inserted in full, not folded into bytes */
	if (esdm_ebpf_pool_insert(es, (const uint8_t *)rec->delta,
				  events * sizeof(rec->delta[0])))
		return;

	/*
	 * Events observed under a previous reset generation were in flight in
	 * the ring buffer when the entropy source was reset: their data has
	 * been inserted as uncredited stirring input above, but the reset
	 * invalidated their entropy.
	 */
	if (rec->reset_gen != es->reset_gen)
		return;

	if (es->perm_failure)
		return;

	/*
	 * Every event delivered passed the health tests - the eBPF programs
	 * submit nothing else - so it is creditable.
	 *
	 * Cap the credited event counter at what one output block costs: an
	 * extraction spends the whole pool on that block, so events beyond it
	 * add data but no entropy. Without the cap the accounted entropy would
	 * ramp up with every fetch and outgrow what an extraction can ever
	 * deliver.
	 */
	es->credited_events = min_uint64(es->credited_events + events,
					 esdm_ebpf_events_per_block(es));
}

static int esdm_ebpf_handle_record(void *ctx, void *data, size_t size)
{
	struct esdm_ebpf_es *es = ctx;
	__u32 type;

	/*
	 * The ring buffer is being erased: what it still holds is on its way
	 * out, and the filler records of the wipe carry nothing to begin with.
	 * The consumption only serves to make room for the filler.
	 */
	if (es->wiping)
		return 0;

	if (size < sizeof(type))
		return 0;

	type = *(__u32 *)data;

	switch (type) {
	case esdm_ebpf_rec_event:
		/*
		 * Stop here once the pool is full rather than hash events it
		 * cannot credit. The record keeps its place in the ring buffer
		 * and the next fetch takes it.
		 */
		if (es->credited_events >= es->fetch_target)
			return ESDM_EBPF_FETCH_DONE;
		if (size >= ESDM_EBPF_EVENT_REC_LEN(0))
			esdm_ebpf_handle_events(es, data, size);
		break;
	case esdm_ebpf_rec_wipe:
		/* Filler left behind by a wipe that could not finish */
		break;
	default:
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "%s ES: unknown ring buffer record type %u\n",
			    es->name, type);
		break;
	}

	return 0;
}

/******************************* Zeroization *********************************/

/*
 * Clear the per-CPU state of the eBPF programs and the copy user space keeps
 * of it. That state holds the collection buffer of each CPU, i.e. the deltas
 * collected but not handed over yet, along with the predecessor time stamp and
 * the health test state derived from the collected samples.
 *
 * A CPU clears its own collection buffer when it hands a batch over and when it
 * observes a reset, so what this covers is the buffer of a CPU that fell quiet
 * before either - and, as the map is written as a whole, of the CPUs that are
 * not even online.
 */
static void esdm_ebpf_clear_state_map(struct esdm_ebpf_es *es)
{
	uint32_t zero = 0;

	if (!es->state_map || !es->cpu_state)
		return;

	memset_secure(es->cpu_state, 0, es->cpu_state_sz);

	if (bpf_map__update_elem(es->state_map, &zero, sizeof(zero),
				 es->cpu_state, es->cpu_state_sz, 0))
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "%s ES: cannot clear the per-CPU state map: %s\n",
			    es->name, strerror(errno));
}

/*
 * Overwrite the events the ring buffer holds, using the only writer it has:
 * its producer. The wipe program is run repeatedly, with the ring buffer
 * drained in between to give the filler room, until the filler has covered the
 * whole ring buffer - which is what it takes for the last of the collected
 * records to be gone, wherever in the ring buffer it sat.
 */
static void esdm_ebpf_wipe_rb(struct esdm_ebpf_es *es)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	uint64_t wiped = 0;
	unsigned int rounds, max_rounds;
	int fd;

	if (!es->rb || !es->wipe_prog || !es->rb_size)
		return;

	fd = bpf_program__fd(es->wipe_prog);
	if (fd < 0)
		return;

	/*
	 * One invocation writes at most ESDM_EBPF_WIPE_RECORDS filler records.
	 * The two extra rounds cover the ones that are cut short because the
	 * ring buffer ran out of room before the invocation was through with
	 * its records.
	 */
	max_rounds = es->rb_size / (ESDM_EBPF_WIPE_RECORDS *
				    (ESDM_EBPF_WIPE_CHUNK +
				     ESDM_EBPF_RB_REC_OVERHEAD)) +
		     2;

	es->wiping = true;

	for (rounds = 0; wiped < es->rb_size && rounds < max_rounds; rounds++) {
		int ret;

		/* Make room for the filler, discarding what is in the way */
		ring_buffer__consume(es->rb);

		opts.retval = 0;
		ret = bpf_prog_test_run_opts(fd, &opts);
		if (ret) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"%s ES: cannot run the ring buffer wipe: %d\n",
				es->name, ret);
			break;
		}

		/* An emptied ring buffer that takes no filler takes none ever */
		if (!opts.retval)
			break;

		wiped += opts.retval;
	}

	ring_buffer__consume(es->rb);
	es->wiping = false;

	if (wiped < es->rb_size) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"%s ES: ring buffer erased over %llu of its %u bytes only\n",
			es->name, (unsigned long long)wiped, es->rb_size);
	} else {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "%s ES: ring buffer erased\n", es->name);
	}
}

void esdm_ebpf_zeroize(struct esdm_ebpf_es *es)
{
	if (!es->loaded)
		return;

	/*
	 * The collection buffers first: a flush timer that is still armed hands
	 * over what it finds in one, and after this it finds nothing - so it
	 * cannot deposit a batch in the ring buffer behind the wipe.
	 */
	esdm_ebpf_clear_state_map(es);
	esdm_ebpf_wipe_rb(es);
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

	es->state_map =
		bpf_object__find_map_by_name(obj, ESDM_EBPF_STATE_MAP_NAME);
	CKNULL_LOG(es->state_map, -EINVAL, "%s ES: per-CPU state map not found\n",
		   es->name);

	/*
	 * The per-CPU map hands out one value per possible CPU in one go, so
	 * the buffer holds them all.
	 */
	es->cpu_state_sz = sizeof(*es->cpu_state) * es->nr_cpus;
	es->cpu_state = calloc(es->nr_cpus, sizeof(*es->cpu_state));
	CKNULL(es->cpu_state, -ENOMEM);

	es->rb = ring_buffer__new(bpf_map__fd(rb_map), esdm_ebpf_handle_record,
				  es, NULL);
	if (!es->rb) {
		ret = errno ? -errno : -EINVAL;
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "%s ES: cannot create ring buffer consumer: %s\n",
			    es->name, strerror(errno));
		goto out;
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
	es->state_map = NULL;
	free(es->cpu_state);
	es->cpu_state = NULL;
	esdm_ebpf_pool_dealloc(es);
	return ret;
}

/*
 * Fetch collected events only while the source has a use for them. This is
 * what keeps the periodic monitor from turning the hand-over back into a
 * stream: it asks for events while the pool has room for their entropy and
 * goes quiet once it has not, until an extraction spends what was collected.
 */
int esdm_ebpf_refill(struct esdm_ebpf_es *es)
{
	if (!es->loaded || !es->pool_initialized)
		return 0;

	/*
	 * Bring the entropy the source reports up to date even on the rounds
	 * that fetch nothing. The sticky SP800-90B permanent failure of the
	 * eBPF programs lives in the status map, and until it is read the
	 * source would go on offering entropy that the failure invalidated -
	 * with the fetching gated below, no other caller would read it.
	 */
	esdm_ebpf_update_status(es);
	if (es->perm_failure)
		return 0;

	/*
	 * An uncredited source (entropy rate of 0) never has a demand to
	 * satisfy - its events are bonus data that esdm_ebpf_get_ent() fetches
	 * for itself when it is about to stir them in.
	 */
	if (!es->entropy_rate())
		return 0;

	/*
	 * The pool holds all the entropy it can, so further events would be
	 * fetched for nobody - the ingest could not credit them anyway. They
	 * stay in the ring buffer until an extraction has made room in the pool
	 * again, and the programs drop what no longer fits.
	 *
	 * The comparison is on the credited events rather than on
	 * esdm_ebpf_avail_entropy() against esdm_ebpf_max_entropy(): the former
	 * discounts the oversampling of an extraction while the latter
	 * deliberately does not, so a full pool does not make the two meet.
	 */
	if (es->credited_events >= esdm_ebpf_events_per_block(es))
		return 0;

	return esdm_ebpf_consume(es);
}

int esdm_ebpf_consume(struct esdm_ebpf_es *es)
{
	int ret;

	if (!es->loaded)
		return 0;

	/*
	 * Take only the events the pool still has room to credit and leave the
	 * rest where they are. Draining the whole ring buffer would hash every
	 * record deposited since the last call into a pool that stops crediting
	 * at one output block, so the surplus would cost a hash update each and
	 * buy nothing - and the events are better off waiting in the ring
	 * buffer, where the next fetch finds them.
	 */
	es->fetch_target = esdm_ebpf_events_per_block(es);
	if (es->credited_events >= es->fetch_target)
		return 0;

	es->ingested = 0;
	ret = ring_buffer__consume(es->rb);
	if (ret == ESDM_EBPF_FETCH_DONE)
		ret = 0;
	if (ret < 0 && ret != -EINTR) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "%s ES: ring buffer consumption failed: %d\n",
			    es->name, ret);
		return ret;
	}

	/* One line per fetch, not per event: trace level, see LOGGER_TRACE */
	if (es->ingested)
		esdm_logger(LOGGER_TRACE, LOGGER_C_ES,
			    "%s ES: fetched %u events\n", es->name,
			    es->ingested);

	esdm_ebpf_update_status(es);

	return 0;
}

void esdm_ebpf_fini_es(struct esdm_ebpf_es *es)
{
	/*
	 * Erase the collected samples while the maps and the ring buffer
	 * consumer are still there to be erased. The caller has detached the
	 * programs by now, so nothing collects into what this clears.
	 */
	esdm_ebpf_zeroize(es);

	if (es->rb) {
		ring_buffer__free(es->rb);
		es->rb = NULL;
	}

	esdm_ebpf_pool_dealloc(es);

	if (es->cpu_state)
		memset_secure(es->cpu_state, 0, es->cpu_state_sz);
	free(es->cpu_state);
	es->cpu_state = NULL;
	es->cpu_state_sz = 0;

	es->obj = NULL;
	es->status_map = NULL;
	es->state_map = NULL;
	es->wipe_prog = NULL;
	es->rb_size = 0;
	es->wiping = false;
	es->loaded = false;
	es->perm_failure = false;
	es->credited_events = 0;
	es->consumed_events = 0;
	es->pending_events = 0;
	es->submitted_events = 0;
	es->health_failures = 0;
	es->startup_done_cpus = 0;
}
