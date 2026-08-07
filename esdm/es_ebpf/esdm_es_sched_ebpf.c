/*
 * ESDM Slow Entropy Source: eBPF-based scheduler entropy source
 *
 * Collects entropy from the timing of scheduler context switches observed
 * via an eBPF program attached to the sched_switch tracepoint. In contrast
 * to the scheduler entropy source implemented by esdm_es_sched.c, no kernel
 * patch is required.
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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_ebpf.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched_ebpf.h"
#include "esdm_logger.h"
#include "helper.h"
#include "math_helper.h"
#include "mutex.h"
#include "test_pertubation.h"

/* The bpftool-generated skeleton does not satisfy the strict warnings */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "esdm_es_sched_ebpf.skel.h"
#pragma GCC diagnostic pop

static struct esdm_es_sched_ebpf_bpf *esdm_sched_ebpf_skel = NULL;
static struct esdm_ebpf_es esdm_sched_ebpf_es = {
	.name = "SchedulerEBPF",
	.entropy_rate = esdm_config_es_sched_ebpf_entropy_rate,
};

/*
 * Serializes the skeleton / ring buffer state between the monitor thread,
 * the seed buffer filler and (re)initialization.
 */
static DEFINE_MUTEX_UNLOCKED(sched_ebpf_mutex);

bool esdm_sched_ebpf_enabled(void)
{
	return esdm_sched_ebpf_es.loaded &&
	       esdm_config_es_sched_ebpf_entropy_rate() > 0;
}

/* Caller must hold sched_ebpf_mutex (write lock). */
static void esdm_sched_ebpf_finalize_locked(void)
{
	esdm_ebpf_fini_es(&esdm_sched_ebpf_es);

	if (esdm_sched_ebpf_skel) {
		esdm_es_sched_ebpf_bpf__destroy(esdm_sched_ebpf_skel);
		esdm_sched_ebpf_skel = NULL;
	}
}

static void esdm_sched_ebpf_finalize(void)
{
	mutex_lock(&sched_ebpf_mutex);
	esdm_sched_ebpf_finalize_locked();
	mutex_unlock(&sched_ebpf_mutex);
}

/*
 * Open, configure and load the eBPF object. On kernels rejecting the
 * bpf_timer usage in tracing programs, the caller retries with the flush
 * timer disabled which prunes the timer code from the program.
 */
static int esdm_sched_ebpf_open_load(bool flush_timer,
				     struct esdm_es_sched_ebpf_bpf **skel_out)
{
	struct esdm_es_sched_ebpf_bpf *skel;
	int ret;

	skel = esdm_es_sched_ebpf_bpf__open();
	if (!skel) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"Opening of eBPF scheduler entropy source object failed: %s\n",
			strerror(errno));
		return -errno;
	}

	ret = esdm_ebpf_prepare(&esdm_sched_ebpf_es, skel->obj,
				&skel->rodata->esdm_ebpf_cfg, flush_timer);
	if (ret)
		goto err;

	ret = esdm_es_sched_ebpf_bpf__load(skel);
	if (ret)
		goto err;

	*skel_out = skel;
	return 0;

err:
	esdm_es_sched_ebpf_bpf__destroy(skel);
	esdm_ebpf_fini_es(&esdm_sched_ebpf_es);
	return ret;
}

static int esdm_sched_ebpf_initialize(void)
{
	struct esdm_es_sched_ebpf_bpf *skel = NULL;
	int ret;

	mutex_lock(&sched_ebpf_mutex);

	/* Allow the init function to be called multiple times */
	esdm_sched_ebpf_finalize_locked();

	if (!esdm_ebpf_btf_available()) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF scheduler-based entropy source as the kernel does not expose BTF data\n");
		ret = 0;
		goto out;
	}

	esdm_ebpf_setup_logging();

	ret = esdm_sched_ebpf_open_load(true, &skel);
	if (ret) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"Loading of eBPF scheduler entropy source program failed (%d), retrying without in-program flush timer\n",
			ret);
		ret = esdm_sched_ebpf_open_load(false, &skel);
	}
	if (ret) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF scheduler-based entropy source as the program cannot be loaded (kernel too old or missing privileges?): %d\n",
			ret);
		ret = 0;
		goto out;
	}

	ret = esdm_es_sched_ebpf_bpf__attach(skel);
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"Attaching of eBPF scheduler entropy source program failed: %d\n",
			ret);
		esdm_es_sched_ebpf_bpf__destroy(skel);
		ret = 0;
		goto out;
	}

	ret = esdm_ebpf_init_es(&esdm_sched_ebpf_es, skel->obj);
	if (ret) {
		esdm_es_sched_ebpf_bpf__destroy(skel);
		goto out;
	}

	esdm_sched_ebpf_skel = skel;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "eBPF scheduler-based entropy source initialized\n");

out:
	mutex_unlock(&sched_ebpf_mutex);
	return ret;
}

static int esdm_sched_ebpf_seed_monitor(void)
{
	uint32_t ent, max_ent;

	if (!esdm_sched_ebpf_es.loaded)
		return 0;

	/*
	 * Always drain the ring buffer into the conditioning pool - even when
	 * fully seeded - so that the collected data is not lost and later
	 * reseeds draw from a filled pool.
	 */
	mutex_lock(&sched_ebpf_mutex);
	esdm_ebpf_consume(&esdm_sched_ebpf_es);
	ent = esdm_ebpf_avail_entropy(&esdm_sched_ebpf_es);
	max_ent = esdm_ebpf_max_entropy(&esdm_sched_ebpf_es);
	mutex_unlock(&sched_ebpf_mutex);

	if (esdm_pool_all_nodes_seeded_get())
		return 0;

	if (!esdm_config_es_sched_ebpf_entropy_rate())
		return 0;

	if (ent >= min_uint32(esdm_security_strength(), max_ent)) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "Full entropy of eBPF scheduler ES detected\n");
		esdm_es_add_entropy();
		esdm_test_seed_entropy(ent);
	}

	return 0;
}

static uint32_t esdm_sched_ebpf_entropylevel(uint32_t requested_bits)
{
	uint32_t ent;

	(void)requested_bits;

	mutex_reader_lock(&sched_ebpf_mutex);
	ent = esdm_ebpf_avail_entropy(&esdm_sched_ebpf_es);
	mutex_reader_unlock(&sched_ebpf_mutex);

	return ent;
}

static uint32_t esdm_sched_ebpf_poolsize(void)
{
	uint32_t ent;

	mutex_reader_lock(&sched_ebpf_mutex);
	ent = esdm_ebpf_max_entropy(&esdm_sched_ebpf_es);
	mutex_reader_unlock(&sched_ebpf_mutex);

	return ent;
}

static void esdm_sched_ebpf_get(struct entropy_es *eb_es,
				uint32_t requested_bits, bool __unused unused)
{
	mutex_lock(&sched_ebpf_mutex);
	/* Opportunistically pick up pending batches before extraction */
	esdm_ebpf_consume(&esdm_sched_ebpf_es);
	esdm_ebpf_get_ent(&esdm_sched_ebpf_es, eb_es, requested_bits);
	mutex_unlock(&sched_ebpf_mutex);
}

static void esdm_sched_ebpf_reset(void)
{
	mutex_lock(&sched_ebpf_mutex);
	esdm_ebpf_pool_reset(&esdm_sched_ebpf_es);
	mutex_unlock(&sched_ebpf_mutex);
}

static void esdm_sched_ebpf_es_state(char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 " Available: %s\n"
		 " Available entropy: %u\n"
		 " Maximum entropy: %u\n"
		 " Total events: %llu\n"
		 " Entropy Rate per 256 events: %u\n"
		 " Timestamp mechanism: %s\n"
		 " Partial batch flush timer: %s\n"
		 " SP800-90B health tests: %s\n"
		 " SP800-90B health test failures: %llu\n",
		 esdm_sched_ebpf_es.loaded ? "true" : "false",
		 esdm_sched_ebpf_entropylevel(0), esdm_sched_ebpf_poolsize(),
		 (unsigned long long)esdm_sched_ebpf_es.total_events,
		 esdm_config_es_sched_ebpf_entropy_rate(),
		 esdm_sched_ebpf_es.tier == 2 ? "CPU cycle counter (perf)" :
						      "monotonic clock",
		 esdm_sched_ebpf_es.flush_timer ? "true" : "false",
		 esdm_sched_ebpf_es.perm_failure ?
			 "permanent failure" :
			       (esdm_sched_ebpf_es.health_enabled ? "active" :
								    "disabled"),
		 (unsigned long long)esdm_sched_ebpf_es.health_failures);
}

static bool esdm_sched_ebpf_active(void)
{
	return esdm_sched_ebpf_es.loaded;
}

struct esdm_es_cb esdm_es_sched_ebpf = {
	.name = "SchedulerEBPF",
	.init = esdm_sched_ebpf_initialize,
	.monitor_es = esdm_sched_ebpf_seed_monitor,
	.fini = esdm_sched_ebpf_finalize,
	.get_ent = esdm_sched_ebpf_get,
	.curr_entropy = esdm_sched_ebpf_entropylevel,
	.max_entropy = esdm_sched_ebpf_poolsize,
	.state = esdm_sched_ebpf_es_state,
	.reset = esdm_sched_ebpf_reset,
	.active = esdm_sched_ebpf_active,
};
