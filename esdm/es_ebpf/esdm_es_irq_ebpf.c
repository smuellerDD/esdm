/*
 * ESDM Slow Entropy Source: eBPF-based interrupt entropy source
 *
 * Collects entropy from the timing of hardware and soft interrupts observed
 * via eBPF programs attached to the irq_handler_entry and softirq_entry
 * tracepoints. In contrast to the interrupt entropy source implemented by
 * esdm_es_irq.c, no kernel patch is required. Also, the interrupt timings
 * are only observed and not diverted from the kernel RNG - as the kernel RNG
 * processes the same events, the data of this entropy source is credited
 * with no entropy by default.
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

#include "config.h"
#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_ebpf.h"
#include "esdm_es_irq_ebpf.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "helper.h"
#include "math_helper.h"
#include "mutex.h"
#include "test_pertubation.h"

/* The bpftool-generated skeleton does not satisfy the strict warnings */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "esdm_es_irq_ebpf.skel.h"
#pragma GCC diagnostic pop

static struct esdm_es_irq_ebpf_bpf *esdm_irq_ebpf_skel = NULL;
static struct esdm_ebpf_es esdm_irq_ebpf_es = {
	.name = "InterruptEBPF",
	.entropy_rate = esdm_config_es_irq_ebpf_entropy_rate,
	.osr = ESDM_IRQ_EBPF_OSR,
};

/*
 * Serializes the skeleton / ring buffer state between the monitor thread,
 * the seed buffer filler and (re)initialization.
 */
static DEFINE_MUTEX_UNLOCKED(irq_ebpf_mutex);

bool esdm_irq_ebpf_enabled(void)
{
	return esdm_irq_ebpf_es.loaded &&
	       esdm_config_es_irq_ebpf_entropy_rate() > 0;
}

/* Caller must hold irq_ebpf_mutex (write lock). */
static void esdm_irq_ebpf_finalize_locked(void)
{
	/*
	 * Detach before the entropy source is torn down: the tear-down erases
	 * the collected events, and an attached program would go on collecting
	 * into what it just erased.
	 */
	if (esdm_irq_ebpf_skel)
		esdm_es_irq_ebpf_bpf__detach(esdm_irq_ebpf_skel);

	esdm_ebpf_fini_es(&esdm_irq_ebpf_es);

	if (esdm_irq_ebpf_skel) {
		esdm_es_irq_ebpf_bpf__destroy(esdm_irq_ebpf_skel);
		esdm_irq_ebpf_skel = NULL;
	}
}

static void esdm_irq_ebpf_finalize(void)
{
	mutex_lock(&irq_ebpf_mutex);
	esdm_irq_ebpf_finalize_locked();
	mutex_unlock(&irq_ebpf_mutex);
}

/*
 * Open, configure and load the eBPF object.
 *
 * @fatal is set when the failure is one the caller must not paper over by
 * running without this entropy source - see esdm_ebpf_prepare().
 */
static int esdm_irq_ebpf_open_load(struct esdm_es_irq_ebpf_bpf **skel_out,
				   bool *fatal)
{
	struct esdm_es_irq_ebpf_bpf *skel;
	int ret;

	skel = esdm_es_irq_ebpf_bpf__open();
	if (!skel) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"Opening of eBPF interrupt entropy source object failed: %s\n",
			strerror(errno));
		return -errno;
	}

	ret = esdm_ebpf_prepare(&esdm_irq_ebpf_es, skel->obj,
				&skel->rodata->esdm_ebpf_cfg);
	if (ret) {
		*fatal = true;
		goto err;
	}

	ret = esdm_es_irq_ebpf_bpf__load(skel);
	if (ret)
		goto err;

	*skel_out = skel;
	return 0;

err:
	esdm_es_irq_ebpf_bpf__destroy(skel);
	esdm_ebpf_fini_es(&esdm_irq_ebpf_es);
	return ret;
}

static int esdm_irq_ebpf_initialize(void)
{
	struct esdm_es_irq_ebpf_bpf *skel = NULL;
	bool fatal = false;
	int ret;

	mutex_lock(&irq_ebpf_mutex);

	/* Allow the init function to be called multiple times */
	esdm_irq_ebpf_finalize_locked();

	if (!esdm_ebpf_btf_available()) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF interrupt-based entropy source as the kernel does not expose BTF data\n");
		ret = 0;
		goto out;
	}

	if (!esdm_ebpf_highres_timer()) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF interrupt-based entropy source as no high-resolution timer is available\n");
		ret = 0;
		goto out;
	}

	esdm_ebpf_setup_logging();

	ret = esdm_irq_ebpf_open_load(&skel, &fatal);
	if (ret && fatal) {
		/*
		 * The source could only run in a state where the raw samples
		 * it collects cannot be erased again. That is not a degraded
		 * mode to fall back to - fail the initialization, which fails
		 * esdm_init() and terminates the ESDM.
		 */
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"eBPF interrupt-based entropy source cannot be set up so that its collected events can be erased again - refusing to start: %d\n",
			ret);
		goto out;
	}
	if (ret) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF interrupt-based entropy source as the programs cannot be loaded (kernel too old or missing privileges?): %d\n",
			ret);
		ret = 0;
		goto out;
	}

	ret = esdm_es_irq_ebpf_bpf__attach(skel);
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"Attaching of eBPF interrupt entropy source programs failed: %d\n",
			ret);
		esdm_es_irq_ebpf_bpf__destroy(skel);
		esdm_ebpf_fini_es(&esdm_irq_ebpf_es);
		ret = 0;
		goto out;
	}

	ret = esdm_ebpf_init_es(&esdm_irq_ebpf_es, skel->obj);
	if (ret) {
		esdm_es_irq_ebpf_bpf__destroy(skel);
		esdm_ebpf_fini_es(&esdm_irq_ebpf_es);
		goto out;
	}

	esdm_irq_ebpf_skel = skel;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "eBPF interrupt-based entropy source initialized\n");

out:
	mutex_unlock(&irq_ebpf_mutex);
	return ret;
}

static int esdm_irq_ebpf_seed_monitor(void)
{
	uint32_t ent, max_ent;

	if (!esdm_irq_ebpf_es.loaded)
		return 0;

	/*
	 * Top the conditioning pool up while it has room for the entropy of
	 * more events. Once it has not, the fetching stops and the eBPF
	 * programs go back to collecting for nobody until an extraction has
	 * spent what is in the pool.
	 */
	mutex_lock(&irq_ebpf_mutex);
	esdm_ebpf_refill(&esdm_irq_ebpf_es);
	ent = esdm_ebpf_avail_entropy(&esdm_irq_ebpf_es);
	max_ent = esdm_ebpf_max_entropy(&esdm_irq_ebpf_es);
	mutex_unlock(&irq_ebpf_mutex);

	if (esdm_pool_all_nodes_seeded_get())
		return 0;

	if (!esdm_config_es_irq_ebpf_entropy_rate())
		return 0;

	if (ent >= min_uint32(esdm_security_strength(), max_ent)) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "Full entropy of eBPF interrupt ES detected\n");
		esdm_es_add_entropy();
		esdm_test_seed_entropy(ent);
	}

	return 0;
}

static uint32_t esdm_irq_ebpf_entropylevel(uint32_t requested_bits)
{
	uint32_t ent;

	(void)requested_bits;

	mutex_reader_lock(&irq_ebpf_mutex);
	ent = esdm_ebpf_avail_entropy(&esdm_irq_ebpf_es);
	mutex_reader_unlock(&irq_ebpf_mutex);

	return ent;
}

static uint32_t esdm_irq_ebpf_poolsize(void)
{
	uint32_t ent;

	mutex_reader_lock(&irq_ebpf_mutex);
	ent = esdm_ebpf_max_entropy(&esdm_irq_ebpf_es);
	mutex_reader_unlock(&irq_ebpf_mutex);

	return ent;
}

static void esdm_irq_ebpf_get(struct entropy_es *eb_es, uint32_t requested_bits,
			      bool __unused unused)
{
	mutex_lock(&irq_ebpf_mutex);
	esdm_ebpf_get_ent(&esdm_irq_ebpf_es, eb_es, requested_bits);
	mutex_unlock(&irq_ebpf_mutex);
}

static void esdm_irq_ebpf_reset(void)
{
	mutex_lock(&irq_ebpf_mutex);
	esdm_ebpf_pool_reset(&esdm_irq_ebpf_es);
	mutex_unlock(&irq_ebpf_mutex);
}

static void esdm_irq_ebpf_es_state(char *buf, size_t buflen)
{
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n"
		 " Oversampling Rate: %u\n"
		 " Standards compliance: %s\n"
		 " eBPF programs loaded: %s\n"
		 " Health test failures: %llu%s\n",
		 esdm_irq_ebpf_entropylevel(0),
		 esdm_config_es_irq_ebpf_entropy_rate(),
		 esdm_ebpf_osr(&esdm_irq_ebpf_es),
		 esdm_irq_ebpf_es.health_enabled ? "SP800-90B" : "",
		 esdm_irq_ebpf_es.loaded ? "true" : "false",
		 (unsigned long long)esdm_irq_ebpf_es.health_failures,
		 esdm_irq_ebpf_es.perm_failure ? " (permanent failure)" : "");
}

static bool esdm_irq_ebpf_active(void)
{
	return esdm_irq_ebpf_es.loaded;
}

struct esdm_es_cb esdm_es_irq_ebpf = {
	.name = "InterruptEBPF",
	.init = esdm_irq_ebpf_initialize,
	.monitor_es = esdm_irq_ebpf_seed_monitor,
	.fini = esdm_irq_ebpf_finalize,
	.get_ent = esdm_irq_ebpf_get,
	.curr_entropy = esdm_irq_ebpf_entropylevel,
	.max_entropy = esdm_irq_ebpf_poolsize,
	.state = esdm_irq_ebpf_es_state,
	.reset = esdm_irq_ebpf_reset,
	.active = esdm_irq_ebpf_active,
};
