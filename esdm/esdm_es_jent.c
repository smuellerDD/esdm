/*
 * ESDM Fast Entropy Source: Jitter RNG
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <jitterentropy.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdatomic.h>
#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_jent.h"
#include "esdm_es_mgr.h"
#include "helper.h"
#include "esdm_logger.h"
#include "mutex.h"
#include "mutex_w.h"
#include "ret_checkers.h"
#include "test_pertubation.h"
#include "threading_support.h"

/*
 * Keeps the collectors from being freed or replaced during a read: reads take
 * it shared, init, teardown and self test exclusively. Writer-preferring, as
 * reads are a steady stream under load.
 */
static mutex_t esdm_jent_lock = MUTEX_UNLOCKED_PREFER_WRITER;

static atomic_int esdm_jent_initialized = 0;

/*
 * The synchronous collectors, each with its own lock: a read takes a free one,
 * so seedings of different DRNGs collect in parallel - collecting dominates
 * the seeding time. Their number is esdm_config_es_jent_instances() at init.
 */
struct esdm_jent_sync {
	mutex_w_t lock;
	struct rand_data *ec;
	bool failed; /* Its last read failed, under lock */
};
static struct esdm_jent_sync *esdm_jent_sync = NULL;
/* Atomic for esdm_jent_seed_admit(), written under esdm_jent_lock alone */
static atomic_uint esdm_jent_num_sync = 0;
static atomic_uint esdm_jent_sync_next = 0;

/* Reads holding or waiting for a collector; admitted seedings under way */
static atomic_uint esdm_jent_sync_users = 0;
static atomic_uint esdm_jent_seed_admitted = 0;

/*
 * No entropy is claimed while a collector fails to read (permanent health test
 * or bound KAT failure) or the self test fails, until the collector's next good
 * read or the next passing self test respectively, or a reinit.
 */
static atomic_uint esdm_jent_read_failures = 0;
static atomic_bool esdm_jent_selftest_failed = false;

int esdm_jent_status(char *buf, size_t buf_length)
{
	int ret = -ENOENT;

#if JENT_VERSION >= 3070000
	/* The first collector stands for all, they run with the same settings */
	mutex_lock(&esdm_jent_lock);
	if (atomic_load(&esdm_jent_initialized) && esdm_jent_num_sync) {
		ret = jent_status(esdm_jent_sync[0].ec, buf, buf_length);
	} else {
		ret = -EAGAIN;
	}
	mutex_unlock(&esdm_jent_lock);
#else
	snprintf(buf, buf_length, "{}");
#endif

	return ret;
}

bool esdm_jent_ntg1(void)
{
#if JENT_VERSION >= 3070000
	const bool jent_secure_memory = jent_secure_memory_supported();
#ifdef ESDM_JENT_NTG1
	const bool jent_ntg1 = true;
#else
	const bool jent_ntg1 = false;
#endif
#else
	const bool jent_secure_memory = false;
	const bool jent_ntg1 = false;
#endif

	return jent_secure_memory && jent_ntg1;
}

static uint32_t esdm_jent_entropylevel(uint32_t requested_bits)
{
	return esdm_fast_noise_entropylevel(
		atomic_load(&esdm_jent_initialized) &&
				!atomic_load(&esdm_jent_read_failures) &&
				!atomic_load(&esdm_jent_selftest_failed) ?
			esdm_config_es_jent_entropy_rate() :
			0,
		requested_bits);
}

static uint32_t esdm_jent_poolsize(void)
{
	return esdm_jent_entropylevel(esdm_security_strength());
}

static bool esdm_jent_read_failed(void)
{
	return !!atomic_load(&esdm_jent_read_failures);
}

/*
 * esdm_get_jent() - Get Jitter RNG entropy
 *
 * @sync: the synchronous collector to read with
 * @eb: entropy buffer to store entropy
 * @requested_bits: requested entropy in bits
 */
static void esdm_jent_get(struct esdm_jent_sync *sync,
			  struct entropy_es *eb_es, uint32_t requested_bits)
{
	ssize_t ret;
	uint32_t ent_bits;

	if (!atomic_load(&esdm_jent_initialized))
		goto err;

	ret = jent_read_entropy_safe(&sync->ec, (char *)eb_es->e,
				     requested_bits >> 3);
	if (esdm_test_jent_sync_read_fails())
		ret = -1;

	if (ret < 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "Jitter RNG failed with %zd\n", ret);
		if (!sync->failed) {
			sync->failed = true;
			if (!atomic_fetch_add(&esdm_jent_read_failures, 1))
				esdm_logger(
					LOGGER_WARN, LOGGER_C_ES,
					"JitterRNG ES: the Jitter RNG failed (%zd) - no entropy until it delivers again\n",
					ret);
		}
		goto err;
	}

	if (sync->failed) {
		sync->failed = false;
		if (atomic_fetch_sub(&esdm_jent_read_failures, 1) == 1)
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_ES,
				"JitterRNG ES: the Jitter RNG delivers again\n");
	}

	ent_bits = esdm_jent_entropylevel((uint32_t)(ret << 3));
	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"obtained %u bits of entropy from Jitter RNG collector %u of %u\n",
		ent_bits, (unsigned int)(sync - esdm_jent_sync),
		atomic_load(&esdm_jent_num_sync));

	eb_es->e_bits = ent_bits;
	return;

err:
	eb_es->e_bits = 0;
}

/*
 * A synchronous collector, locked: a free one, otherwise - if the caller may
 * @wait - the next in turn. The caller holds esdm_jent_lock shared.
 */
static struct esdm_jent_sync *esdm_jent_sync_get(bool wait)
{
	unsigned int i, start, n = esdm_jent_num_sync;
	struct esdm_jent_sync *sync;

	if (!n)
		return NULL;

	atomic_fetch_add(&esdm_jent_sync_users, 1);
	start = atomic_fetch_add(&esdm_jent_sync_next, 1);
	for (i = 0; i < n; i++) {
		sync = &esdm_jent_sync[(start + i) % n];
		if (!mutex_w_trylock(&sync->lock))
			return sync;
	}

	if (!wait) {
		atomic_fetch_sub(&esdm_jent_sync_users, 1);
		return NULL;
	}

	sync = &esdm_jent_sync[start % n];
	mutex_w_lock(&sync->lock);
	return sync;
}

/* Read with @sync of esdm_jent_sync_get() (none: no entropy), then free it */
static void esdm_jent_sync_read(struct esdm_jent_sync *sync,
				struct entropy_es *eb_es,
				uint32_t requested_bits)
{
	if (!sync) {
		eb_es->e_bits = 0;
		return;
	}

	esdm_jent_get(sync, eb_es, requested_bits);
	mutex_w_unlock(&sync->lock);
	atomic_fetch_sub(&esdm_jent_sync_users, 1);
}

/*
 * Admit a seeding of a caller that may not wait (RPC or EGD worker) only while
 * a collector is free, instead of queueing it behind seedings under way. Reads
 * holding or waiting for a collector and admitted seedings count as taken, the
 * latter's own read once more. Not strict: a read may still win the collector,
 * costing the seeding one collection. esdm_jent_seed_done() ends an admission.
 */
bool esdm_jent_seed_admit(void)
{
	unsigned int n = atomic_load(&esdm_jent_num_sync);
	unsigned int admitted = atomic_load(&esdm_jent_seed_admitted);

	if (!n || !atomic_load(&esdm_jent_initialized)) {
		atomic_fetch_add(&esdm_jent_seed_admitted, 1);
		return true;
	}

	do {
		if (atomic_load(&esdm_jent_sync_users) + admitted >= n)
			return false;
	} while (!atomic_compare_exchange_weak(&esdm_jent_seed_admitted,
					       &admitted, admitted + 1));

	return true;
}

void esdm_jent_seed_done(void)
{
	atomic_fetch_sub(&esdm_jent_seed_admitted, 1);
}

/* Free the synchronous collectors, under esdm_jent_lock taken alone */
static void esdm_jent_sync_free(void)
{
	unsigned int i;

	for (i = 0; i < esdm_jent_num_sync; i++) {
		jent_entropy_collector_free(esdm_jent_sync[i].ec);
		mutex_w_destroy(&esdm_jent_sync[i].lock);
	}
	free(esdm_jent_sync);
	esdm_jent_sync = NULL;
	esdm_jent_num_sync = 0;
	atomic_store(&esdm_jent_read_failures, 0);
}

/* Allocate the synchronous collectors, under esdm_jent_lock taken alone */
static int esdm_jent_sync_alloc(unsigned int osr, unsigned int flags)
{
	unsigned int i, n = esdm_config_es_jent_instances();

	esdm_jent_sync = calloc(n, sizeof(*esdm_jent_sync));
	if (!esdm_jent_sync)
		return -ENOMEM;

	for (i = 0; i < n; i++) {
		if (mutex_w_init(&esdm_jent_sync[i].lock, 0, 0))
			goto err;
		esdm_jent_sync[i].ec = jent_entropy_collector_alloc(osr, flags);
		if (!esdm_jent_sync[i].ec) {
			mutex_w_destroy(&esdm_jent_sync[i].lock);
			goto err;
		}
	}
	esdm_jent_num_sync = n;
	if (n > 1)
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
			    "JitterRNG ES: %u collectors serve side by side\n",
			    n);

	return 0;

err:
	/* Undo what was allocated so it is not leaked */
	esdm_jent_num_sync = i;
	esdm_jent_sync_free();
	return -EFAULT;
}

static void esdm_jent_get_check(struct entropy_es *eb_es,
				uint32_t requested_bits)
{
	mutex_reader_lock(&esdm_jent_lock);
	esdm_jent_sync_read(esdm_jent_sync_get(true), eb_es, requested_bits);
	mutex_reader_unlock(&esdm_jent_lock);
}

static void esdm_jent_finalize(void)
{
	if (!atomic_load(&esdm_jent_initialized))
		return;

	atomic_store(&esdm_jent_initialized, 0);

	mutex_lock(&esdm_jent_lock);
	esdm_jent_sync_free();
	mutex_unlock(&esdm_jent_lock);
}

/* The flags the Jitter RNG is operated with. */
static unsigned int esdm_jent_flags(void)
{
	unsigned int flags = 0;

	if (esdm_config_sp80090c_compliant() || esdm_config_fips_enabled() ||
	    esdm_ntg1_2024_compliant()) {
		flags |= JENT_FORCE_FIPS;
	}

#if JENT_VERSION >= 3070000
	if (esdm_jent_ntg1()) {
		flags |= JENT_NTG1;
	}

	switch (ESDM_JENT_MAX_MEM) {
	case 1:
		flags |= JENT_MAX_MEMSIZE_1kB;
		break;
	case 2:
		flags |= JENT_MAX_MEMSIZE_2kB;
		break;
	case 3:
		flags |= JENT_MAX_MEMSIZE_4kB;
		break;
	case 4:
		flags |= JENT_MAX_MEMSIZE_8kB;
		break;
	case 5:
		flags |= JENT_MAX_MEMSIZE_16kB;
		break;
	case 6:
		flags |= JENT_MAX_MEMSIZE_32kB;
		break;
	case 7:
		flags |= JENT_MAX_MEMSIZE_64kB;
		break;
	case 8:
		flags |= JENT_MAX_MEMSIZE_128kB;
		break;
	case 9:
		flags |= JENT_MAX_MEMSIZE_256kB;
		break;
	case 10:
		flags |= JENT_MAX_MEMSIZE_512kB;
		break;
	case 11:
		flags |= JENT_MAX_MEMSIZE_1MB;
		break;
	case 12:
		flags |= JENT_MAX_MEMSIZE_2MB;
		break;
	case 13:
		flags |= JENT_MAX_MEMSIZE_4MB;
		break;
	case 14:
		flags |= JENT_MAX_MEMSIZE_8MB;
		break;
	case 15:
		flags |= JENT_MAX_MEMSIZE_16MB;
		break;
	case 16:
		flags |= JENT_MAX_MEMSIZE_32MB;
		break;
	case 17:
		flags |= JENT_MAX_MEMSIZE_64MB;
		break;
	case 18:
		flags |= JENT_MAX_MEMSIZE_128MB;
		break;
	case 19:
		flags |= JENT_MAX_MEMSIZE_256MB;
		break;
	case 20:
		flags |= JENT_MAX_MEMSIZE_512MB;
		break;
	}

	switch (ESDM_JENT_HASH_LOOP_COUNT) {
	case 0:
		flags |= JENT_HASHLOOP_1;
		break;
	case 1:
		flags |= JENT_HASHLOOP_2;
		break;
	case 2:
		flags |= JENT_HASHLOOP_4;
		break;
	case 3:
		flags |= JENT_HASHLOOP_8;
		break;
	case 4:
		flags |= JENT_HASHLOOP_16;
		break;
	case 5:
		flags |= JENT_HASHLOOP_32;
		break;
	case 6:
		flags |= JENT_HASHLOOP_64;
		break;
	case 7:
		flags |= JENT_HASHLOOP_128;
		break;
	}
#endif /* JENT_VERSION >= 3070000 */

	return flags;
}

static int esdm_jent_initialize(void)
{
	unsigned int flags = esdm_jent_flags();
	int ret;

	/* Allow the init function to be called multiple times. */
	esdm_jent_finalize();

	/*
	 * esdm_jent_lock is statically initialized and left unlocked by
	 * esdm_jent_finalize() above, so just acquire it.
	 */
	mutex_lock(&esdm_jent_lock);

	CKINT(jent_entropy_init_ex(ESDM_JENT_OSR, flags));

	/* Initialize the Jitter RNG after the clocksources are initialized. */
	CKINT(esdm_jent_sync_alloc(ESDM_JENT_OSR, flags));

	/* New collectors, past the startup tests the self test runs */
	atomic_store(&esdm_jent_selftest_failed, false);
	atomic_store(&esdm_jent_initialized, 1);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "Jitter RNG working on current system\n");

out:
	mutex_unlock(&esdm_jent_lock);

	if (ret) {
		esdm_config_es_jent_entropy_rate_set(0);
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "Jitter RNG unusable on current system\n");
	}

	return ret;
}

static void esdm_jent_es_state_json(char *buf, size_t buflen)
{
	struct json_object *obj = json_object_new_object();
	bool sp80090b = esdm_es_oversampling() || esdm_config_fips_enabled() ||
			esdm_ntg1_2024_compliant() || esdm_jent_ntg1();
	char compliance[32];

	if (obj) {
		snprintf(compliance, sizeof(compliance), "%s%s%s",
			 sp80090b ? "SP800-90B" : "",
			 (sp80090b && esdm_jent_ntg1()) ? " " : "",
			 esdm_jent_ntg1() ? "NTG.1(2024)" : "");
		json_object_object_add(
			obj, "available_entropy",
			json_object_new_int64(esdm_jent_poolsize()));
		json_object_object_add(obj, "library_version",
				       json_object_new_int64(jent_version()));
		json_object_object_add(obj, "standards_compliance",
				       json_object_new_string(compliance));
		json_object_object_add(
			obj, "entropy_rate_per_256_data_bits",
			json_object_new_int64(esdm_jent_entropylevel(256)));
		json_object_object_add(obj, "oversampling_rate",
				       json_object_new_int64(ESDM_JENT_OSR));
	}

	esdm_es_state_write(obj, buf, buflen);
}

static bool esdm_jent_active(void)
{
	return !!atomic_load(&esdm_jent_initialized);
}

/*
 * SP800-90B section 4.3 asks an entropy source for its start-up health tests,
 * and IG 10.3.A for the same tests on demand. From jitterentropy 3.8.0 on, the
 * known answer tests of the conditioning component run bound to the
 * collectors, which take a failure as reason to stop serving.
 */
static int esdm_jent_selftest(void)
{
#if JENT_VERSION >= 3080000
	unsigned int i;
#endif
	int ret;

	if (!atomic_load(&esdm_jent_initialized)) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"JitterRNG ES: not initialized - nothing to test\n");
		return 0;
	}

	/*
	 * Under the ES lock, which is what the initialization holds while it
	 * runs the very same call: the library keeps state of its own behind
	 * it, and a self test landing in the middle of a reinitialization would
	 * be two of these at once.
	 */
	mutex_lock(&esdm_jent_lock);

#if JENT_VERSION >= 3080000
	/*
	 * The conditioning KATs, bound to each collector: one failing serves
	 * nothing until a later run passes. Reads hold esdm_jent_lock, so no
	 * jent_read_entropy_safe() replaces a collector meanwhile.
	 */
	ret = 0;
	for (i = 0; i < esdm_jent_num_sync; i++) {
		if (jent_selftest(esdm_jent_sync[i].ec))
			ret = EHASH;
	}
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"JitterRNG ES: known answer tests of the conditioning component failed\n");
	} else {
		ret = jent_entropy_init_ex(ESDM_JENT_OSR, esdm_jent_flags());
	}
#else
	ret = jent_entropy_init_ex(ESDM_JENT_OSR, esdm_jent_flags());
#endif

	mutex_unlock(&esdm_jent_lock);

	if (ret) {
		atomic_store(&esdm_jent_selftest_failed, true);
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"JitterRNG ES: SP800-90B health tests failed: %d\n",
			ret);
		return -EFAULT;
	}

	if (atomic_exchange(&esdm_jent_selftest_failed, false))
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "JitterRNG ES: self test passed again\n");

	return 0;
}

struct esdm_es_cb esdm_es_jent = {
	.name = "JitterRNG",
	.init = esdm_jent_initialize,
	.fini = esdm_jent_finalize,
	.monitor_es = NULL,
	.get_ent = esdm_jent_get_check,
	.curr_entropy = esdm_jent_entropylevel,
	.max_entropy = esdm_jent_poolsize,
	.state_json = esdm_jent_es_state_json,
	.reset = NULL,
	.active = esdm_jent_active,
	.selftest = esdm_jent_selftest,
	.read_failed = esdm_jent_read_failed,
};
