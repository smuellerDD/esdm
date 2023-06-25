/*
 * ESDM Entropy sources management
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "es_cpu/cpu_random.h"
#include "esdm.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_aux.h"
#include "esdm_es_cpu.h"
#include "esdm_es_hwrand.h"
#include "esdm_es_irq.h"
#include "esdm_es_jent.h"
#include "esdm_es_krng.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched.h"
#include "esdm_interface_dev_common.h"
#include "esdm_shm_status.h"
#include "helper.h"
#include "logger.h"
#include "memset_secure.h"
#include "mutex_w.h"
#include "queue.h"
#include "ret_checkers.h"
#include "test_pertubation.h"
#include "visibility.h"

struct esdm_state {
	bool esdm_operational;		/* Is DRNG operational? */
	bool esdm_fully_seeded;		/* Is DRNG fully seeded? */
	bool esdm_min_seeded;		/* Is DRNG minimally seeded? */
	bool all_online_nodes_seeded;	/* All DRNGs nodes seeded? */

	/*
	 * To ensure that external entropy providers cannot dominate the
	 * internal noise sources but yet cannot be dominated by internal
	 * noise sources, the following booleans are intended to allow
	 * external to provide seed once when a DRNG reseed occurs. This
	 * triggering of external noise source is performed even when the
	 * entropy pool has sufficient entropy.
	 */

	atomic_t boot_entropy_thresh;	/* Reseed threshold */
	mutex_w_t reseed_in_progress;	/* Flag for on executing reseed */
};

static struct esdm_state esdm_state = {
	false, false, false, false,
	.boot_entropy_thresh	= ATOMIC_INIT(ESDM_FULL_SEED_ENTROPY_BITS),
	.reseed_in_progress	= MUTEX_W_UNLOCKED,
};

/*
 * If the entropy count falls under this number of bits, then we
 * should wake up processes which are selecting or polling on write
 * access to /dev/random.
 */
uint32_t esdm_write_wakeup_bits = (ESDM_WRITE_WAKEUP_ENTROPY << 3);

static atomic_t esdm_es_mgr_terminate = ATOMIC_INIT(0);

/* Wait queue to wait until the ESDM is not initialized. */
static DECLARE_WAIT_QUEUE(esdm_monitor_wait);

/*
 * The entries must be in the same order as defined by enum esdm_internal_es and
 * enum esdm_external_es
 */
struct esdm_es_cb *esdm_es[] = {
#ifdef ESDM_ES_IRQ
	&esdm_es_irq,
#endif
#ifdef ESDM_ES_SCHED
	&esdm_es_sched,
#endif
#ifdef ESDM_ES_JENT
	&esdm_es_jent,
#endif
#ifdef ESDM_ES_CPU
	&esdm_es_cpu,
#endif
#ifdef ESDM_ES_KERNEL_RNG
	&esdm_es_krng,
#endif
#ifdef ESDM_ES_HWRAND
	&esdm_es_hwrand,
#endif
	&esdm_es_aux
};

/******************************** ES monitor **********************************/

/* Restart the ES monitor if it is sleeping */
static void esdm_es_mgr_monitor_wakeup(void)
{
	thread_wake_all(&esdm_monitor_wait);
}

/* ES monitor worker loop */
int esdm_es_mgr_monitor_initialize(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 1U<<29 };
	unsigned int i, avail = 0;

	for_each_esdm_es(i) {
		if (esdm_es[i]->active())
			avail += !!esdm_es[i]->monitor_es;
	}

	if (!avail) {
		logger(LOGGER_DEBUG, LOGGER_C_ES,
		       "Full entropy monitor not started as no slow entropy sources present\n");
		return 0;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ES, "Full entropy monitor started\n");

	while (!atomic_read(&esdm_es_mgr_terminate)) {
		unsigned int j;

		for_each_esdm_es(j) {
			if (esdm_es[j]->monitor_es)
				esdm_es[j]->monitor_es();
		}

		thread_wait_event(&esdm_init_wait,
				  !esdm_pool_all_nodes_seeded_get() &&
				  !atomic_read(&esdm_es_mgr_terminate));

		nanosleep(&ts, NULL);
	}

	logger(LOGGER_VERBOSE, LOGGER_C_ES, "Stopping entropy monitor\n");
	return 0;
}

/******************************** Read Helper *********************************/

/**
 * Common read function to obtain data from the kernel entropy sources
 * such as IRQ / Sched ES.
 *
 * @param [out] eb_es entropy buffer to be filled
 * @param [in] fd file descriptor to the entropy source
 * @param [in] ioctl_cmd IOCTL command to be used with the FD
 * @param [in] data_size Specification of the data size detected during
 *			 initialization of the ES
 * @param [in] name Entropy source name
 */
void esdm_kernel_read(struct entropy_es *eb_es, int fd, unsigned int ioctl_cmd,
		      enum esdm_es_data_size data_size, const char *name)
{
	struct entropy_es_small small_es;
	struct entropy_es_large large_es;
	ssize_t ret;
	uint8_t *buf;

	if (fd < 0)
		goto err;

	switch (data_size) {
	case esdm_es_data_equal:
		buf = (uint8_t *)eb_es;
		break;
	case esdm_es_data_large:
		buf = (uint8_t *)&large_es;
		break;
	case esdm_es_data_small:
		buf = (uint8_t *)&small_es;
		break;
	default:
		goto err;
	}

	ret = ioctl(fd, ioctl_cmd, buf);
	if (ret < 0) {
		logger(LOGGER_WARN, LOGGER_C_ES,
		       "failed to obtain entropy from ES %s, error %d\n", name,
		       errno);
		goto err;
	}

	switch (data_size) {
	case esdm_es_data_equal:
		/* Nothing to do */
		break;
	case esdm_es_data_large:
		/*
		 * Use min_size to convince static code analyzer that there is
		 * no overflow, but it should always be the case that
		 * ESDM_DRNG_INIT_SEED_SIZE_BYTES is smaller when reaching
		 * this branch.
		 */
		memcpy(eb_es->e, large_es.e,
		       min_size(ESDM_DRNG_INIT_SEED_SIZE_BYTES,
				ESDM_DRNG_OVERSAMPLE_SEED_SIZE_BYTES));

		/*
		 * According to SP800-90B table 1, the truncated hash contains
		 * the amount of entropy of the original hash capped by the
		 * truncated size.
		 */
		eb_es->e_bits = min_uint32(ESDM_DRNG_INIT_SEED_SIZE_BITS,
					   large_es.e_bits);

		memset_secure(&large_es, 0, sizeof(large_es));

		break;
	case esdm_es_data_small:
		memcpy(eb_es->e, small_es.e, ESDM_DRNG_SECURITY_STRENGTH_BYTES);
		eb_es->e_bits = small_es.e_bits;
		memset_secure(&small_es, 0, sizeof(small_es));
		break;
	default:
		goto err;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "obtained %u bits of entropy from ES %s\n", eb_es->e_bits, name);

	return;

err:
	eb_es->e_bits = 0;
}

/**
 * Common service function to set the requested amount of bits with the kernel
 * entropy sources.
 *
 * @param [in/out] configured_bits Currently and newly configured bit size
 * @param [in] requested_bits Bit size to be configured
 * @param [in] fd file descriptor to the entropy source
 * @param [in] ioctl_cmd IOCTL command to be used with the FD
 */
void esdm_kernel_set_requested_bits(uint32_t *configured_bits,
				    uint32_t requested_bits, int fd,
				    unsigned int ioctl_cmd)
{
	if (*configured_bits != requested_bits && fd >= 0) {
		uint32_t data[2];
		ssize_t ret;

		data[0] = requested_bits;
		data[1] = 0;
		ret = ioctl(fd, ioctl_cmd, &data);
		if (ret >= 0) {
			*configured_bits = requested_bits;
			logger(LOGGER_DEBUG, LOGGER_C_ES,
			       "Set requested %u bits with kernel\n",
			       requested_bits);
		} else {
			logger(LOGGER_WARN, LOGGER_C_ES,
			       "Failed to set requested %u bits with kernel\n",
			       requested_bits);
		}
	}
}

/********************************** Helper ***********************************/

void esdm_debug_report_seedlevel(const char *name)
{
	if (!esdm_state_min_seeded())
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "%s called without reaching minimally seeded level (available entropy %u)\n",
		       name, esdm_avail_entropy());

	esdm_force_fully_seeded();
}

/*
 * Reading of the ESDM pool is only allowed by one caller. The reading is
 * only performed to (re)seed DRNGs. Thus, if this "lock" is already taken,
 * the reseeding operation is in progress. The caller is not intended to wait
 * but continue with its other operation.
 */
int esdm_pool_trylock(void)
{
	return mutex_w_trylock(&esdm_state.reseed_in_progress);
}

void esdm_pool_lock(void)
{
	mutex_w_lock(&esdm_state.reseed_in_progress);
}

void esdm_pool_unlock(void)
{
	mutex_w_unlock(&esdm_state.reseed_in_progress);
}

/* Set new entropy threshold for reseeding during boot */
void esdm_set_entropy_thresh(uint32_t new_entropy_bits)
{
	atomic_set(&esdm_state.boot_entropy_thresh, (int)new_entropy_bits);
}

/*
 * Reset ESDM state - the entropy counters are reset, but the data that may
 * or may not have entropy remains in the pools as this data will not hurt.
 */
void esdm_reset_state(void)
{
	uint32_t i;

	for_each_esdm_es(i) {
		if (esdm_es[i]->reset)
			esdm_es[i]->reset();
	}
	esdm_state.esdm_operational = false;
	esdm_state.esdm_fully_seeded = false;
	esdm_state.esdm_min_seeded = false;
	esdm_state.all_online_nodes_seeded = false;
	logger(LOGGER_DEBUG, LOGGER_C_ES, "reset ESDM\n");

	/* Start the entropy monitor */
	esdm_es_mgr_monitor_wakeup();
}

/* Set flag that all DRNGs are fully seeded */
void esdm_pool_all_nodes_seeded(bool set)
{
	esdm_state.all_online_nodes_seeded = set;
	if (set)
		thread_wake_all(&esdm_init_wait);
}

bool esdm_pool_all_nodes_seeded_get(void)
{
	return esdm_state.all_online_nodes_seeded;
}

/* Return boolean whether ESDM reached minimally seed level */
bool esdm_state_min_seeded(void)
{
	return esdm_state.esdm_min_seeded;
}

/* Return boolean whether ESDM reached fully seed level */
DSO_PUBLIC
int esdm_state_fully_seeded(void)
{
	return esdm_state.esdm_fully_seeded;
}

/* Return boolean whether ESDM is considered fully operational */
DSO_PUBLIC
int esdm_state_operational(void)
{
	return esdm_state.esdm_operational;
}

static void esdm_init_wakeup(void)
{
	thread_wake_all(&esdm_init_wait);
}

static uint32_t esdm_avail_entropy_thresh(void)
{
	uint32_t ent_thresh = esdm_security_strength();

	/*
	 * Apply oversampling during initialization according to SP800-90C as
	 * we request a larger buffer from the ES.
	 */
	if (esdm_sp80090c_compliant() &&
	    !esdm_state.all_online_nodes_seeded)
		ent_thresh += ESDM_SEED_BUFFER_INIT_ADD_BITS;

	return ent_thresh;
}

bool esdm_fully_seeded(bool fully_seeded, uint32_t collected_entropy,
		       struct entropy_buf *eb)
{
	/* AIS20/31 NTG.1: two entropy sources with each delivering 220 bits */
	if (esdm_ntg1_2022_compliant()) {
		uint32_t i, result = 0,
			 ent_thresh = esdm_avail_entropy_thresh();

		for_each_esdm_es(i) {
			result += (eb ? eb->entropy_es[i].e_bits :
					esdm_es[i]->curr_entropy(ent_thresh)) >=
				   ESDM_AIS2031_NPTRNG_MIN_ENTROPY;
		}

		return (result >= 2);
	}

	return (collected_entropy >= esdm_get_seed_entropy_osr(fully_seeded));
}

uint32_t esdm_entropy_rate_eb(struct entropy_buf *eb)
{
	uint32_t i, collected_entropy = 0;

	for_each_esdm_es(i)
		collected_entropy += eb->entropy_es[i].e_bits;

	esdm_test_seed_entropy(collected_entropy);

	return collected_entropy;
}

/* Mark one DRNG as not fully seeded */
void esdm_unset_fully_seeded(struct esdm_drng *drng)
{
	drng->fully_seeded = false;
	esdm_pool_all_nodes_seeded(false);

	/*
	 * The init DRNG instance must always be fully seeded as this instance
	 * is the fall-back if any of the per-node DRNG instances is
	 * insufficiently seeded. Thus, we mark the entire ESDM as
	 * non-operational if the initial DRNG becomes not fully seeded.
	 */
	if (drng == esdm_drng_init_instance() && esdm_state_operational()) {
		logger(LOGGER_DEBUG, LOGGER_C_ES,
		       "ESDM set to non-operational\n");
		esdm_state.esdm_operational = false;
		esdm_state.esdm_fully_seeded = false;

		esdm_shm_status_set_operational(false);
	}

	/* If sufficient entropy is available, reseed now. */
	esdm_force_fully_seeded();
	esdm_es_mgr_monitor_wakeup();
}

/* Policy to enable ESDM operational mode */
static void esdm_set_operational(void)
{
	/*
	 * ESDM is operational if the initial DRNG is fully seeded. This state
	 * can only occur if either the external entropy sources provided
	 * sufficient entropy, or the SP800-90B startup test completed for
	 * the internal ES to supply also entropy data.
	 */
	if (esdm_state.esdm_fully_seeded) {
		esdm_state.esdm_operational = true;
		esdm_init_wakeup();
		esdm_shm_status_set_operational(true);
		logger(LOGGER_VERBOSE, LOGGER_C_ES,"ESDM fully operational\n");
	}
}

/* Available entropy in the entire ESDM considering all entropy sources */
DSO_PUBLIC
uint32_t esdm_avail_entropy(void)
{
	uint32_t i, ent = 0, ent_thresh = esdm_avail_entropy_thresh();

	BUILD_BUG_ON(ARRAY_SIZE(esdm_es) != esdm_ext_es_last);
	for_each_esdm_es(i)
		ent += esdm_es[i]->curr_entropy(ent_thresh);
	return ent;
}

DSO_PUBLIC
uint32_t esdm_avail_entropy_aux(void)
{
	uint32_t ent_thresh = esdm_avail_entropy_thresh();

	return esdm_es[esdm_ext_es_aux]->curr_entropy(ent_thresh);
}

DSO_PUBLIC
uint32_t esdm_avail_poolsize_aux(void)
{
	return esdm_es[esdm_ext_es_aux]->max_entropy();
}

DSO_PUBLIC
uint32_t esdm_get_write_wakeup_bits(void)
{
	return esdm_write_wakeup_bits;
}

DSO_PUBLIC
void esdm_set_write_wakeup_bits(uint32_t val)
{
	if (!val)
		return;

	esdm_write_wakeup_bits =
		min_uint32(val, esdm_reduce_by_osr(esdm_get_digestsize()));
}

/**
 * esdm_init_ops() - Set seed stages of ESDM
 *
 * Set the slow noise source reseed trigger threshold. The initial threshold
 * is set to the minimum data size that can be read from the pool: a word. Upon
 * reaching this value, the next seed threshold of 128 bits is set followed
 * by 256 bits.
 *
 * @param [in] eb buffer containing the size of entropy currently injected into
 *		  DRNG - if NULL, the function obtains the available entropy
 *		  from the ES.
 */
void esdm_init_ops(struct entropy_buf *eb)
{
	struct esdm_state *state = &esdm_state;
	uint32_t i, requested_bits, seed_bits = 0;

	if (state->esdm_operational)
		return;

	requested_bits = esdm_ntg1_2022_compliant() ?
		/* Approximation so that two ES should deliver 220 bits each */
		(esdm_avail_entropy() + ESDM_AIS2031_NPTRNG_MIN_ENTROPY) :
		/* Apply SP800-90C oversampling if applicable */
		esdm_get_seed_entropy_osr(state->all_online_nodes_seeded);

	if (eb) {
		seed_bits = esdm_entropy_rate_eb(eb);
	} else {
		uint32_t ent_thresh = esdm_avail_entropy_thresh();

		for_each_esdm_es(i)
			seed_bits += esdm_es[i]->curr_entropy(ent_thresh);
	}

	/* DRNG is seeded with full security strength */
	if (state->esdm_fully_seeded) {
		esdm_set_operational();
		esdm_set_entropy_thresh(requested_bits);
	} else if (esdm_fully_seeded(state->all_online_nodes_seeded,
				     seed_bits, eb)) {
		state->esdm_fully_seeded = true;
		esdm_set_operational();
		state->esdm_min_seeded = true;
		logger(LOGGER_VERBOSE, LOGGER_C_ES,
		       "ESDM fully seeded with %u bits of entropy\n",
			seed_bits);
		esdm_set_entropy_thresh(requested_bits);
	} else if (!state->esdm_min_seeded) {

		/* DRNG is seeded with at least 128 bits of entropy */
		if (seed_bits >= ESDM_MIN_SEED_ENTROPY_BITS) {
			state->esdm_min_seeded = true;
			logger(LOGGER_VERBOSE, LOGGER_C_ES,
			       "ESDM minimally seeded with %u bits of entropy\n",
				seed_bits);
			esdm_set_entropy_thresh(requested_bits);
			esdm_init_wakeup();

		/* DRNG is seeded with at least ESDM_INIT_ENTROPY_BITS bits */
		} else if (seed_bits >= ESDM_INIT_ENTROPY_BITS) {
			logger(LOGGER_VERBOSE, LOGGER_C_ES,
			       "ESDM initial entropy level %u bits of entropy\n",
				seed_bits);
			esdm_set_entropy_thresh(ESDM_MIN_SEED_ENTROPY_BITS);
		}
	}
}

int esdm_es_mgr_reinitialize(void)
{
	unsigned int i;
	int ret = 0;

	esdm_set_entropy_thresh(esdm_get_seed_entropy_osr(false));

	/* Initialize the entropy sources */
	for_each_esdm_es(i) {
		if (esdm_es[i]->init) {
			logger(LOGGER_DEBUG, LOGGER_C_ES, "Re-initialize ES %s\n",
			       esdm_es[i]->name);
			CKINT_LOG(esdm_es[i]->init(),
				  "Reinitialization of ES %s failed: %d",
				  esdm_es[i]->name, ret);
		}
	}

	esdm_force_fully_seeded();

out:
	return ret;
}

static int esdm_es_mgr_init_es(struct esdm_es_cb *esdm_es_one)
{
	int ret = 0;

	if (esdm_es_one->init) {
		logger(LOGGER_DEBUG, LOGGER_C_ES, "Initialize ES %s\n",
		       esdm_es_one->name);
		CKINT_LOG(esdm_es_one->init(),
			  "Initialization of ES %s failed: %d",
			  esdm_es_one->name, ret);
	}

out:
	return ret;
}

int esdm_es_mgr_initialize(void)
{
	struct seed {
		time_t time;
		unsigned long data[(ESDM_MAX_DIGESTSIZE /
				    sizeof(unsigned long))];
	} seed __aligned(ESDM_KCAPI_ALIGN);
	struct timespec timeval;
	unsigned int i;
	int ret = 0;

	BUILD_BUG_ON(ESDM_MAX_DIGESTSIZE % sizeof(unsigned long));

	logger(LOGGER_VERBOSE, LOGGER_C_ES, "Initialize ES manager\n");

	esdm_set_entropy_thresh(esdm_get_seed_entropy_osr(false));

	/* Initialize the auxiliary pool first */
	CKINT(esdm_es_mgr_init_es(esdm_es[esdm_ext_es_aux]));

	/* Initialize the entropy sources */
	for_each_esdm_es(i) {
		if (i == esdm_ext_es_aux)
			continue;

		CKINT(esdm_es_mgr_init_es(esdm_es[i]));
	}

	seed.time = time(NULL);

	for (i = 0; i < ARRAY_SIZE(seed.data); i++) {
		if (!cpu_es_get(&(seed.data[i]))) {
			clock_gettime(CLOCK_REALTIME, &timeval);
			seed.data[i] = (unsigned long)timeval.tv_nsec;
		}
	}

	esdm_pool_insert_aux((uint8_t *)&seed, sizeof(seed), 0);
	memset_secure(&seed, 0, sizeof(seed));

	esdm_force_fully_seeded_all_drbgs();

out:
	return ret;
}

void esdm_es_mgr_finalize(void)
{
	uint32_t i;

	atomic_set(&esdm_es_mgr_terminate, 1);
	esdm_es_mgr_monitor_wakeup();

	for_each_esdm_es(i) {
		if (esdm_es[i]->fini)
			esdm_es[i]->fini();
	}
}

bool esdm_es_reseed_wanted(void)
{
	/* If the ESDM is not yet available, skip */
	if (!esdm_get_available())
		return false;

	/*
	 * Once all DRNGs are fully seeded, the system-triggered arrival of
	 * entropy will not cause any reseeding any more.
	 */
	if (esdm_state.all_online_nodes_seeded)
		return false;

	/* Only trigger the DRNG reseed if we have collected entropy. */
	if (esdm_avail_entropy() <
	    atomic_read_u32(&esdm_state.boot_entropy_thresh))
		return false;

	return true;
}

/* Interface requesting a reseed of the DRNG */
void esdm_es_add_entropy(void)
{
	if (!esdm_es_reseed_wanted())
		return;

	/* Ensure that the seeding only occurs once at any given time. */
	if (!esdm_pool_trylock())
		return;

	/* Seed the DRNG with any available noise. */
	esdm_drng_seed_work();
}

/* Fill the seed buffer with data from the noise sources */
void esdm_fill_seed_buffer(struct entropy_buf *eb, uint32_t requested_bits,
			   bool force)
{
	struct esdm_state *state = &esdm_state;
	uint32_t i, req_ent = esdm_sp80090c_compliant() ?
			  esdm_security_strength() : ESDM_MIN_SEED_ENTROPY_BITS;

	/* Guarantee that requested bits is a multiple of bytes */
	BUILD_BUG_ON(ESDM_DRNG_SECURITY_STRENGTH_BITS % 8);

	/* always reseed the DRNG with the current time stamp */
	eb->now = time(NULL);

	/*
	 * Require at least 128 bits of entropy for any reseed. If the ESDM is
	 * operated SP800-90C compliant we want to comply with SP800-90A section
	 * 9.2 mandating that DRNG is reseeded with the security strength.
	 */
	if (!force &&
	    state->esdm_fully_seeded && (esdm_avail_entropy() < req_ent)) {
		for_each_esdm_es(i)
			eb->entropy_es[i].e_bits = 0;

		goto wakeup;
	}

	/* Concatenate the output of the entropy sources. */
	for_each_esdm_es(i) {
		esdm_es[i]->get_ent(&eb->entropy_es[i], requested_bits,
				    state->esdm_fully_seeded);
	}

wakeup:
	esdm_writer_wakeup();
}
