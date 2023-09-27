/* ESDM Runtime configuration facility
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "build_bug_on.h"
#include "config.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_irq.h"
#include "esdm_es_mgr.h"
#include "fips.h"
#include "helper.h"
#include "logger.h"
#include "visibility.h"

struct esdm_config {
	uint32_t esdm_es_cpu_entropy_rate_bits;
	uint32_t esdm_es_jent_entropy_rate_bits;
	uint32_t esdm_es_irq_entropy_rate_bits;
	uint32_t esdm_es_krng_entropy_rate_bits;
	uint32_t esdm_es_sched_entropy_rate_bits;
	uint32_t esdm_es_hwrand_entropy_rate_bits;
	uint32_t esdm_es_jent_kernel_entropy_rate_bits;
	uint32_t esdm_drng_max_wo_reseed;
	uint32_t esdm_max_nodes;
	enum esdm_config_force_fips force_fips;

	bool esdm_es_irq_retry;
	bool esdm_es_sched_retry;
	bool esdm_jent_entropy_async_enable;
};

static struct esdm_config esdm_config = {
	/*
	 * Estimated entropy of data is a 32th of
	 * ESDM_DRNG_SECURITY_STRENGTH_BITS. As we have no ability to review the
	 * implementation of those noise sources, it is prudent to have a
	 * conservative estimate here.
	 */
	.esdm_es_cpu_entropy_rate_bits = ESDM_CPU_ENTROPY_RATE,

	/*
	 * Estimated entropy of data is a 16th of
	 * ESDM_DRNG_SECURITY_STRENGTH_BITS. Albeit a full entropy assessment
	 * is provided for the noise source indicating that it provides high
	 * entropy rates and considering that it deactivates when it detects
	 * insufficient hardware, the chosen under estimation of entropy is
	 * considered to be acceptable to all reviewers.
	 */
	.esdm_es_jent_entropy_rate_bits = ESDM_JENT_ENTROPY_RATE,

	/*
	 * See documentation of ESDM_IRQ_ENTROPY_RATE
	 */
	.esdm_es_irq_entropy_rate_bits = ESDM_IRQ_ENTROPY_RATE,

	/*
	 * See documentation of ESDM_KERNEL_RNG_ENTROPY_RATE
	 */
	.esdm_es_krng_entropy_rate_bits = ESDM_KERNEL_RNG_ENTROPY_RATE,

	/*
	 * See documentation of ESDM_SCHED_ENTROPY_RATE
	 */
	.esdm_es_sched_entropy_rate_bits = ESDM_SCHED_ENTROPY_RATE,

	/*
	 * See documentation of ESDM_HWRAND_ENTROPY_RATE
	 */
	.esdm_es_hwrand_entropy_rate_bits = ESDM_HWRAND_ENTROPY_RATE,

	/*
	 * See documentation of ESDM_JENT_KERNEL_ENTROPY_RATE
	*/
	.esdm_es_jent_kernel_entropy_rate_bits = ESDM_JENT_KERNEL_ENTROPY_RATE,

	/*
	 * See documentation of ESDM_DRNG_MAX_WITHOUT_RESEED.
	 */
	.esdm_drng_max_wo_reseed = ESDM_DRNG_MAX_WITHOUT_RESEED,

	/*
	 * Upper limit of DRNG nodes
	 */
	.esdm_max_nodes = 0xffffffff,

	/* Shall the FIPS mode be forcefully set/unset? */
	.force_fips = esdm_config_force_fips_unset,

	/* Retry to access the IRQ ES during initialization */
	.esdm_es_irq_retry = false,

	/* Retry to access the Sched ES during initialization */
	.esdm_es_sched_retry = false,

	/* Enable the Jitter RNG buffer filling */
	.esdm_jent_entropy_async_enable = true,
};

static uint32_t esdm_config_entropy_rate_max(uint32_t val)
{
	return min_uint32(ESDM_DRNG_SECURITY_STRENGTH_BITS, val);
}

DSO_PUBLIC
uint32_t esdm_config_es_cpu_entropy_rate(void)
{
	return esdm_config.esdm_es_cpu_entropy_rate_bits;
}

DSO_PUBLIC
void esdm_config_es_cpu_entropy_rate_set(uint32_t ent)
{
	esdm_config.esdm_es_cpu_entropy_rate_bits =
		esdm_config_entropy_rate_max(ent);
	esdm_es_add_entropy();
}

DSO_PUBLIC
uint32_t esdm_config_es_jent_entropy_rate(void)
{
	return esdm_config.esdm_es_jent_entropy_rate_bits;
}

DSO_PUBLIC
void esdm_config_es_jent_entropy_rate_set(uint32_t ent)
{
	esdm_config.esdm_es_jent_entropy_rate_bits =
		esdm_config_entropy_rate_max(ent);
	esdm_es_add_entropy();
}

DSO_PUBLIC
uint32_t esdm_config_es_jent_async_enabled(void)
{
	return esdm_config.esdm_jent_entropy_async_enable;
}

DSO_PUBLIC
void esdm_config_es_jent_async_enabled_set(int setting)
{
	esdm_config.esdm_jent_entropy_async_enable = !!setting;
}

DSO_PUBLIC
uint32_t esdm_config_es_irq_entropy_rate(void)
{
	return esdm_config.esdm_es_irq_entropy_rate_bits;
}

DSO_PUBLIC
void esdm_config_es_irq_entropy_rate_set(uint32_t ent)
{
	uint32_t val = esdm_config_entropy_rate_max(ent);

	/*
	 * Due to dependencies between both entropy sources, it is not
	 * permissible to have both set to non-zero values.
	 */
	if (val > 0)
		esdm_config_es_sched_entropy_rate_set(0);

	esdm_config.esdm_es_irq_entropy_rate_bits = val;
	esdm_es_add_entropy();
}

DSO_PUBLIC
uint32_t esdm_config_es_irq_retry(void)
{
	return esdm_config.esdm_es_irq_retry;
}

DSO_PUBLIC
void esdm_config_es_irq_retry_set(int setting)
{
	esdm_config.esdm_es_irq_retry = !!setting;
}

DSO_PUBLIC
uint32_t esdm_config_es_krng_entropy_rate(void)
{
	return esdm_config.esdm_es_krng_entropy_rate_bits;
}

DSO_PUBLIC
void esdm_config_es_krng_entropy_rate_set(uint32_t ent)
{
	if (esdm_irq_enabled())
		ent = min_uint32(ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY, ent);

	esdm_config.esdm_es_krng_entropy_rate_bits =
		esdm_config_entropy_rate_max(ent);
	esdm_es_add_entropy();
}

DSO_PUBLIC
uint32_t esdm_config_es_sched_entropy_rate(void)
{
	return esdm_config.esdm_es_sched_entropy_rate_bits;
}

DSO_PUBLIC
void esdm_config_es_sched_entropy_rate_set(uint32_t ent)
{
	uint32_t val = esdm_config_entropy_rate_max(ent);

	/*
	 * Due to dependencies between both entropy sources, it is not
	 * permissible to have both set to non-zero values.
	 */
	if (val > 0)
		esdm_config_es_irq_entropy_rate_set(0);

	esdm_config.esdm_es_sched_entropy_rate_bits = val;
	esdm_es_add_entropy();
}

DSO_PUBLIC
uint32_t esdm_config_es_sched_retry(void)
{
	return esdm_config.esdm_es_sched_retry;
}

DSO_PUBLIC
void esdm_config_es_sched_retry_set(int setting)
{
	esdm_config.esdm_es_sched_retry = !!setting;
}

DSO_PUBLIC
uint32_t esdm_config_es_hwrand_entropy_rate(void)
{
	return esdm_config.esdm_es_hwrand_entropy_rate_bits;
}

DSO_PUBLIC
void esdm_config_es_hwrand_entropy_rate_set(uint32_t ent)
{
	uint32_t val = esdm_config_entropy_rate_max(ent);

	esdm_config.esdm_es_hwrand_entropy_rate_bits = val;
	esdm_es_add_entropy();
}

DSO_PUBLIC
uint32_t esdm_config_es_jent_kernel_entropy_rate(void)
{
	return esdm_config.esdm_es_jent_kernel_entropy_rate_bits;
}

DSO_PUBLIC
void esdm_config_es_jent_kernel_entropy_rate_set(uint32_t ent)
{
	uint32_t val = esdm_config_entropy_rate_max(ent);

	esdm_config.esdm_es_jent_kernel_entropy_rate_bits = val;
	esdm_es_add_entropy();
}

DSO_PUBLIC
uint32_t esdm_config_drng_max_wo_reseed(void)
{
	/* If DRNG operated without proper reseed for too long, block ESDM */
	BUILD_BUG_ON(ESDM_DRNG_MAX_WITHOUT_RESEED < ESDM_DRNG_RESEED_THRESH);
	return esdm_config.esdm_drng_max_wo_reseed;
}

DSO_PUBLIC
uint32_t esdm_config_max_nodes(void)
{
	return esdm_config.esdm_max_nodes;
}

#ifdef ESDM_TESTMODE
void esdm_config_drng_max_wo_reseed_set(uint32_t val)
{
	esdm_config.esdm_drng_max_wo_reseed = val;
}

void esdm_config_max_nodes_set(uint32_t val)
{
	esdm_config.esdm_max_nodes = val;
}
#endif

/******************************************************************************/

DSO_PUBLIC
void esdm_config_force_fips_set(enum esdm_config_force_fips val)
{
	esdm_config.force_fips = val;
}

DSO_PUBLIC
int esdm_config_fips_enabled(void)
{
	/* FIPS 140 mode can only be set with FIPS-140 compile time option */
#ifdef ESDM_FIPS140
	if (esdm_config.force_fips == esdm_config_force_fips_unset)
		return fips_enabled();
	return (esdm_config.force_fips >= esdm_config_force_fips_enabled);
#else
	return false;
#endif
}

DSO_PUBLIC
int esdm_config_sp80090c_compliant(void)
{
	/* SP800-90C mode can only be set with SP800-90C compile-time option */
#ifdef ESDM_OVERSAMPLE_ENTROPY_SOURCES
	if (esdm_config.force_fips == esdm_config_force_fips_unset)
		return fips_enabled();

	/* SP800-90C is always enabled if FIPS-140 mode is enabled */
	return (esdm_config.force_fips >= esdm_config_force_sp80090c_enabled);
#else
	return false;
#endif
}

DSO_PUBLIC
uint32_t esdm_config_online_nodes(void)
{
	return min_uint32(esdm_online_nodes(), esdm_config_max_nodes());
}

DSO_PUBLIC
uint32_t esdm_config_curr_node(void)
{
	return esdm_curr_node() % esdm_config_max_nodes();
}

int esdm_config_init(void)
{
	uint32_t complete_entropy_rate = 0;

	/*
	 * Sanity checks - if runtime configuration is added, it must be
	 * above these checks.
	 */
	esdm_config.esdm_es_cpu_entropy_rate_bits =
		esdm_config_entropy_rate_max(
			esdm_config.esdm_es_cpu_entropy_rate_bits);
	complete_entropy_rate += esdm_config.esdm_es_cpu_entropy_rate_bits;
	esdm_config.esdm_es_jent_entropy_rate_bits =
		esdm_config_entropy_rate_max(
			esdm_config.esdm_es_jent_entropy_rate_bits);
	complete_entropy_rate += esdm_config.esdm_es_jent_entropy_rate_bits;
	esdm_config.esdm_es_krng_entropy_rate_bits =
		esdm_config_entropy_rate_max(
			esdm_config.esdm_es_krng_entropy_rate_bits);
	complete_entropy_rate += esdm_config.esdm_es_krng_entropy_rate_bits;
	esdm_config.esdm_es_sched_entropy_rate_bits =
		esdm_config_entropy_rate_max(
			esdm_config.esdm_es_sched_entropy_rate_bits);
	complete_entropy_rate += esdm_config.esdm_es_sched_entropy_rate_bits;
	esdm_config.esdm_es_irq_entropy_rate_bits =
		esdm_config_entropy_rate_max(
			esdm_config.esdm_es_irq_entropy_rate_bits);
	complete_entropy_rate += esdm_config.esdm_es_irq_entropy_rate_bits;
	esdm_config.esdm_es_hwrand_entropy_rate_bits =
		esdm_config_entropy_rate_max(
			esdm_config.esdm_es_hwrand_entropy_rate_bits);
	complete_entropy_rate += esdm_config.esdm_es_hwrand_entropy_rate_bits;

	if (!complete_entropy_rate) {
		logger_status(
			LOGGER_C_ES,
			"All entropy sources managed by ESDM collectively cannot satisfy seed requirement - ensure to use an external entropy provider to fill up auxiliary pool!\n");
	}

	return 0;
}

int esdm_config_reinit(void)
{
	return esdm_config_init();
}
