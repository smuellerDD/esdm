/*
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

#ifndef _ESDM_CONFIG
#define _ESDM_CONFIG

#include <stdint.h>

/**
 * @brief CPU ES configuration: set the entropy rate
 *
 * NOTE: The ESDM ensures that the entropy rate cannot be set to a value larger
 *	 than the security strength of the the applied DRNG.
 *
 * @param [in] ent Entropy rate in bits.
 */
void esdm_config_es_cpu_entropy_rate_set(uint32_t ent);

/**
 * @brief CPU ES configuration: get the entropy rate
 *
 * @return Entropy rate in bits
 */
uint32_t esdm_config_es_cpu_entropy_rate(void);

/**
 * @brief JENT ES configuration: set the entropy rate
 *
 * NOTE: The ESDM ensures that the entropy rate cannot be set to a value larger
 *	 than the security strength of the the applied DRNG.
 *
 * @param [in] ent Entropy rate in bits.
 */
void esdm_config_es_jent_entropy_rate_set(uint32_t ent);

/**
 * @brief JENT ES configuration: get the entropy rate
 *
 * @return Entropy rate in bits
 */
uint32_t esdm_config_es_jent_entropy_rate(void);

/**
 * @brief Interrupt ES configuration: set the entropy rate
 *
 * NOTE: The ESDM ensures that the entropy rate cannot be set to a value larger
 *	 than the security strength of the the applied DRNG.
 *
 * @param [in] ent Entropy rate in bits.
 */
void esdm_config_es_irq_entropy_rate_set(uint32_t ent);

/**
 * @brief Interrupt ES configuration: get the entropy rate
 *
 * @return Entropy rate in bits
 */
uint32_t esdm_config_es_irq_entropy_rate(void);

/**
 * @brief Kernel RNG ES configuration: set the entropy rate
 *
 * NOTE: The ESDM ensures that the entropy rate cannot be set to a value larger
 *	 than the security strength of the the applied DRNG.
 *
 * NOTE: The ESDM forces the entropy rate to 0 irrespective of this setting
 *	 in FIPS mode because the Linux kernel /dev/random entropy source
 *	 is known to be not SP800-90B compliant.
 *
 * NOTE: The ESDM forces the entropy rate to 0 irrespective of this setting if
 *	 the scheduler ES is enabled. This is due to the fact that both ES
 *	 potentially have a dependency.
 *
 * @param [in] ent Entropy rate in bits.
 */
void esdm_config_es_krng_entropy_rate_set(uint32_t ent);

/**
 * @brief Kernel RNG ES configuration: get the entropy rate
 *
 * NOTE: This call returns the configured entropy rate and not the effective
 *	 entropy rate as documented for esdm_config_es_krng_entropy_rate_set().
 *
 * @return Entropy rate in bits
 */
uint32_t esdm_config_es_krng_entropy_rate(void);

/**
 * @brief Scheduler ES configuration: set the entropy rate
 *
 * NOTE: The ESDM ensures that the entropy rate cannot be set to a value larger
 *	 than the security strength of the the applied DRNG.
 *
 * @param [in] ent Entropy rate in bits.
 */
void esdm_config_es_sched_entropy_rate_set(uint32_t ent);

/**
 * @brief Scheduler ES configuration: get the entropy rate
 *
 * @return Entropy rate in bits
 */
uint32_t esdm_config_es_sched_entropy_rate(void);

/**
 * @brief /dev/hwrng ES configuration: set the entropy rate
 *
 * NOTE: The ESDM ensures that the entropy rate cannot be set to a value larger
 *	 than the security strength of the the applied DRNG.
 *
 * @param [in] ent Entropy rate in bits.
 */
void esdm_config_es_hwrand_entropy_rate_set(uint32_t ent);

/**
 * @brief /dev/hwrng ES configuration: get the entropy rate
 *
 * @return Entropy rate in bits
 */
uint32_t esdm_config_es_hwrand_entropy_rate(void);

/**
 * @brief DRNG Manager configuration: get maximum value without successful
 *	  reseed
 *
 * If the DRNG is reseeded but insufficient entropy is present, the DRNG
 * continues to operate. However, if the reseed with insufficient entropy
 * persists up to this threshold, the DRNG is marked as unseeded and not
 * further used until it is seeded with full entropy again.
 *
 * @return Number of DRNG reseed triggers which are allowed to not deliver
 *	   an full entropy.
 */
uint32_t esdm_config_drng_max_wo_reseed(void);

/**
 * @brief DRNG Manager configuration: get number of DRNG instances
 *
 * The ESDM operates multiple DRNG instances independently of each other.
 *
 * @return Number of DRNG instances.
 */
uint32_t esdm_config_max_nodes(void);

/* FIPS mode enforcement */
enum esdm_config_force_fips {
	/** Default: no FIPS enforcement is set, ESDM checks environment */
	esdm_config_force_fips_unset,
	/** Force FIPS mode irrespective of environment */
	esdm_config_force_fips_disabled,
	/** Disable FIPS mode irrespective of environment */
	esdm_config_force_fips_enabled,
};

/**
 * @brief DRNG Manager configuration:Set the effective FIPS mode
 */

void esdm_config_force_fips_set(enum esdm_config_force_fips val);

/**
 * @brief DRNG Manager configuration: Indicator whether FIPS mode is enabled
 *
 * @return 1 if FIPS mode is enabled, 0 if FIPS mode is disabled
 */
int esdm_config_fips_enabled(void);

/**
 * @brief DRNG Manager configuration: Get number of active nodes
 *
 * The number of nodes indicates the maximum number of DRNG instances the ESDM
 * could instantiate.
 *
 * @return Number of available nodes.
 */
uint32_t esdm_config_online_nodes(void);

/**
 * @brief DRNG Manager configuration: Get current DRNG instance
 *
 * This call returns the DRNG instance number that would serve a request
 * for random numbers.
 *
 * @return Current DRNG instance.
 */
uint32_t esdm_config_curr_node(void);

int esdm_config_init(void);
int esdm_config_reinit(void);

#endif /* _ESDM_CONFIG */
