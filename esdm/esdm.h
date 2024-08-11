/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef _ESDM_H
#define _ESDM_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/**
 * @brief esdm_init() - initialize the ESDM library
 *
 * @return: 0 on success, < 0 on error
 */
int esdm_init(void);

/**
 * @brief esdm_reinit() - reinitialize the ESDM library
 *
 * The reinitialization implies that all parts re-initialized like the entropy
 * sources or the configuration but without loosing any state or entropy.
 *
 * It is intended to re-initialize the ESDM after configuration changes or
 * entropy source changes, i.e. after esdm_init() was run.
 *
 * It MUST NOT be run concurrently with esdm_init().
 *
 * @return: 0 on success, < 0 on error
 */
int esdm_reinit(void);

/**
 * @brief esdm_init_monitor() - initialize ES monitor
 *
 * This call is intended to be invoked from a thread to monitor the ES
 * for arrival of new entropy when not yet all DRNGs are initialized.
 * Yet, it is also permissible to call it in the current thread if one
 * wants to synchronously wait until all DRNGs are initialized.
 *
 * @param [in] priv_init_completion Optional function pointer that is called
 *				    when privileged initialization is complete
 *
 * @return: 0 on success, < 0 on error
 */
int esdm_init_monitor(void (*priv_init_completion)(void));

/**
 * @brief esdm_fini() - finalize the ESDM library and release all resources
 */
void esdm_fini(void);

/**
 * @brief esdm_get_random_bytes() - Provider of cryptographic strong random
 * numbers without a guarantee of the ESDM being properly seeded
 *
 * It provides access to the full functionality of ESDM including the
 * switchable DRNG support, that may support other DRNGs such as the SP800-90A
 * DRBG.
 *
 * @buf: buffer to store the random bytes
 * @nbytes: size of the buffer
 */
ssize_t esdm_get_random_bytes(uint8_t *buf, size_t nbytes);

/**
 * @brief esdm_get_random_bytes_full() - Provider of cryptographic strong
 * random numbers from a fully initialized ESDM.
 *
 * This function will always return random numbers from a fully seeded and
 * fully initialized ESDM.
 *
 * It provides access to the full functionality of ESDM including the
 * switchable DRNG support, that may support other DRNGs such as the SP800-90A
 * DRBG.
 *
 * @buf: buffer to store the random bytes
 * @nbytes: size of the buffer
 *
 * @return: positive number indicates amount of generated bytes, < 0 on error
 */
ssize_t esdm_get_random_bytes_full(uint8_t *buf, size_t nbytes);

/**
 * @brief esdm_get_random_bytes_full_timeout - Provider of cryptographic strong
 * random numbers from a fully initialized ESDM.
 *
 * This function will always return random numbers from a fully seeded and
 * fully initialized ESDM.
 *
 * It provides access to the full functionality of ESDM including the
 * switchable DRNG support, that may support other DRNGs such as the SP800-90A
 * DRBG.
 *
 * @param [out] buf buffer to store the random bytes
 * @param [in] nbytes size of the buffer
 * @param [in] ts maximum timeout after which the waiting will be stopped
 *
 * @return: positive number indicates amount of generated bytes, < 0 on error,
 * -ETIMEDOUT on timeout
 */
ssize_t esdm_get_random_bytes_full_timeout(uint8_t *buf, size_t nbytes,
					   struct timespec *ts);

/**
 * @brief see esdm_get_random_bytes_full except that in case of blocking,
 * it returns -EAGAIN.
 */
ssize_t esdm_get_random_bytes_full_noblock(uint8_t *buf, size_t nbytes);

/**
 * @brief esdm_get_random_bytes_min() - Provider of cryptographic strong
 * random numbers from at least a minimally seeded ESDM, which is not
 * necessarily fully initialized yet (e.g. SP800-90C oversampling applied in
 * FIPS mode is not applied yet).
 *
 * It provides access to the full functionality of ESDM including the
 * switchable DRNG support, that may support other DRNGs such as the SP800-90A
 * DRBG.
 *
 * @buf: buffer to store the random bytes
 * @nbytes: size of the buffer
 *
 * @return: positive number indicates amount of generated bytes, < 0 on error
 */
ssize_t esdm_get_random_bytes_min(uint8_t *buf, size_t nbytes);

/**
 * @brief see esdm_get_random_bytes_min except that in case of blocking,
 * it returns -EAGAIN.
 */
ssize_t esdm_get_random_bytes_min_noblock(uint8_t *buf, size_t nbytes);

/**
 * @brief esdm_get_random_bytes_pr() - Provider of cryptographic strong
 * random numbers from a fully initialized ESDM and requiring a reseed
 * from the entropy sources before.
 *
 * This function will always return random numbers from a fully seeded and
 * fully initialized ESDM.
 *
 * This call only returns no more data than entropy was pulled from the
 * entropy sources. Thus, it is likely that this call returns less data
 * than requested by the caller. Also, the caller MUST be prepared that this
 * call returns 0 bytes, i.e. it did not generate data.
 *
 * @buf: buffer to store the random bytes
 * @nbytes: size of the buffer
 *
 * @return: positive number indicates amount of generated bytes, < 0 on error
 */
ssize_t esdm_get_random_bytes_pr(uint8_t *buf, size_t nbytes);

/**
 * @brief see esdm_get_random_bytes_pr except that in case of blocking,
 * it returns -EAGAIN.
 */
ssize_t esdm_get_random_bytes_pr_noblock(uint8_t *buf, size_t nbytes);

enum esdm_get_seed_flags {
	ESDM_GET_SEED_NONBLOCK = 0x0001, /**< Do not block the call */
	ESDM_GET_SEED_FULLY_SEEDED = 0x0002, /**< DRNG is fully seeded */
};

/**
 * @brief esdm_get_seed() - Fill buffer with data from entropy sources
 *
 * This call allows accessing the entropy sources directly and fill the buffer
 * with data from all available entropy sources. This filled buffer is
 * identical to the temporary seed buffer used by the ESDM to seed its DRNGs.
 *
 * The call is to allows users to seed their DRNG directly from the entropy
 * sources in case the caller does not want to use the ESDM's DRNGs. This
 * buffer can be directly used to seed the caller's DRNG from.
 *
 * The call blocks as long as one ESDM DRNG is not yet fully seeded. If
 * ESDM_GET_SEED_NONBLOCK is specified, it does not block in this case, but
 * returns with an error.
 *
 * Considering SP800-90C, there is a differentiation between the seeding
 * requirements during instantiating a DRNG and at runtime of the DRNG. When
 * specifying ESDM_GET_SEED_FULLY_SEEDED the caller indicates the DRNG was
 * already fully seeded and the regular amount of entropy is requested.
 * Otherwise, the ESDM will obtain the entropy rate required for initial
 * seeding. The following minimum entropy rates will be obtained:
 *
 * * FIPS mode:
 *	* Initial seeding: 384 bits of entropy
 *	* Runtime seeding: 256 bits of entropy
 * * Non-FIPS mode:
 *	* 128 bits of entropy in any case
 *
 * Albeit these are minimum entropy rates, the ESDM tries to request the
 * given amount of entropy from each entropy source individually. If the
 * minimum amount of entropy cannot be obtained collectively by all entropy
 * sources, the ESDM will not fill the buffer.
 *
 * Hint: if you do not want to use the ESDM's DRNGs in general, you may want
 * to consider to reduce the number of DRNGs to only one to reduce the pressure
 * on the entropy sources as all DRNGs are always seeded from the entropy
 * sources.
 *
 * The return data in @param buf is structurally equivalent to the following
 * definition:
 *
 * struct {
 *	uint64_t seedlen;
 *	uint64_t entropy_rate;
 *	struct entropy_buf seed;
 * } __attribute((__packed__));
 *
 * As struct entropy_buf is not known outsize of the ESDM, the ESDM fills
 * seedlen first with the size of struct entropy_buf. If the caller-provided
 * buffer @param buf is smaller than uint64_t, then -EINVAL is returned
 * and @param buf is not touched. If it is uint64_t or larger but smaller
 * than the size of the structure above, -EMSGSIZE is returned and seedlen
 * is filled with the size of the buffer. Finally, if @param buf is large
 * enough to hold all data, it is filled with the seed data and the seedlen
 * is set to sizeof(struct entropy_buf). The entropy rate is returned with
 * the variable entropy_rate and provides the value in bits.
 *
 * The seed buffer is the data that should be handed to the caller's DRNG as
 * seed data.
 *
 * @param [out] buf Buffer to be filled with data from the entropy sources -
 *		    note, the buffer is marked as uint64_t to ensure it is
 *		    aligned to 64 bits.
 * @param [in] nbytes Size of the buffer allocated by the caller - this value
 *		      provides size of @param buf in bytes.
 * @param [in] flags Flags field to adjust the behavior
 *
 * @return -EINVAL or -EMSGSIZE indicating the buffer is too small, -EAGAIN when
 *	   the call would block, but NONBLOCK is specified, > 0 the size of
 *	   the filled buffer.
 */
ssize_t esdm_get_seed(uint64_t *buf, size_t nbytes,
		      enum esdm_get_seed_flags flags);

/**
 * @brief esdm_status() - Get status information on ESDM
 *
 * @param [out] buf Buffer to be filled with status information
 * @param [in] buflen Length of buffer
 */
void esdm_status(char *buf, size_t buflen);

/**
 * @brief esdm_status_machine() - Get status information on ESDM
 *
 * @param [out] status Buffer to be filled with status information
 */
struct esdm_status_st {
	unsigned int es_irq_enabled : 1;
	unsigned int es_sched_enabled : 2;
};
void esdm_status_machine(struct esdm_status_st *status);

/**
 * @brief esdm_version() - Get ESDM version information
 *
 * @param [out] buf Buffer to be filled with status information
 * @param [in] buflen Length of buffer
 */
void esdm_version(char *buf, size_t buflen);

/**
 * @brief Insert entropy into the auxiliary pool
 *
 * External entities are allowed to insert entropy into the auxiliary pool.
 * The auxiliary pool therefore is a separate entropy source.
 *
 * NOTE: When wanting to operate the ESDM SP800-90C compliant, make sure that
 * you only insert data from an SP800-90B entropy source where entropy_bits
 * is set to a value > 0. When the value is 0, the data does not need to be
 * provided by an SP800-90B entropy source.
 *
 * @param [in] inbuf Buffer with the data to be inserted into the aux pool.
 * @param [in] inbuflen Size of the buffer.
 * @param [in] entropy_bits Amount of bits to be credited for the inserted
 *			    data.
 *
 * @return: 0 on success, < 0 on error
 */
int esdm_pool_insert_aux(const uint8_t *inbuf, size_t inbuflen,
			 uint32_t entropy_bits);

/**
 * @brief Obtain the available entropy in all ESDM entropy pools in bits
 *
 * @return available entropy in bits
 */
uint32_t esdm_avail_entropy(void);

/**
 * @brief Obtain the available entropy in the aux ESDM entropy pool in bits
 *
 * @return available entropy in bits
 */
uint32_t esdm_avail_entropy_aux(void);

/**
 * @brief Obtain the poolsize of the aux ESDM entropy pool in bits
 *
 * @return poolsize in bits
 */
uint32_t esdm_avail_poolsize_aux(void);

/**
 * @brief Obtain the available entropy of the auxiliary pool in bits
 *
 * @return available entropy in bits
 */
uint32_t esdm_get_aux_ent(void);

/**
 * @brief Obtain the size of the message digest of the conditioner used by the
 *	  ESDM
 *
 * @return message digest size in bits
 */
uint32_t esdm_get_digestsize(void);

/**
 * @brief Set the entropy level of the auxiliary pool
 *
 * @param [in] entropy_bits Entropy rate in bits
 */
void esdm_pool_set_entropy(uint32_t entropy_bits);

/**
 * @brief Force a reseed of all DRNGs in the ESDM
 *
 * The call only sets a flag for the reseed, the actual reseed is performed
 * the next time the DRNG is requested to deliver random data.
 */
void esdm_drng_force_reseed(void);

/**
 * @brief Indicator whether the ESDM is operational
 *
 * The ESDM is operational if at least one DRNG is fully seeded with the amount
 * of entropy equal to the DRNG security strength (regular mode) or with the
 * amount of entropy stipulated by SP800-90C (FIPS mode).
 *
 * @return 1 if operational, 0 if not operational
 */
int esdm_state_operational(void);

/**
 * @brief Indicator whether ESDM operates SP800-90C compliant
 *
 * @return 1 if SP800-90C compliant, 0 if not SP800-90C compliant
 */
int esdm_sp80090c_compliant(void);

/**
 * @brief Indicator whether ESDM operates NTG.1 compliant
 *
 * @return 1 if NTG.1 compliant, 0 if not NTG.1 compliant
 */
int esdm_ntg1_compliant(void);

/**
 * @brief Indicator whether ESDM operates NTG.1 compliant according to
 * AIS 20/31 from 2022
 *
 * @return 1 if NTG.1 compliant, 0 if not NTG.1 compliant
 */
int esdm_ntg1_2022_compliant(void);

/**
 * @brief Indicator whether at least one DRNG is fully seeded
 *
 * @return 1 if fully seeded, 0 if not fully seeded
 */
int esdm_state_fully_seeded(void);

/**
 * @brief Get write wakeup in bits
 *
 * @return write wakeup in bits
 */
uint32_t esdm_get_write_wakeup_bits(void);

/**
 * @brief Set write wakeup in bits
 */
void esdm_set_write_wakeup_bits(uint32_t val);

/**
 * @brief Get maximum reseed interval in seconds
 *
 * @return maximum reseed interval in seconds
 */
uint32_t esdm_get_reseed_max_time(void);

/**
 * @brief Set maximum reseed interval in seconds
 */
void esdm_set_reseed_max_time(uint32_t seconds);

#endif /* _ESDM_H */
