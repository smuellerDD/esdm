/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef _ESDM_SELFTEST_H
#define _ESDM_SELFTEST_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Outcome of a self test. The crypto implementations and the entropy sources
 * are tracked separately - see esdm_selftest_es_state() for why.
 */
enum esdm_selftest_state {
	esdm_selftest_undone = 0,
	esdm_selftest_passed,
	esdm_selftest_failed,
};

/**
 * @brief Run a self test pass
 * @return 0 if every test passed, the error of the crypto self test if that
 * 	failed, the error of the first failing entropy source otherwise
 */
int esdm_selftest_run(void);

/**
 * @brief Run the self tests of the crypto implementations
 * @return 0 if both passed, < 0 otherwise
 */
int esdm_selftest_crypto(void);

/**
 * @brief State of the self tests of the crypto implementations
 */
enum esdm_selftest_state esdm_selftest_crypto_state(void);

/**
 * @brief May the ESDM hand out random bits?
 */
bool esdm_selftest_crypto_passed(void);

/**
 * @brief Name of the crypto self test state, for reporting
 */
const char *esdm_selftest_crypto_state_name(void);

/**
 * @brief Run the self test of every entropy source
 * @return 0 if every source that has a self test passed it, the error of the
 * 	first failing source otherwise
 */
int esdm_selftest_es(void);

/**
 * @brief Outcome of the last pass over the entropy source self tests
 */
enum esdm_selftest_state esdm_selftest_es_state(void);

/**
 * @brief Name of the state above, for reporting
 */
const char *esdm_selftest_es_state_name(void);

/**
 * @brief Number of entropy sources the last pass tested
 */
uint32_t esdm_selftest_es_sources(void);

/**
 * @brief Number of entropy sources that failed in the last pass
 */
uint32_t esdm_selftest_es_failures(void);

/**
 * @brief Put the periodic self test worker on duty
 * @return true if a worker is on duty afterwards
 */
bool esdm_selftest_periodic_start(void);

/**
 * @brief Is the periodic self test worker on duty?
 */
bool esdm_selftest_periodic_running(void);

/**
 * @brief Number of self test passes that completed
 */
long long esdm_selftest_passes(void);

/**
 * @brief Seconds between two runs of the periodic self tests
 */
uint32_t esdm_selftest_periodic_interval(void);

/**
 * @brief Ask the periodic self test worker to leave
 */
void esdm_selftest_periodic_stop(void);

#ifdef ESDM_TESTMODE
/**
 * @brief Record a failed self test - test mode only
 */
void esdm_test_selftest_set_failed(void);
#endif

#endif /* _ESDM_SELFTEST_H */
