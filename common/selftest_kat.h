/* Known answer test comparison used by the crypto self tests
 *
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

#ifndef SELFTEST_KAT_H
#define SELFTEST_KAT_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Longest known answer any self test compares. */
#define ESDM_KAT_MAX_LEN 512

/**
 * @brief Compare a self test result against its known answer
 * @param [in] act Result the implementation produced
 * @param [in] exp Known answer the result is expected to match
 * @param [in] len Length of both buffers in bytes, at most ESDM_KAT_MAX_LEN
 * @return 0 if the result matches the known answer and the modified copy of it
 * 	is detected as different, -EFAULT if either does not hold, -EINVAL if the
 * 	arguments cannot be checked
 */
static inline int esdm_kat_check(const void *act, const void *exp, size_t len)
{
	uint8_t neg[ESDM_KAT_MAX_LEN];

	if (!act || !exp || !len || len > sizeof(neg))
		return -EINVAL;

	/* Positive test: the implementation produced the known answer */
	if (memcmp(act, exp, len))
		return -EFAULT;

	memcpy(neg, exp, len);

	/* Negative test: a known answer off by its first byte is not accepted */
	neg[0] = (uint8_t)(neg[0] ^ 0xff);
	if (!memcmp(act, neg, len))
		return -EFAULT;

	return 0;
}

/**
 * @brief Copy an input of a known answer test and modify its first byte
 * @param [out] out Buffer receiving the modified copy, @len bytes
 * @param [in] in Input of the known answer test
 * @param [in] len Length of both in bytes
 * @return 0 on success, -EINVAL if the arguments cannot be used
 */
static inline int esdm_kat_modify(void *out, const void *in, size_t len)
{
	uint8_t *mod = (uint8_t *)out;

	if (!out || !in || !len)
		return -EINVAL;

	memcpy(out, in, len);
	mod[0] = (uint8_t)(mod[0] ^ 0xff);

	return 0;
}

/**
 * @brief Verify that a result does not match the known answer
 * @param [in] act Result the implementation produced from the modified input
 * @param [in] exp Known answer of the unmodified input
 * @param [in] len Length of both in bytes
 * @return 0 if the two differ, -EFAULT if they do not, -EINVAL if the arguments
 * 	cannot be checked
 */
static inline int esdm_kat_check_differs(const void *act, const void *exp,
					 size_t len)
{
	if (!act || !exp || !len)
		return -EINVAL;

	return memcmp(act, exp, len) ? 0 : -EFAULT;
}

#endif /* SELFTEST_KAT_H */
