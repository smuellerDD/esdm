/* xoshiro256++ PRNG
 *
 * based on code from: https://prng.di.unimi.it/xoshiro256plusplus.c
 *
 * Copyright (C) 2025, Markus Theil <theil.markus@gmail.com>
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

#ifndef XOSHIRO_H
#define XOSHIRO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct xoshiro_state {
	uint64_t s[4];
};

/**
 * @brief Seed the generator state from the operating system
 * @param [out] state generator state to seed
 * @return 0 on success, < 0 on error (negative errno). The state is left all
 * 	zero on error, which the caller must not generate from.
 */
int xoshiro_init(struct xoshiro_state *state);

/**
 * @brief Draw the next number of the sequence
 * @param [in,out] state seeded generator state
 * @return number equidistributed over the full 64 bit range
 */
uint64_t xoshiro_generate(struct xoshiro_state *state);

/**
 * @brief Draw the next number of the sequence, mapped into an interval
 * @param [in,out] state seeded generator state
 * @param [in] lower lower bound of the interval, included
 * @param [in] upper upper bound of the interval, excluded
 * @return number equidistributed over [lower, upper), or @p lower if the
 * 	interval holds no more than one value
 */
uint64_t xoshiro_generate_interval(struct xoshiro_state *state, uint64_t lower,
				   uint64_t upper);

#ifdef __cplusplus
}
#endif

#endif /* XOSHIRO_H */
