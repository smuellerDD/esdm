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

/*
 * Written in 2019 by David Blackman and Sebastiano Vigna (vigna@acm.org)
 *
 * To the extent possible under law, the author has dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "xoshiro_prng.h"
#include "os_random.h"
#include "rotate.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

/* This is xoshiro256++ 1.0, one of our all-purpose, rock-solid generators. */

int xoshiro_init(struct xoshiro_state *state)
{
	static const uint64_t invalid_buf[4] = { 0, 0, 0, 0 };
	int ret;

	assert(state != NULL);

	/*
	 * The all-zero state is the one state the generator cannot leave, so it
	 * is drawn again.
	 */
	do {
		ret = esdm_os_random((uint8_t *)state->s, sizeof(state->s));
		if (ret) {
			memset(state->s, 0, sizeof(state->s));
			return ret;
		}
	} while (memcmp(invalid_buf, state->s, sizeof(invalid_buf)) == 0);

	return 0;
}

uint64_t xoshiro_generate(struct xoshiro_state *state)
{
	assert(state != NULL);

	const uint64_t result =
		rol64(state->s[0] + state->s[3], 23) + state->s[0];

	const uint64_t t = state->s[1] << 17;

	state->s[2] ^= state->s[0];
	state->s[3] ^= state->s[1];
	state->s[1] ^= state->s[2];
	state->s[0] ^= state->s[3];

	state->s[2] ^= t;

	state->s[3] = rol64(state->s[3], 45);

	return result;
}

uint64_t xoshiro_generate_interval(struct xoshiro_state *state, uint64_t lower,
				   uint64_t upper)
{
	uint64_t span, reject, val;

	assert(state != NULL);

	/* An interval that holds one value needs no draw at all */
	if (upper <= lower + 1)
		return lower;

	span = upper - lower;

	/*
	 * The remainder of a draw alone is not equidistributed: 2^64 is not a
	 * multiple of the span, so the first (2^64 mod span) values of the
	 * interval would be reached by one draw more than the rest.
	 */
	reject = ((uint64_t)0 - span) % span;

	do {
		val = xoshiro_generate(state);
	} while (val < reject);

	return lower + val % span;
}
