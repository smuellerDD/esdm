/*
 * Fuzz harness: the ESDM library API
 *
 * The RPC harnesses next to this file reach the library through the server,
 * which decides what of an input ever gets that far: a request is decoded
 * before a handler sees it, and a handler passes on the few fields its call
 * carries. This one leaves that out and calls the library the way a program
 * linking it does - and that is a surface of its own, as libesdm is used
 * directly by the CUSE daemons, the getrandom server, the OpenSSL provider and
 * anything else built on it.
 *
 * One input is a script: a byte picking a call, then the bytes its arguments
 * are taken from, over and over until the input runs out. So an input is a
 * sequence of API calls rather than a single one, which is what the library
 * sees in practice - the entropy inserted by one call is what the next one
 * generates from, a reseed forced in between changes what the one after it
 * does, and the state the calls share is the point.
 *
 * Every buffer handed to the library sits in front of a guard the harness
 * checks afterwards, and every buffer that comes back as a string has to be
 * terminated inside the length that was given. Those two are what the calls
 * promise their callers, and neither is something a crash would necessarily
 * reveal.
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esdm.h"
#include "esdm_logger.h"
#include "fuzz.h"

/* Largest buffer a call is given. */
#define FUZZ_BUF_MAX 8192

/*
 * The prediction resistance calls collect entropy for every request they
 * serve, which is orders of magnitude slower than the rest - they are asked
 * for little, so an input that reaches them still gets through.
 */
#define FUZZ_PR_MAX 64

/* Bytes of guard behind every buffer, and what they are painted with */
#define FUZZ_GUARD 64
#define FUZZ_GUARD_BYTE 0xa5

/* Calls of an input, so one input cannot run for arbitrarily long */
#define FUZZ_MAX_CALLS 64

/*
 * The buffer every call writes into: the area it is given, then the guard.
 * uint64_t so it is aligned for esdm_get_seed(), which asks for that.
 */
static uint64_t fuzz_area[(FUZZ_BUF_MAX + FUZZ_GUARD) / sizeof(uint64_t)];

/* The input, and how far it has been read */
struct fuzz_input {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

static uint8_t fuzz_u8(struct fuzz_input *in)
{
	return (in->pos < in->len) ? in->data[in->pos++] : 0;
}

static uint32_t fuzz_u32(struct fuzz_input *in)
{
	uint32_t val = 0;
	unsigned int i;

	for (i = 0; i < 4; i++)
		val = (val << 8) | fuzz_u8(in);

	return val;
}

/* A length the harness is willing to hand out, taken from two input bytes */
static size_t fuzz_len(struct fuzz_input *in, size_t max)
{
	size_t val = ((size_t)fuzz_u8(in) << 8) | fuzz_u8(in);

	return (val % (max + 1));
}

/* Hand out the buffer with its guard painted, ready for a call of @len bytes */
static uint8_t *fuzz_buf(size_t len)
{
	uint8_t *buf = (uint8_t *)fuzz_area;

	memset(buf, 0, len);
	memset(buf + len, FUZZ_GUARD_BYTE, FUZZ_GUARD);

	return buf;
}

/* Nothing may be written behind the buffer that was handed out */
static void fuzz_check_guard(const char *call, size_t len)
{
	const uint8_t *buf = (const uint8_t *)fuzz_area;
	unsigned int i;

	for (i = 0; i < FUZZ_GUARD; i++) {
		if (buf[len + i] == FUZZ_GUARD_BYTE)
			continue;

		fprintf(stderr,
			"%s wrote %u byte(s) behind the buffer of %zu it was given\n",
			call, FUZZ_GUARD - i, len);
		abort();
	}
}

/*
 * A call handing back text has to terminate it inside the buffer it was given.
 */
static void fuzz_check_string(const char *call, size_t len, int ret)
{
	const char *buf = (const char *)fuzz_area;
	size_t i;

	fuzz_check_guard(call, len);

	/* Nothing was asked for, so nothing has to come back */
	if (!len)
		return;

	/*
	 * An answer that did not fit is reported rather than written, and the
	 * buffer is then whatever the call got as far as - it is not read as a
	 * string, so it does not have to be one.
	 */
	if (ret < 0)
		return;

	for (i = 0; i < len; i++) {
		if (!buf[i])
			return;
	}

	fprintf(stderr, "%s returned %d with %zu bytes of text and no end\n",
		call, ret, len);
	abort();
}

/* The calls an input can pick from */
enum fuzz_call {
	fuzz_call_get_random_bytes,
	fuzz_call_get_random_bytes_full,
	fuzz_call_get_random_bytes_pr,
	fuzz_call_get_seed,
	fuzz_call_insert_aux,
	fuzz_call_status,
	fuzz_call_status_json,
	fuzz_call_status_drng_json,
	fuzz_call_status_drng_pr_json,
	fuzz_call_version,
	fuzz_call_set_write_wakeup_bits,
	fuzz_call_set_reseed_max_time,
	fuzz_call_pool_set_entropy,
	fuzz_call_force_reseed,
	fuzz_call_query,
	fuzz_calls
};

static void fuzz_one_call(struct fuzz_input *in)
{
	size_t len;
	uint8_t *buf;
	int ret;

	switch ((enum fuzz_call)(fuzz_u8(in) % fuzz_calls)) {
	case fuzz_call_get_random_bytes:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		esdm_get_random_bytes(buf, len);
		fuzz_check_guard("esdm_get_random_bytes", len);
		break;

	case fuzz_call_get_random_bytes_full:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		esdm_get_random_bytes_full_noblock(buf, len);
		fuzz_check_guard("esdm_get_random_bytes_full_noblock", len);
		break;

	case fuzz_call_get_random_bytes_pr:
		len = fuzz_len(in, FUZZ_PR_MAX);
		buf = fuzz_buf(len);
		esdm_get_random_bytes_pr_noblock(buf, len);
		fuzz_check_guard("esdm_get_random_bytes_pr_noblock", len);
		break;

	case fuzz_call_get_seed:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		esdm_get_seed((uint64_t *)fuzz_area, len,
			      (enum esdm_get_seed_flags)fuzz_u8(in));
		fuzz_check_guard("esdm_get_seed", len);
		break;

	case fuzz_call_insert_aux:
		/*
		 * The one call taking bytes rather than only sizes: what is
		 * inserted here is what the generating calls above go on to
		 * work from.
		 */
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		if (len) {
			size_t avail = in->len - in->pos;

			memcpy(buf, in->data + in->pos,
			       (avail < len) ? avail : len);
			in->pos += (avail < len) ? avail : len;
		}
		esdm_pool_insert_aux(buf, len, fuzz_u32(in));
		fuzz_check_guard("esdm_pool_insert_aux", len);
		break;

	case fuzz_call_status:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_status((char *)buf, len);
		fuzz_check_string("esdm_status", len, ret);
		break;

	case fuzz_call_status_json:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_status_json((char *)buf, len);
		fuzz_check_string("esdm_status_json", len, ret);
		break;

	case fuzz_call_status_drng_json:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_status_drng_json(fuzz_u32(in), (char *)buf, len);
		fuzz_check_string("esdm_status_drng_json", len, ret);
		break;

	case fuzz_call_status_drng_pr_json:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_status_drng_pr_json((char *)buf, len);
		fuzz_check_string("esdm_status_drng_pr_json", len, ret);
		break;

	case fuzz_call_version:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		esdm_version((char *)buf, len);
		fuzz_check_string("esdm_version", len, 0);
		break;

	case fuzz_call_set_write_wakeup_bits:
		esdm_set_write_wakeup_bits(fuzz_u32(in));
		break;

	case fuzz_call_set_reseed_max_time:
		esdm_set_reseed_max_time(fuzz_u32(in));
		break;

	case fuzz_call_pool_set_entropy:
		esdm_pool_set_entropy(fuzz_u32(in));
		break;

	case fuzz_call_force_reseed:
		esdm_drng_force_reseed();
		break;

	case fuzz_call_query: {
		/* The calls that only report. */
		struct esdm_status_st status;
		static volatile uint32_t sink;

		esdm_status_machine(&status);
		sink = esdm_avail_entropy();
		sink = esdm_avail_entropy_aux();
		sink = esdm_avail_poolsize_aux();
		sink = esdm_get_aux_ent();
		sink = esdm_get_digestsize();
		sink = esdm_get_write_wakeup_bits();
		sink = esdm_get_reseed_max_time();
		sink = (uint32_t)esdm_state_operational();
		sink = (uint32_t)esdm_state_fully_seeded();
		sink = (uint32_t)esdm_es_oversampling();
		(void)sink;
		break;
	}

	case fuzz_calls:
	default:
		break;
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	if (!getenv("ESDM_FUZZ_VERBOSE"))
		esdm_logger_set_verbosity(LOGGER_NONE);

	if (esdm_init()) {
		fprintf(stderr, "cannot initialize the ESDM\n");
		exit(1);
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_input in = { .data = data, .len = size, .pos = 0 };
	unsigned int calls = 0;

	while (in.pos < in.len && calls++ < FUZZ_MAX_CALLS)
		fuzz_one_call(&in);

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

/*
 * One seed per call, so the fuzzer starts with every one of them reached at
 * least once, plus a script running through all of them in order - the calls
 * share the state of the library, and a sequence is where that shows.
 */
#define FUZZ_MAX_SEEDS (fuzz_calls + 1)
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static char fuzz_seed_names[FUZZ_MAX_SEEDS][32];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][2 * FUZZ_MAX_SEEDS + 16];
static size_t fuzz_num_seeds;

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	unsigned int call;
	uint8_t *seed;

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	for (call = 0; call < fuzz_calls; call++) {
		seed = fuzz_seed_data[fuzz_num_seeds];

		/* The call, then a length of 32 and room for its arguments */
		seed[0] = (uint8_t)call;
		seed[1] = 0;
		seed[2] = 32;
		memset(seed + 3, 0, 8);

		snprintf(fuzz_seed_names[fuzz_num_seeds],
			 sizeof(fuzz_seed_names[0]), "call-%u", call);

		fuzz_seeds[fuzz_num_seeds].name =
			fuzz_seed_names[fuzz_num_seeds];
		fuzz_seeds[fuzz_num_seeds].data = seed;
		fuzz_seeds[fuzz_num_seeds].len = 11;
		fuzz_num_seeds++;
	}

	/* And one input running through every call */
	seed = fuzz_seed_data[fuzz_num_seeds];
	for (call = 0; call < fuzz_calls; call++) {
		seed[2 * call] = (uint8_t)call;
		seed[2 * call + 1] = 0;
	}

	snprintf(fuzz_seed_names[fuzz_num_seeds], sizeof(fuzz_seed_names[0]),
		 "every-call");

	fuzz_seeds[fuzz_num_seeds].name = fuzz_seed_names[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = 2 * fuzz_calls;
	fuzz_num_seeds++;

	*num = fuzz_num_seeds;

	return fuzz_seeds;
}
