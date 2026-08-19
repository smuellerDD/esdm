/*
 * Fuzz harness: the ESDM OpenSSL RAND providers
 *
 * A provider is a library loaded into somebody else's process, and everything
 * it is handed comes from that side: libcrypto asks for a number of bytes, an
 * entropy strength, a seed of at least this and at most that many bytes, and
 * hands over OSSL_PARAM arrays whose types and sizes the provider has to check
 * rather than believe. On the other side the provider talks to the ESDM, over
 * the RPC interface or over the EGD socket, and what comes back from there is
 * a second set of bytes it does not control.
 *
 * This harness drives an ESDM provider from both directions. The provider is
 * loaded the way libcrypto loads it - through OSSL_PROVIDER_add_builtin(), so
 * OSSL_provider_init() runs with the real core upcalls - and its dispatch
 * table is then called directly, which is what lets an input choose arguments
 * no application would produce: a seed request of INT_MAX bits, a minimum
 * length above the maximum, an OSSL_PARAM claiming to be an integer in a
 * buffer of one byte. The peer behind the provider is the backend next to this
 * file; for the EGD variants it is an impostor answering with the tail of the
 * same input.
 *
 * Beyond crashes the harness holds the provider to the contract of
 * <openssl/core_dispatch.h>, which is where a bug here would do its damage:
 *
 *  - nothing is written behind the buffer a call was given, and no OSSL_PARAM
 *    is filled past its data_size,
 *  - a generate() or nonce() that failed leaves no partial random data behind
 *    for a caller to mistake for a complete answer,
 *  - get_seed() either hands back nothing at all, or a buffer of at least
 *    min_len and at most max_len bytes that is really that large - a seed
 *    consumer sizes its pool by the returned length,
 *  - a failed get_seed() leaves the caller's pointer NULL rather than a buffer
 *    it would then free twice,
 *  - and the EGD variant bound to the ordinary socket refuses every request
 *    asking for prediction resistance, rather than serving data that does not
 *    have the property that was asked for.
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

#include <limits.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_egd_protocol.h"
#include "esdm_logger.h"
#include "fuzz.h"
#include "ossl_prov_fuzz.h"

/* The provider module this harness was linked against */
extern OSSL_provider_init_fn OSSL_provider_init;

/*
 * Largest buffer a call is given, and the guard behind it. The variants
 * defaulting every request to the prediction resistance generator collect
 * fresh entropy for each one, so what they are asked for stays small - the
 * point of those builds is the routing decision, not the volume.
 */
#ifdef ESDM_OSSL_PROV_FORCE_PR
#define FUZZ_BUF_MAX 32
#else
#define FUZZ_BUF_MAX 4096
#endif
#define FUZZ_GUARD 64
#define FUZZ_GUARD_BYTE 0x5a

/* What a request asking for prediction resistance may ask for, for the same reason */
#define FUZZ_PR_MAX 32

/* Calls of an input, so one input cannot run for arbitrarily long */
#define FUZZ_MAX_CALLS 24

/* OSSL_PARAM arrays an input can build, and the room behind each entry */
#define FUZZ_PARAM_MAX 4
#define FUZZ_PARAM_DATA 32

static uint64_t fuzz_area[(FUZZ_BUF_MAX + FUZZ_GUARD) / sizeof(uint64_t)];
static uint64_t fuzz_param_area[FUZZ_PARAM_MAX]
			       [(FUZZ_PARAM_DATA + FUZZ_GUARD) /
				sizeof(uint64_t)];

/******************************************************************************
 * The input
 ******************************************************************************/

struct fuzz_input {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

static uint8_t fuzz_u8(struct fuzz_input *in)
{
	return (in->pos < in->len) ? in->data[in->pos++] : 0;
}

static size_t fuzz_len(struct fuzz_input *in, size_t max)
{
	size_t val = ((size_t)fuzz_u8(in) << 8) | fuzz_u8(in);

	return (val % (max + 1));
}

static uint8_t *fuzz_buf(size_t len)
{
	uint8_t *buf = (uint8_t *)fuzz_area;

	memset(buf, 0, len);
	memset(buf + len, FUZZ_GUARD_BYTE, FUZZ_GUARD);

	return buf;
}

/* Nothing may be written behind the buffer the call was given */
static void fuzz_check_guard(const char *call, const uint8_t *buf, size_t len)
{
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
 * A call that failed has to leave nothing behind that could pass for the
 * answer it did not deliver. The buffer went in zeroed, so anything else in it
 * is a piece of an answer the caller was told it did not get.
 */
static void fuzz_check_cleansed(const char *call, const uint8_t *buf,
				size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (!buf[i])
			continue;

		fprintf(stderr,
			"%s failed and left %zu byte(s) of a partial answer behind\n",
			call, len - i);
		abort();
	}
}

/******************************************************************************
 * The provider under test
 ******************************************************************************/

/* Everything of the provider one input holds on to */
struct fuzz_prov {
	OSSL_LIB_CTX *libctx;
	OSSL_PROVIDER *prov;

	/* Handed over by OSSL_provider_init(), captured on the way through */
	const OSSL_CORE_HANDLE *handle;
	const OSSL_DISPATCH *in;
	const OSSL_DISPATCH *out;
	void *provctx;

	/* The provider's own functions */
	OSSL_FUNC_provider_gettable_params_fn *gettable_params;
	OSSL_FUNC_provider_get_params_fn *get_params;
	OSSL_FUNC_provider_query_operation_fn *query_operation;
	OSSL_FUNC_provider_unquery_operation_fn *unquery_operation;
	OSSL_FUNC_provider_get_reason_strings_fn *get_reason_strings;
	OSSL_FUNC_provider_self_test_fn *self_test;
	OSSL_FUNC_provider_teardown_fn *teardown;

	/* The RAND algorithm currently selected, and its functions */
	const OSSL_ALGORITHM *algs;
	OSSL_FUNC_rand_newctx_fn *newctx;
	OSSL_FUNC_rand_freectx_fn *freectx;
	OSSL_FUNC_rand_instantiate_fn *instantiate;
	OSSL_FUNC_rand_uninstantiate_fn *uninstantiate;
	OSSL_FUNC_rand_generate_fn *generate;
	OSSL_FUNC_rand_reseed_fn *reseed;
	OSSL_FUNC_rand_nonce_fn *nonce;
	OSSL_FUNC_rand_get_seed_fn *get_seed;
	OSSL_FUNC_rand_clear_seed_fn *clear_seed;
	OSSL_FUNC_rand_verify_zeroization_fn *verify_zeroization;
	OSSL_FUNC_rand_enable_locking_fn *enable_locking;
	OSSL_FUNC_rand_lock_fn *lock;
	OSSL_FUNC_rand_unlock_fn *unlock;
	OSSL_FUNC_rand_gettable_ctx_params_fn *gettable_ctx_params;
	OSSL_FUNC_rand_get_ctx_params_fn *get_ctx_params;

	/* The RNG context the calls of this input run against */
	void *randctx;

	/*
	 * Whether locking was enabled on that context, and whether its lock is
	 * currently held. Both are the harness keeping itself honest rather
	 * than anything about the provider: libcrypto pairs a lock with the
	 * unlock around one operation, and taking a write lock the calling
	 * thread already holds - or giving back one it never took - wedges the
	 * harness rather than saying anything about what it is testing. A
	 * context without locking enabled answers both calls with a no-op, so
	 * only a lock taken after enable_locking succeeded is a real one.
	 */
	bool locking_enabled;
	bool locked;
};

static struct fuzz_prov fuzz_prov;

/*
 * libcrypto calls OSSL_provider_init() and keeps what comes out to itself.
 * This wrapper sits in between and keeps a copy: the dispatch table is what
 * the harness calls, and the core handle together with the upcall table is
 * what lets it stand up a second, independent provider context of its own.
 */
static int fuzz_provider_init(const OSSL_CORE_HANDLE *handle,
			      const OSSL_DISPATCH *in,
			      const OSSL_DISPATCH **out, void **provctx)
{
	int ret = OSSL_provider_init(handle, in, out, provctx);

	if (ret) {
		fuzz_prov.handle = handle;
		fuzz_prov.in = in;
		fuzz_prov.out = *out;
		fuzz_prov.provctx = *provctx;
	}

	return ret;
}

static void fuzz_resolve_provider_fns(struct fuzz_prov *p)
{
	const OSSL_DISPATCH *d;

	for (d = p->out; d != NULL && d->function_id != 0; d++) {
		switch (d->function_id) {
		case OSSL_FUNC_PROVIDER_GETTABLE_PARAMS:
			p->gettable_params =
				OSSL_FUNC_provider_gettable_params(d);
			break;
		case OSSL_FUNC_PROVIDER_GET_PARAMS:
			p->get_params = OSSL_FUNC_provider_get_params(d);
			break;
		case OSSL_FUNC_PROVIDER_QUERY_OPERATION:
			p->query_operation =
				OSSL_FUNC_provider_query_operation(d);
			break;
		case OSSL_FUNC_PROVIDER_UNQUERY_OPERATION:
			p->unquery_operation =
				OSSL_FUNC_provider_unquery_operation(d);
			break;
		case OSSL_FUNC_PROVIDER_GET_REASON_STRINGS:
			p->get_reason_strings =
				OSSL_FUNC_provider_get_reason_strings(d);
			break;
		case OSSL_FUNC_PROVIDER_SELF_TEST:
			p->self_test = OSSL_FUNC_provider_self_test(d);
			break;
		case OSSL_FUNC_PROVIDER_TEARDOWN:
			p->teardown = OSSL_FUNC_provider_teardown(d);
			break;
		default:
			break;
		}
	}
}

static void fuzz_resolve_rand_fns(struct fuzz_prov *p,
				  const OSSL_DISPATCH *table)
{
	const OSSL_DISPATCH *d;

	for (d = table; d != NULL && d->function_id != 0; d++) {
		switch (d->function_id) {
		case OSSL_FUNC_RAND_NEWCTX:
			p->newctx = OSSL_FUNC_rand_newctx(d);
			break;
		case OSSL_FUNC_RAND_FREECTX:
			p->freectx = OSSL_FUNC_rand_freectx(d);
			break;
		case OSSL_FUNC_RAND_INSTANTIATE:
			p->instantiate = OSSL_FUNC_rand_instantiate(d);
			break;
		case OSSL_FUNC_RAND_UNINSTANTIATE:
			p->uninstantiate = OSSL_FUNC_rand_uninstantiate(d);
			break;
		case OSSL_FUNC_RAND_GENERATE:
			p->generate = OSSL_FUNC_rand_generate(d);
			break;
		case OSSL_FUNC_RAND_RESEED:
			p->reseed = OSSL_FUNC_rand_reseed(d);
			break;
		case OSSL_FUNC_RAND_NONCE:
			p->nonce = OSSL_FUNC_rand_nonce(d);
			break;
		case OSSL_FUNC_RAND_GET_SEED:
			p->get_seed = OSSL_FUNC_rand_get_seed(d);
			break;
		case OSSL_FUNC_RAND_CLEAR_SEED:
			p->clear_seed = OSSL_FUNC_rand_clear_seed(d);
			break;
		case OSSL_FUNC_RAND_VERIFY_ZEROIZATION:
			p->verify_zeroization =
				OSSL_FUNC_rand_verify_zeroization(d);
			break;
		case OSSL_FUNC_RAND_ENABLE_LOCKING:
			p->enable_locking = OSSL_FUNC_rand_enable_locking(d);
			break;
		case OSSL_FUNC_RAND_LOCK:
			p->lock = OSSL_FUNC_rand_lock(d);
			break;
		case OSSL_FUNC_RAND_UNLOCK:
			p->unlock = OSSL_FUNC_rand_unlock(d);
			break;
		case OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS:
			p->gettable_ctx_params =
				OSSL_FUNC_rand_gettable_ctx_params(d);
			break;
		case OSSL_FUNC_RAND_GET_CTX_PARAMS:
			p->get_ctx_params = OSSL_FUNC_rand_get_ctx_params(d);
			break;
		default:
			break;
		}
	}
}

/*
 * Ask the provider what it offers for the RAND operation and take the
 * implementation of one of its algorithms. Every name a provider declares
 * resolves to the same dispatch table here, but going through the query is
 * what puts that table on the record rather than assuming it.
 */
static void fuzz_select_algorithm(struct fuzz_prov *p, uint8_t which)
{
	size_t count = 0;
	int no_cache = 0;

	if (!p->query_operation)
		return;

	p->algs = p->query_operation(p->provctx, OSSL_OP_RAND, &no_cache);
	if (!p->algs)
		return;

	while (p->algs[count].algorithm_names)
		count++;
	if (!count)
		return;

	fuzz_resolve_rand_fns(p, p->algs[which % count].implementation);
}

/* Load the provider the way libcrypto does, into a library context of its own */
static bool fuzz_prov_load(struct fuzz_prov *p, uint8_t which_alg)
{
	memset(p, 0, sizeof(*p));

	p->libctx = OSSL_LIB_CTX_new();
	if (!p->libctx)
		return false;

	if (!OSSL_PROVIDER_add_builtin(p->libctx, FUZZ_PROV_MODULE_NAME,
				       fuzz_provider_init))
		goto err;

	p->prov = OSSL_PROVIDER_load(p->libctx, FUZZ_PROV_MODULE_NAME);
	if (!p->prov)
		goto err;

	fuzz_resolve_provider_fns(p);
	fuzz_select_algorithm(p, which_alg);

	if (p->newctx)
		p->randctx = p->newctx(p->provctx, NULL, NULL);

	return true;

err:
	OSSL_LIB_CTX_free(p->libctx);
	p->libctx = NULL;

	return false;
}

static void fuzz_prov_unload(struct fuzz_prov *p)
{
	if (p->locked && p->unlock)
		p->unlock(p->randctx);
	p->locked = false;
	p->locking_enabled = false;

	if (p->randctx && p->freectx)
		p->freectx(p->randctx);
	p->randctx = NULL;

	if (p->unquery_operation && p->algs)
		p->unquery_operation(p->provctx, OSSL_OP_RAND, p->algs);

	if (p->prov)
		OSSL_PROVIDER_unload(p->prov);
	OSSL_LIB_CTX_free(p->libctx);

	/*
	 * The error stack of this thread carries whatever the provider
	 * reported, and the next input starts from a clean one - an error
	 * stack growing across inputs is a leak the fuzzer would find
	 * eventually, in the wrong place.
	 */
	ERR_clear_error();

	memset(p, 0, sizeof(*p));
}

/******************************************************************************
 * The calls an input can pick from
 ******************************************************************************/

/*
 * An entropy request in bits. Mostly a plausible number, occasionally one of
 * the values the arithmetic in get_seed() has to survive: the rounding to
 * bytes, and the comparison against a caller's limits.
 */
static int fuzz_entropy_bits(struct fuzz_input *in, size_t max_bytes)
{
	switch (fuzz_u8(in) & 0x07) {
	case 0:
		return INT_MAX;
	case 1:
		return INT_MIN;
	case 2:
		return 0;
	case 3:
		return -1;
	default:
		return (int)fuzz_len(in, max_bytes * 8);
	}
}

/* The keys a provider of this kind is asked about, plus ones it has never heard of */
static const char *const fuzz_param_keys[] = {
	OSSL_RAND_PARAM_MAX_REQUEST, OSSL_RAND_PARAM_STRENGTH,
	OSSL_RAND_PARAM_STATE,	     OSSL_PROV_PARAM_NAME,
	OSSL_PROV_PARAM_VERSION,     OSSL_PROV_PARAM_BUILDINFO,
	OSSL_PROV_PARAM_STATUS,	     "",
	"esdm-no-such-parameter",    OSSL_RAND_PARAM_TEST_ENTROPY,
};

static const unsigned int fuzz_param_types[] = {
	OSSL_PARAM_INTEGER,	   OSSL_PARAM_UNSIGNED_INTEGER,
	OSSL_PARAM_REAL,	   OSSL_PARAM_UTF8_STRING,
	OSSL_PARAM_OCTET_STRING,   OSSL_PARAM_UTF8_PTR,
	OSSL_PARAM_OCTET_PTR,
};

/*
 * Build an OSSL_PARAM array the caller's way: any key, any type, any size. The
 * data area behind each entry is always large enough for a pointer - the
 * OSSL_PARAM_set_*_ptr() setters write one without consulting data_size, which
 * is the caller's job to get right and not the provider's - while data_size
 * itself is whatever the input says, so the checks the provider does make are
 * the ones under test.
 */
static OSSL_PARAM *fuzz_build_params(struct fuzz_input *in, OSSL_PARAM *params,
				     size_t *num)
{
	size_t count = (size_t)(fuzz_u8(in) % (FUZZ_PARAM_MAX + 1));
	size_t i;

	for (i = 0; i < count; i++) {
		uint8_t key = fuzz_u8(in);
		uint8_t type = fuzz_u8(in);
		uint8_t *data = (uint8_t *)fuzz_param_area[i];

		memset(data, 0, FUZZ_PARAM_DATA);
		memset(data + FUZZ_PARAM_DATA, FUZZ_GUARD_BYTE, FUZZ_GUARD);

		params[i].key =
			fuzz_param_keys[key % (sizeof(fuzz_param_keys) /
					       sizeof(fuzz_param_keys[0]))];
		params[i].data_type =
			fuzz_param_types[type % (sizeof(fuzz_param_types) /
						 sizeof(fuzz_param_types[0]))];
		params[i].data = data;
		params[i].data_size =
			(size_t)(fuzz_u8(in) % (FUZZ_PARAM_DATA + 1));
		params[i].return_size = 0;
	}

	params[count] = OSSL_PARAM_construct_end();
	*num = count;

	return params;
}

static void fuzz_check_params(const char *call, size_t num)
{
	size_t i;

	for (i = 0; i < num; i++)
		fuzz_check_guard(call, (const uint8_t *)fuzz_param_area[i],
				 FUZZ_PARAM_DATA);
}

/* A parameter descriptor a provider hands out has to be a terminated array */
static void fuzz_walk_param_defs(const char *call, const OSSL_PARAM *defs)
{
	static volatile size_t sink;
	size_t count = 0;

	if (!defs) {
		fprintf(stderr, "%s handed back no descriptor at all\n", call);
		abort();
	}

	while (defs[count].key) {
		sink = strlen(defs[count].key);
		count++;
	}

	(void)sink;
}

enum fuzz_call {
	fuzz_call_generate,
	fuzz_call_nonce,
	fuzz_call_get_seed,
	fuzz_call_instantiate,
	fuzz_call_uninstantiate,
	fuzz_call_reseed,
	fuzz_call_locking,
	fuzz_call_get_ctx_params,
	fuzz_call_gettable_ctx_params,
	fuzz_call_verify_zeroization,
	fuzz_call_prov_get_params,
	fuzz_call_prov_gettable_params,
	fuzz_call_query_operation,
	fuzz_call_self_test,
	fuzz_call_reason_strings,
	fuzz_call_null_ctx,
	fuzz_call_newctx,
	fuzz_call_second_init,
	fuzz_call_evp_rand,
	fuzz_calls
};

/*
 * The prediction resistance flag of a request, and what the provider variant
 * under test owes the caller for it.
 */
static bool fuzz_pr(struct fuzz_input *in)
{
	return (fuzz_u8(in) & 1) != 0;
}

static void fuzz_check_pr_refused(const char *call, bool pr, bool succeeded)
{
	if (!FUZZ_PROV_REFUSES_PR || !pr || !succeeded)
		return;

	fprintf(stderr,
		"%s served a request asking for prediction resistance, which this provider cannot deliver\n",
		call);
	abort();
}

static void fuzz_call_generate_one(struct fuzz_prov *p, struct fuzz_input *in)
{
	bool pr = fuzz_pr(in);
	size_t len = fuzz_len(in, pr ? FUZZ_PR_MAX : FUZZ_BUF_MAX);
	unsigned int strength = fuzz_u8(in);
	uint8_t *buf;
	int ret;

	if (!p->generate)
		return;

	/* Every so often the buffer libcrypto never passes, which is refused */
	if (!(fuzz_u8(in) & 0x3f)) {
		p->generate(p->randctx, NULL, len, strength, pr, NULL, 0);
		return;
	}

	buf = fuzz_buf(len);
	ret = p->generate(p->randctx, buf, len, strength, pr, NULL, 0);
	fuzz_check_guard("rand_generate", buf, len);
	fuzz_check_pr_refused("rand_generate", pr, ret == 1);

	if (ret != 1)
		fuzz_check_cleansed("rand_generate", buf, len);
}

static void fuzz_call_nonce_one(struct fuzz_prov *p, struct fuzz_input *in)
{
	size_t min_len = fuzz_len(in, FUZZ_BUF_MAX);
	size_t max_len = fuzz_len(in, FUZZ_BUF_MAX);
	unsigned int strength = fuzz_u8(in);
	uint8_t *buf;
	size_t ret;

	if (!p->nonce)
		return;

	/* A NULL buffer asks for the length the call would deliver */
	if (!(fuzz_u8(in) & 0x0f)) {
		ret = p->nonce(p->randctx, NULL, strength, min_len, max_len);
		if (ret > min_len) {
			fprintf(stderr,
				"rand_nonce announced %zu bytes for a request of %zu\n",
				ret, min_len);
			abort();
		}
		return;
	}

	buf = fuzz_buf(min_len);
	ret = p->nonce(p->randctx, buf, strength, min_len, max_len);
	fuzz_check_guard("rand_nonce", buf, min_len);

	if (ret && ret != min_len) {
		fprintf(stderr,
			"rand_nonce delivered %zu bytes into a buffer of %zu\n",
			ret, min_len);
		abort();
	}

	/* A zero length request cannot be told apart from a refusal */
	if (!ret && min_len)
		fuzz_check_cleansed("rand_nonce", buf, min_len);
}

static void fuzz_call_get_seed_one(struct fuzz_prov *p, struct fuzz_input *in)
{
	bool pr = fuzz_pr(in);
	/*
	 * A request asking for prediction resistance is served from entropy
	 * collected for it, one round per block of output, so it stays small -
	 * what these harnesses are after is the routing decision and the
	 * arithmetic in front of it, not the volume.
	 */
	size_t max_req = pr ? FUZZ_PR_MAX : FUZZ_BUF_MAX;
	int entropy_bits = fuzz_entropy_bits(in, max_req);
	size_t min_len = fuzz_len(in, max_req);
	size_t max_len = fuzz_len(in, max_req);
	unsigned char *buffer = (unsigned char *)(uintptr_t)0x1;
	static volatile uint8_t sink;
	size_t ret, i;

	if (!p->get_seed)
		return;

	ret = p->get_seed(p->randctx, &buffer, entropy_bits, min_len, max_len,
			  pr, NULL, 0);

	fuzz_check_pr_refused("rand_get_seed", pr, ret != 0);

	if (!ret) {
		/*
		 * Nothing was delivered, so nothing may be handed back either
		 * - a caller freeing what it was given would otherwise free a
		 * buffer the provider has already released, or one that was
		 * never allocated at all.
		 */
		if (buffer) {
			fprintf(stderr,
				"rand_get_seed failed and handed back a buffer anyway\n");
			abort();
		}
		return;
	}

	if (!buffer) {
		fprintf(stderr,
			"rand_get_seed reports %zu bytes and no buffer to find them in\n",
			ret);
		abort();
	}

	/*
	 * The caller sizes its seed material by the returned length, so it has
	 * to sit inside what the caller said it accepts - and the buffer has to
	 * really be that large, which reading it through is what establishes.
	 */
	if (ret < min_len || ret > max_len) {
		fprintf(stderr,
			"rand_get_seed delivered %zu bytes for a request of %zu to %zu\n",
			ret, min_len, max_len);
		abort();
	}

	for (i = 0; i < ret; i++)
		sink = buffer[i];
	(void)sink;

	if (p->clear_seed)
		p->clear_seed(p->randctx, buffer, ret);
}

/*
 * Everything a provider is handed a NULL context for, which libcrypto does on
 * the paths where a context could not be created. Nothing is asserted about
 * the answers: the RPC based providers keep no state in the context that a
 * request needs, so a call without one is served rather than refused, while
 * the EGD ones reach their connection through it and have to refuse. What both
 * owe the caller is not to walk into the NULL pointer.
 */
static void fuzz_call_null_ctx_one(struct fuzz_prov *p)
{
	unsigned char buf[16];
	unsigned char *seed = (unsigned char *)(uintptr_t)0x1;

	if (p->freectx)
		p->freectx(NULL);
	if (p->lock)
		p->lock(NULL);
	if (p->unlock)
		p->unlock(NULL);
	if (p->enable_locking)
		p->enable_locking(NULL);
	if (p->uninstantiate)
		p->uninstantiate(NULL);
	if (p->instantiate)
		p->instantiate(NULL, 256, 0, NULL, 0, NULL);
	if (p->generate)
		p->generate(NULL, buf, sizeof(buf), 256, 0, NULL, 0);
	if (p->nonce)
		p->nonce(NULL, buf, 256, sizeof(buf), sizeof(buf));
	if (p->get_seed) {
		size_t ret = p->get_seed(NULL, &seed, 128, 16, 64, 0, NULL, 0);

		if (!ret && seed) {
			fprintf(stderr,
				"rand_get_seed failed and handed back a buffer anyway\n");
			abort();
		}
		if (ret && seed && p->clear_seed)
			p->clear_seed(NULL, seed, ret);
	}
	if (p->get_ctx_params)
		p->get_ctx_params(NULL, NULL);
	if (p->verify_zeroization)
		p->verify_zeroization(NULL);
	if (p->gettable_ctx_params)
		fuzz_walk_param_defs("rand_gettable_ctx_params",
				     p->gettable_ctx_params(NULL, p->provctx));
}

/*
 * A second provider context alongside the one libcrypto holds. What this
 * reaches is the initialization and the teardown themselves - for the RPC
 * variants the reference counting of the shared client connection, for the EGD
 * ones a second connection to the peer.
 */
static void fuzz_call_second_init_one(struct fuzz_prov *p)
{
	const OSSL_DISPATCH *out = NULL;
	void *provctx = NULL;

	if (!p->handle || !p->in)
		return;

	if (!OSSL_provider_init(p->handle, p->in, &out, &provctx))
		return;

	if (!out || !provctx) {
		fprintf(stderr,
			"OSSL_provider_init succeeded without handing back a provider\n");
		abort();
	}

	for (; out->function_id != 0; out++) {
		if (out->function_id != OSSL_FUNC_PROVIDER_TEARDOWN)
			continue;

		OSSL_FUNC_provider_teardown(out)(provctx);
		return;
	}

	fprintf(stderr, "the provider offers no teardown\n");
	abort();
}

/* The provider through the interface an application actually uses */
static void fuzz_call_evp_rand_one(struct fuzz_prov *p, struct fuzz_input *in)
{
	static const char *const names[] = { "CTR-DRBG", "HASH-DRBG",
					     "HMAC-DRBG", "SEED-SRC" };
	const char *name = names[fuzz_u8(in) % 4];
	bool pr = fuzz_pr(in);
	size_t len = fuzz_len(in, pr ? FUZZ_PR_MAX : FUZZ_BUF_MAX);
	EVP_RAND_CTX *rctx;
	EVP_RAND *rand;
	uint8_t *buf;

	rand = EVP_RAND_fetch(p->libctx, name, FUZZ_PROV_PROPERTY);
	if (!rand)
		return;

	rctx = EVP_RAND_CTX_new(rand, NULL);
	EVP_RAND_free(rand);
	if (!rctx)
		return;

	if (fuzz_u8(in) & 1)
		EVP_RAND_enable_locking(rctx);

	if (EVP_RAND_instantiate(rctx, fuzz_u8(in), pr, NULL, 0, NULL) == 1) {
		/*
		 * Only the guard is checked here. libcrypto splits a request
		 * into transfers of the size the provider announces and reports
		 * the failure of the last one, so bytes from the transfers
		 * before it stay in the buffer - that is its doing, not the
		 * provider's, and the direct call above is where the provider
		 * is held to cleansing what it did not deliver.
		 */
		buf = fuzz_buf(len);
		EVP_RAND_generate(rctx, buf, len, fuzz_u8(in), pr, NULL, 0);
		fuzz_check_guard("EVP_RAND_generate", buf, len);

		EVP_RAND_uninstantiate(rctx);
	}

	EVP_RAND_CTX_free(rctx);
	ERR_clear_error();
}

static void fuzz_one_call(struct fuzz_prov *p, struct fuzz_input *in)
{
	OSSL_PARAM params[FUZZ_PARAM_MAX + 1];
	size_t num = 0;

	switch ((enum fuzz_call)(fuzz_u8(in) % fuzz_calls)) {
	case fuzz_call_generate:
		fuzz_call_generate_one(p, in);
		break;

	case fuzz_call_nonce:
		fuzz_call_nonce_one(p, in);
		break;

	case fuzz_call_get_seed:
		fuzz_call_get_seed_one(p, in);
		break;

	case fuzz_call_instantiate: {
		bool pr = fuzz_pr(in);
		uint8_t pstr[16];
		size_t pstr_len = fuzz_len(in, sizeof(pstr));
		size_t i;
		int ret;

		if (!p->instantiate)
			break;

		for (i = 0; i < pstr_len; i++)
			pstr[i] = fuzz_u8(in);

		fuzz_build_params(in, params, &num);
		ret = p->instantiate(p->randctx, fuzz_u8(in), pr, pstr,
				     pstr_len, params);
		fuzz_check_params("rand_instantiate", num);
		fuzz_check_pr_refused("rand_instantiate", pr, ret == 1);
		break;
	}

	case fuzz_call_uninstantiate:
		if (p->uninstantiate)
			p->uninstantiate(p->randctx);
		break;

	case fuzz_call_reseed: {
		uint8_t ent[32];
		size_t ent_len = fuzz_len(in, sizeof(ent));
		size_t i;

		if (!p->reseed)
			break;

		for (i = 0; i < ent_len; i++)
			ent[i] = fuzz_u8(in);

		p->reseed(p->randctx, fuzz_pr(in), ent, ent_len, NULL, 0);
		break;
	}

	case fuzz_call_locking:
		/*
		 * Enabling locking twice leaks the first lock unless the
		 * provider notices, and locking a context that never had one
		 * has to be a no-op rather than a crash. The lock is taken and
		 * given back across calls rather than around one, so the
		 * operations in between run under it the way they do for a
		 * context shared between threads.
		 */
		switch (fuzz_u8(in) & 3) {
		case 0:
			if (p->enable_locking &&
			    p->enable_locking(p->randctx) == 1)
				p->locking_enabled = true;
			break;
		case 1:
			if (p->lock && !p->locked)
				p->locked = p->lock(p->randctx) == 1 &&
					    p->locking_enabled;
			break;
		default:
			if (p->unlock && p->locked) {
				p->unlock(p->randctx);
				p->locked = false;
			}
			break;
		}
		break;

	case fuzz_call_get_ctx_params:
		if (!p->get_ctx_params)
			break;
		fuzz_build_params(in, params, &num);
		p->get_ctx_params(p->randctx, params);
		fuzz_check_params("rand_get_ctx_params", num);
		break;

	case fuzz_call_gettable_ctx_params:
		if (!p->gettable_ctx_params)
			break;
		fuzz_walk_param_defs("rand_gettable_ctx_params",
				     p->gettable_ctx_params(p->randctx,
							    p->provctx));
		break;

	case fuzz_call_verify_zeroization:
		if (p->verify_zeroization)
			p->verify_zeroization(p->randctx);
		break;

	case fuzz_call_prov_get_params:
		if (!p->get_params)
			break;
		fuzz_build_params(in, params, &num);
		p->get_params(p->provctx, params);
		fuzz_check_params("provider_get_params", num);
		break;

	case fuzz_call_prov_gettable_params:
		if (!p->gettable_params)
			break;
		fuzz_walk_param_defs("provider_gettable_params",
				     p->gettable_params(p->provctx));
		break;

	case fuzz_call_query_operation: {
		/*
		 * Every operation identifier, not only the one this provider
		 * answers - libcrypto asks about all of them.
		 */
		int no_cache = 0;
		int op = (int)fuzz_u8(in);
		const OSSL_ALGORITHM *algs;

		if (!p->query_operation)
			break;

		algs = p->query_operation(p->provctx, op, &no_cache);
		if (algs && p->unquery_operation)
			p->unquery_operation(p->provctx, op, algs);

		/* And back to a table this input can keep calling */
		fuzz_select_algorithm(p, fuzz_u8(in));
		break;
	}

	case fuzz_call_self_test:
		if (p->self_test)
			p->self_test(p->provctx);
		break;

	case fuzz_call_reason_strings: {
		static volatile size_t sink;
		const OSSL_ITEM *items;

		if (!p->get_reason_strings)
			break;

		items = p->get_reason_strings(p->provctx);
		if (!items) {
			fprintf(stderr,
				"the provider offers no reason strings\n");
			abort();
		}

		for (; items->id != 0; items++) {
			if (!items->ptr) {
				fprintf(stderr,
					"reason %u has no text\n", items->id);
				abort();
			}
			sink = strlen(items->ptr);
		}
		(void)sink;
		break;
	}

	case fuzz_call_null_ctx:
		fuzz_call_null_ctx_one(p);
		break;

	case fuzz_call_newctx:
		/* A fresh RNG context, the old one released */
		if (!p->newctx || !p->freectx)
			break;
		if (p->locked && p->unlock)
			p->unlock(p->randctx);
		p->locked = false;
		p->locking_enabled = false;
		p->freectx(p->randctx);
		p->randctx = p->newctx(p->provctx, NULL, NULL);
		break;

	case fuzz_call_second_init:
		fuzz_call_second_init_one(p);
		break;

	case fuzz_call_evp_rand:
		fuzz_call_evp_rand_one(p, in);
		break;

	case fuzz_calls:
	default:
		break;
	}
}

/******************************************************************************
 * Driver
 ******************************************************************************/

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(getenv("ESDM_FUZZ_VERBOSE") ? LOGGER_DEBUG :
							       LOGGER_NONE);

	ret = fuzz_backend_init();
	if (ret) {
		fprintf(stderr, "the peer of the provider did not come up\n");
		exit(ret);
	}

	return 0;
}

/*
 * One input is a script of provider calls and the material the peer answers
 * them with: byte 0 the number of script bytes that follow, the script itself,
 * and the rest for the backend. The script comes first and is bounded by a
 * byte so that a mutation of the tail leaves the calls it is answering alone.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_input in;
	unsigned int calls = 0;
	size_t script_len;

	if (!size)
		return 0;

	script_len = data[0];
	if (script_len > size - 1)
		script_len = size - 1;

	in.data = data + 1;
	in.len = script_len;
	in.pos = 0;

	fuzz_backend_begin(data + 1 + script_len, size - 1 - script_len);

	/*
	 * A provider per input: it holds a connection to the peer, and one
	 * carried over from the input before would be answered with the tail of
	 * that one's stream.
	 */
	if (fuzz_prov_load(&fuzz_prov, fuzz_u8(&in))) {
		while (in.pos < in.len && calls++ < FUZZ_MAX_CALLS)
			fuzz_one_call(&fuzz_prov, &in);

		fuzz_prov_unload(&fuzz_prov);
	}

	fuzz_backend_end();

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

/*
 * One seed per call, so every function the provider offers is reached by a
 * plain "meson test" rather than only by a fuzzer that got there, plus a script
 * running through all of them - a provider is used as a sequence of calls
 * against one context, and what one of them leaves behind is what the next one
 * finds.
 *
 * Each carries a stream for the peer as well. The variants talking to a real
 * ESDM ignore it; the EGD ones answer their commands from it, so the seeds
 * start the fuzzer from exchanges that are parsed rather than refused at their
 * first byte.
 */
#define FUZZ_MAX_SEEDS (fuzz_calls + 4)
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static char fuzz_seed_names[FUZZ_MAX_SEEDS][32];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][1024];
static size_t fuzz_num_seeds;

/*
 * What the peer answers with, as records: a length byte and that many bytes,
 * each record one write and thus one read on the other side. Two records of
 * the largest transfer the protocol knows, which is what it takes for the
 * seeds to reach the paths where a request is served rather than refused: a
 * provider splits anything above 255 bytes into transfers of that size, and
 * the commands answered with a fixed length number take theirs off the front
 * of a record just the same.
 */
#define FUZZ_SEED_RECORDS 2
static uint8_t fuzz_seed_stream[FUZZ_SEED_RECORDS *
				(1 + ESDM_EGD_MAX_TRANSFER)];

static void fuzz_seed_stream_fill(void)
{
	size_t rec, i, pos = 0;

	for (rec = 0; rec < FUZZ_SEED_RECORDS; rec++) {
		fuzz_seed_stream[pos++] = ESDM_EGD_MAX_TRANSFER;
		for (i = 0; i < ESDM_EGD_MAX_TRANSFER; i++)
			fuzz_seed_stream[pos++] = (uint8_t)i;
	}
}

/* A seed: the script of provider calls, then what the peer answers with */
static void fuzz_seed_add(const char *name, const uint8_t *script,
			  size_t script_len)
{
	uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];

	if (fuzz_num_seeds >= FUZZ_MAX_SEEDS ||
	    1 + script_len + sizeof(fuzz_seed_stream) > sizeof(fuzz_seed_data[0]))
		return;

	seed[0] = (uint8_t)script_len;
	memcpy(seed + 1, script, script_len);
	memcpy(seed + 1 + script_len, fuzz_seed_stream,
	       sizeof(fuzz_seed_stream));

	snprintf(fuzz_seed_names[fuzz_num_seeds],
		 sizeof(fuzz_seed_names[0]), "%s", name);

	fuzz_seeds[fuzz_num_seeds].name = fuzz_seed_names[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len =
		1 + script_len + sizeof(fuzz_seed_stream);
	fuzz_num_seeds++;
}

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	/* Room for the arguments of the longest call, and then some */
	uint8_t script[1 + 8 * fuzz_calls];
	char name[sizeof(fuzz_seed_names[0])];
	unsigned int call;

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	fuzz_seed_stream_fill();

	for (call = 0; call < fuzz_calls; call++) {
		/*
		 * The algorithm to take out of the provider, the call, and
		 * arguments that are neither zero nor extreme - a length of a
		 * few hundred bytes, an output buffer rather than the NULL one.
		 */
		script[0] = 0;
		script[1] = (uint8_t)call;
		memset(script + 2, 1, 10);

		snprintf(name, sizeof(name), "call-%u", call);
		fuzz_seed_add(name, script, 12);
	}

	/* Every call in turn against one context and one connection */
	script[0] = 0;
	for (call = 0; call < fuzz_calls; call++) {
		script[1 + 8 * call] = (uint8_t)call;
		memset(script + 2 + 8 * call, 1, 7);
	}
	fuzz_seed_add("every-call", script, sizeof(script));

	/*
	 * A request asking for prediction resistance, which is the one thing
	 * the EGD variants have to refuse rather than serve.
	 */
	script[0] = 0;
	script[1] = fuzz_call_generate;
	script[2] = 1; /* prediction resistance */
	script[3] = 0;
	script[4] = 32; /* 32 bytes */
	script[5] = 0; /* strength */
	script[6] = 1; /* into a buffer */
	fuzz_seed_add("generate-prediction-resistance", script, 7);

	/* A seed request whose entropy in bits and byte limits line up */
	script[0] = 0;
	script[1] = fuzz_call_get_seed;
	script[2] = 0; /* no prediction resistance */
	script[3] = 4; /* the entropy is a number, not an extreme */
	script[4] = 0;
	script[5] = 128; /* 128 bits */
	script[6] = 0;
	script[7] = 16; /* at least 16 bytes */
	script[8] = 0;
	script[9] = 64; /* at most 64 */
	fuzz_seed_add("get-seed", script, 10);

	/*
	 * A seed request the provider cannot satisfy: more entropy than the
	 * caller accepts bytes for.
	 */
	script[3] = 0; /* INT_MAX bits */
	script[4] = 0;
	script[5] = 16;
	script[6] = 0;
	script[7] = 16;
	fuzz_seed_add("get-seed-beyond-max-len", script, 8);

	*num = fuzz_num_seeds;

	return fuzz_seeds;
}
