/*
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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

#include <cstdint>
#include <ctime>
#include <errno.h>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <botan/hash.h>
#include <botan/exceptn.h>

#include "esdm_crypto.h"
#include "esdm_botan.h"
#include "esdm_logger.h"
#include "ret_checkers.h"
#include "selftest_kat.h"

#include "config.h"

#include <botan/stateful_rng.h>
#ifdef ESDM_BOTAN_DRNG_CHACHA20
#include <botan/chacha_rng.h>
#endif
#ifdef ESDM_BOTAN_DRNG_HMAC
#include <botan/hmac_drbg.h>
#endif

#if (defined(ESDM_BOTAN_DRNG_CHACHA20) && defined(ESDM_BOTAN_DRNG_HMAC)) ||    \
	(!defined(ESDM_BOTAN_DRNG_CHACHA20) && !defined(ESDM_BOTAN_DRNG_HMAC))
#error "Only define one Botan DRNG implementation and/or at least one!"
#endif

static const std::string DEFAULT_BOTAN_HASH{ "SHA-3(512)" };

/* introduced, as Botan only exposes unique_ptr for its digests */
struct esdm_botan_hash_ctx {
	std::unique_ptr<Botan::HashFunction> hash_fn;
};

static uint32_t esdm_botan_hash_digestsize(void *hash)
{
	(void)hash;
	return 512 / 8;
}

static int esdm_botan_hash_init(void *hash)
{
	struct esdm_botan_hash_ctx *ctx =
		reinterpret_cast<esdm_botan_hash_ctx *>(hash);

	try {
		ctx->hash_fn = Botan::HashFunction::create_or_throw(
			DEFAULT_BOTAN_HASH);
	} catch (const std::exception &ex) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "Botan::HashFunction::create() failed %s\n",
			    ex.what());
		return -EFAULT;
	}

	return 0;
}

static int esdm_botan_hash_update(void *hash, const uint8_t *inbuf,
				  size_t inbuflen)
{
	struct esdm_botan_hash_ctx *ctx =
		reinterpret_cast<esdm_botan_hash_ctx *>(hash);

	/* A null hash_fn (hash_init never ran or failed) would SIGSEGV - the
	 * deref is not a C++ exception, so try/catch cannot recover it. */
	if (!ctx || !ctx->hash_fn)
		return -EFAULT;

	try {
		ctx->hash_fn->update(inbuf, inbuflen);
	} catch (const std::exception &ex) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "Botan hash update failed %s\n", ex.what());
		return -EFAULT;
	}

	return 0;
}

static int esdm_botan_hash_final(void *hash, uint8_t *digest)
{
	struct esdm_botan_hash_ctx *ctx =
		reinterpret_cast<esdm_botan_hash_ctx *>(hash);

	/* See esdm_botan_hash_update: guard the null unique_ptr deref. */
	if (!ctx || !ctx->hash_fn)
		return -EFAULT;

	try {
		ctx->hash_fn->final(digest);
	} catch (const std::exception &ex) {
		esdm_logger(LOGGER_ERR, LOGGER_C_MD,
			    "Botan hash final failed %s\n", ex.what());
		return -EFAULT;
	}

	return 0;
}

static int esdm_botan_hash_alloc(void **hash)
{
	struct esdm_botan_hash_ctx *tmp;
	struct esdm_botan_hash_ctx **ctx = (struct esdm_botan_hash_ctx **)hash;

	tmp = new (std::nothrow) struct esdm_botan_hash_ctx;
	if (!tmp)
		return -ENOMEM;

	*ctx = tmp;

	return 0;
}

static void esdm_botan_hash_dealloc(void *hash)
{
	struct esdm_botan_hash_ctx *ctx =
		reinterpret_cast<esdm_botan_hash_ctx *>(hash);

	if (ctx)
		delete ctx;
}

static const char *esdm_botan_hash_name(void)
{
	return "Botan SHA3-512";
}

static void esdm_botan_hash_desc_zero(void *hash)
{
	(void)hash;
}

struct nist_test_vector_sha3 {
	size_t len; /* in bit */
	const uint8_t *msg;
	const uint8_t *md;
};

static int esdm_botan_hash_selftest(void)
{
	/*
	 * taken from NIST FIPS 202 test vectors
	 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
	 *
	 * SHA3_512ShortMsg.rsp
	 */
	static const uint8_t msg_1[] = { 0x00 };
	static const uint8_t md_1[] = {
		0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5,
		0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16,
		0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c,
		0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
		0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00,
		0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86,
		0x28, 0x1d, 0xcd, 0x26
	};
	static const uint8_t msg_2[] = { 0xc6, 0x1a, 0x91, 0x88, 0x81,
					 0x2a, 0xe7, 0x39, 0x94, 0xbc,
					 0x0d, 0x6d, 0x40, 0x21 };
	static const uint8_t md_2[] = {
		0x06, 0x9e, 0x6a, 0xb1, 0x67, 0x5f, 0xed, 0x8d, 0x44, 0x10,
		0x5f, 0x3b, 0x62, 0xbb, 0xf5, 0xb8, 0xff, 0x7a, 0xe8, 0x04,
		0x09, 0x89, 0x86, 0x87, 0x9b, 0x11, 0xe0, 0xd7, 0xd9, 0xb1,
		0xb4, 0xcb, 0x7b, 0xc4, 0x7a, 0xeb, 0x74, 0x20, 0x1f, 0x50,
		0x9d, 0xdc, 0x92, 0xe5, 0x63, 0x3a, 0xbd, 0x2c, 0xbe, 0x0d,
		0xdc, 0xa2, 0x48, 0x0e, 0x99, 0x08, 0xaf, 0xa6, 0x32, 0xc8,
		0xc8, 0xd5, 0xaf, 0x2a
	};

	/*
	 * Two records rather than every short message of the NIST file: the
	 * self tests are repeated on their interval for as long as the ESDM
	 * runs, and a further message of a different length walks the same code
	 * with other values.
	 */
	static struct nist_test_vector_sha3 test_vectors[] = {
		{ .len = 0, .msg = msg_1, .md = md_1 },
		{ .len = 112, .msg = msg_2, .md = md_2 }
	};

	const size_t md_len = 512 / 8;
	uint8_t act[md_len];
	/* The longest message of the table above, with room to spare */
	uint8_t mod[64];
	void *hash = NULL;
	/* default to failure so an (empty) test table cannot return success */
	int ret = -EFAULT;

	for (size_t i = 0;
	     i < sizeof(test_vectors) / sizeof(struct nist_test_vector_sha3);
	     ++i) {
		size_t msg_len = test_vectors[i].len / 8;

		if (msg_len > sizeof(mod)) {
			ret = -EINVAL;
			goto out;
		}

		CKINT(esdm_botan_hash_alloc(&hash));
		CKINT(esdm_botan_hash_init(hash));
		CKINT(esdm_botan_hash_update(hash, test_vectors[i].msg,
					     msg_len));
		CKINT(esdm_botan_hash_final(hash, act));

		ret = esdm_kat_check(act, test_vectors[i].md, md_len);
		if (ret)
			goto out;

		esdm_botan_hash_dealloc(hash);
		hash = NULL;

		/* The empty message has no input byte to modify */
		if (!msg_len)
			continue;

		/* A message off by its first byte must not produce that digest */
		CKINT(esdm_kat_modify(mod, test_vectors[i].msg, msg_len));
		CKINT(esdm_botan_hash_alloc(&hash));
		CKINT(esdm_botan_hash_init(hash));
		CKINT(esdm_botan_hash_update(hash, mod, msg_len));
		CKINT(esdm_botan_hash_final(hash, act));

		ret = esdm_kat_check_differs(act, test_vectors[i].md, md_len);
		if (ret)
			goto out;

		esdm_botan_hash_dealloc(hash);
		hash = NULL;
	}

out:
	esdm_botan_hash_dealloc(hash);

	return ret;
}

const struct esdm_hash_cb esdm_botan_hash_cb = {
	.hash_name = esdm_botan_hash_name,
	.hash_selftest = esdm_botan_hash_selftest,
	.hash_digestsize = esdm_botan_hash_digestsize,
	.hash_init = esdm_botan_hash_init,
	.hash_update = esdm_botan_hash_update,
	.hash_final = esdm_botan_hash_final,
	.hash_desc_zero = esdm_botan_hash_desc_zero,
	.hash_alloc = esdm_botan_hash_alloc,
	.hash_dealloc = esdm_botan_hash_dealloc,
};

struct esdm_botan_drng_state {
	std::unique_ptr<Botan::Stateful_RNG> drbg;
	bool initialized;
};

static int esdm_botan_drbg_seed(void *drng, const uint8_t *inbuf,
				size_t inbuflen, const uint8_t *addtl,
				size_t addtllen)
{
	struct esdm_botan_drng_state *state =
		reinterpret_cast<esdm_botan_drng_state *>(drng);
#ifdef ESDM_BOTAN_DRNG_HMAC
	/* init at least with 256 bit entropy + 128 bit nonce */
	const size_t min_init_seedlen = 3 * (256 / 8) / 2;
#else
	/* init at least with 256 bit entropy */
	const size_t min_init_seedlen = 256 / 8;
#endif

	try {
		if (state->initialized) {
			/*
			 * SP800-90A reseeds over
			 * seed_material = entropy_input || additional_input,
			 * i.e. one Update across the concatenation. Dropping
			 * addtl loses the caller's additional input, and a
			 * second add_entropy() call would be two Updates and
			 * thus a different state transition.
			 */
			if (addtl && addtllen) {
				Botan::secure_vector<uint8_t> seed_material(
					inbuflen + addtllen);

				memcpy(seed_material.data(), inbuf, inbuflen);
				memcpy(seed_material.data() + inbuflen, addtl,
				       addtllen);

				state->drbg->add_entropy(seed_material.data(),
							 seed_material.size());
			} else {
				state->drbg->add_entropy(inbuf, inbuflen);
			}

			return 0;
		}

		if (inbuflen < min_init_seedlen) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"Botan DRNG initial seed too short: %zu < %zu bytes\n",
				inbuflen, min_init_seedlen);
			return -EINVAL;
		}

		state->drbg->initialize_with(inbuf, inbuflen);
		if (addtl)
			state->drbg->add_entropy(addtl, addtllen);
		state->initialized = true;

		return 0;
	} catch (const std::exception &ex) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Botan DRNG seeding failed: %s\n", ex.what());
		return -EFAULT;
	}
}

#ifdef ESDM_BOTAN_DRNG_HMAC
static ssize_t esdm_botan_drbg_generate_w_additional_data(void *drng,
							  uint8_t *outbuf,
							  size_t outbuflen,
							  const uint8_t *adata,
							  size_t adatalen)
{
	struct esdm_botan_drng_state *state =
		reinterpret_cast<esdm_botan_drng_state *>(drng);

	try {
		state->drbg->randomize_with_input(outbuf, outbuflen, adata,
						  adatalen);
	} catch (const std::exception &ex) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Botan DRNG generate failed: %s\n", ex.what());
		return -EFAULT;
	}

	return (ssize_t)outbuflen;
}
#endif

static ssize_t esdm_botan_drbg_generate(void *drng, uint8_t *outbuf,
					size_t outbuflen)
{
	/* calling randomize_with_input on chacha20 would
	 * trigger generating a new key on every request,
	 * skip this, as ChaCha20 should be the high speed
	 * option */
#ifdef ESDM_BOTAN_DRNG_CHACHA20
	struct esdm_botan_drng_state *state =
		reinterpret_cast<esdm_botan_drng_state *>(drng);

	try {
		state->drbg->randomize(outbuf, outbuflen);
	} catch (const std::exception &ex) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Botan DRNG generate failed: %s\n", ex.what());
		return -EFAULT;
	}

	return (ssize_t)outbuflen;
#endif

#ifdef ESDM_BOTAN_DRNG_HMAC
	/* value-initialize to avoid feeding uninitialized padding bytes as
	 * additional data */
	struct timespec ts = {};
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret) {
		return -errno;
	}

	/* always use additional data in order to perform additional mixing steps
	 * inside HMAC-DRBG (recommended by BSI AIS 20/31 V3.0, Sec. 5.3.2 Par. 1079) */
	return esdm_botan_drbg_generate_w_additional_data(
		drng, outbuf, outbuflen, reinterpret_cast<const uint8_t *>(&ts),
		sizeof(ts));
#endif
}

static void
esdm_botan_drbg_dealloc_internal(struct esdm_botan_drng_state *state)
{
	if (!state)
		return;

	state->drbg.reset();
	state->initialized = false;
}

static int esdm_botan_drbg_alloc(void **drng, uint32_t sec_strength)
{
	struct esdm_botan_drng_state *state =
		new (std::nothrow) struct esdm_botan_drng_state;

	(void)sec_strength;

	if (!state)
		return -ENOMEM;

	/* the DRNG constructors can throw, e.g. Botan::Lookup_Error if the
	 * underlying primitive is not compiled into Botan; exceptions must
	 * not propagate into the C callers */
	try {
#ifdef ESDM_BOTAN_DRNG_CHACHA20
		state->drbg.reset(new Botan::ChaCha_RNG());
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			    "Botan ChaCha20 DRNG core allocated\n");
#endif
#ifdef ESDM_BOTAN_DRNG_HMAC
		state->drbg.reset(new Botan::HMAC_DRBG("SHA-512"));
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			    "Botan SP800-90A HMAC-DRBG core allocated\n");
#endif
	} catch (const std::exception &ex) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Botan DRNG allocation failed: %s\n", ex.what());
		delete state;
		return -EFAULT;
	}

	if (state->drbg == nullptr) {
		delete state;
		return -ENOMEM;
	}

	*drng = state;

	state->initialized = false;

	return 0;
}

static void esdm_botan_drbg_dealloc(void *drng)
{
	struct esdm_botan_drng_state *state =
		reinterpret_cast<esdm_botan_drng_state *>(drng);

	esdm_botan_drbg_dealloc_internal(state);

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "DRBG core zeroized and freed\n");

	delete state;
}

static const char *esdm_botan_drbg_name(void)
{
#ifdef ESDM_BOTAN_DRNG_CHACHA20
	return "Botan ChaCha20 DRNG";
#endif

#ifdef ESDM_BOTAN_DRNG_HMAC
	return "Botan SP800-90A DRBG";
#endif
}

#ifdef ESDM_BOTAN_DRNG_CHACHA20
static int esdm_botan_drbg_selftest_chacha20(void)
{
	void *drng = NULL;
	/* default to failure so an (empty) test table cannot return success */
	int ret = -EFAULT;

	static const uint8_t ent_nonce[] = {
		0xBF, 0x26, 0x84, 0xC8, 0xA6, 0x9E, 0x68, 0x6E, 0xAE, 0x68,
		0x25, 0x1F, 0x33, 0x26, 0xBA, 0x4F, 0xB0, 0x82, 0x05, 0x0C,
		0x08, 0xCF, 0x26, 0x3D, 0xA6, 0x62, 0x3F, 0x4F, 0x4C, 0x44,
		0x7F, 0x71, 0xB9, 0xDE, 0xBB, 0xA0, 0xE6, 0xDD, 0x95, 0x16,
		0x4C, 0x68, 0x4C, 0x34, 0xA1, 0x77, 0x95, 0x3F, 0x98, 0xEB,
		0xC9, 0x92, 0x8E, 0x11, 0x6F, 0xBA, 0x38, 0xE3, 0xCC, 0x9C,
		0x43, 0x77, 0x9F, 0xE1
	};
	static const uint8_t reseed[] = { 0x88, 0x7F, 0x5A, 0x5C, 0xC7, 0x46,
					  0xC2, 0x9D, 0xF8, 0xD1, 0x62, 0xB4,
					  0x4F, 0x16, 0x1C, 0x77, 0x32, 0x18,
					  0xE0, 0xC2, 0xE8, 0x27, 0x60, 0x1A,
					  0x82, 0x4B, 0x0F, 0x68, 0x3C, 0x61,
					  0x40, 0x11 };

	CKINT(esdm_botan_drbg_alloc(&drng, 256));
	CKINT(esdm_botan_drbg_seed(drng, ent_nonce, sizeof(ent_nonce), NULL,
				   0));
	CKINT(esdm_botan_drbg_seed(drng, reseed, sizeof(reseed), NULL, 0));

	static const uint8_t exp[] = {
		0xb2, 0xe0, 0x1c, 0x33, 0xf7, 0x38, 0xd8, 0x34, 0xb9, 0xc8,
		0xf2, 0x72, 0xcf, 0x05, 0x4e, 0x8a, 0x77, 0x10, 0x93, 0x7d,
		0xa6, 0xcc, 0xeb, 0xd2, 0x94, 0x11, 0x4d, 0x51, 0x5e, 0x8f,
		0x76, 0xc4, 0x77, 0x94, 0x02, 0x5b, 0xdf, 0x55, 0x71, 0xea,
		0xd7, 0x3d, 0x9f, 0xad, 0xc0, 0x44, 0x6c, 0xc6, 0x13, 0x20,
		0x35, 0x4c, 0xa8, 0x38, 0x6f, 0x0f, 0x4c, 0x42, 0xd6, 0xb6,
		0xf1, 0x54, 0x96, 0xf2, 0xbb, 0x7c, 0xd3, 0xbe, 0xdd, 0x2f,
		0xb5, 0xcc, 0xa8, 0xb3, 0x49, 0x83, 0x1f, 0xda, 0x23, 0x0d,
		0x7a, 0x52, 0x23, 0xc8, 0xd7, 0x0b, 0x73, 0xf3, 0x3f, 0x59,
		0xde, 0xe1, 0xf1, 0x05, 0xad, 0x7b, 0x60, 0xe1, 0xaf, 0x52,
		0xd7, 0xad, 0xdc, 0xd3, 0x8a, 0x7c, 0x46, 0xd8, 0x57, 0xb9,
		0x60, 0xed, 0x2a, 0x0d, 0x6b, 0x68, 0xae, 0xdb, 0xd3, 0xe0,
		0xf4, 0xa3, 0xcf, 0x3e, 0xdb, 0x53, 0x62, 0x02,
	};
	uint8_t act[sizeof(exp)];
	uint8_t mod[sizeof(ent_nonce)];

	if (esdm_botan_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	if (esdm_botan_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	CKINT(esdm_kat_check(act, exp, sizeof(exp)));

	/* Seed material off by its first byte must not produce that output. */
	esdm_botan_drbg_dealloc(drng);
	drng = NULL;
	CKINT(esdm_kat_modify(mod, ent_nonce, sizeof(mod)));

	CKINT(esdm_botan_drbg_alloc(&drng, 256));
	CKINT(esdm_botan_drbg_seed(drng, mod, sizeof(mod), NULL, 0));
	CKINT(esdm_botan_drbg_seed(drng, reseed, sizeof(reseed), NULL, 0));

	if (esdm_botan_drbg_generate(drng, act, sizeof(act)) != sizeof(act) ||
	    esdm_botan_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	ret = esdm_kat_check_differs(act, exp, sizeof(exp));

out:
	esdm_botan_drbg_dealloc(drng);
	return ret;
}
#endif

#ifdef ESDM_BOTAN_DRNG_HMAC
/* we need to use test vectors with personalization strings,
 * otherwise Botan receive's too short seeds.
 * They have to be at least OutLen(HMAC_SHA512) = 512 long.
 */
struct nist_test_vector_hmac_drbg {
	const uint8_t *entropy;
	const uint8_t *nonce;
	const uint8_t *personalization_string;
	const uint8_t *returned_bits;
	const uint8_t *additional_input_1;
	const uint8_t *additional_input_2;
	/*
	 * Entropy of a reseed between the instantiation and the two generate
	 * calls, nullptr for the records that do not reseed.
	 */
	const uint8_t *reseed;
};

#define HMAC_TEST_VECTOR(IDX)                                                  \
	{                                                                      \
		.entropy = entropy_##IDX,                                      \
		.nonce = nonce_##IDX,                                          \
		.personalization_string = personalization_string_##IDX,        \
		.returned_bits = returned_bits_##IDX,                          \
		.additional_input_1 = nullptr,                                 \
		.additional_input_2 = nullptr,                                 \
		.reseed = nullptr,                                             \
	}

#define HMAC_TEST_VECTOR_AI(IDX)                                               \
	{                                                                      \
		.entropy = entropy_##IDX,                                      \
		.nonce = nonce_##IDX,                                          \
		.personalization_string = personalization_string_##IDX,        \
		.returned_bits = returned_bits_##IDX,                          \
		.additional_input_1 = additional_input_1_##IDX,                \
		.additional_input_2 = additional_input_2_##IDX,                \
		.reseed = nullptr,                                             \
	}

#define HMAC_TEST_VECTOR_RESEED(IDX)                                           \
	{                                                                      \
		.entropy = entropy_##IDX,                                      \
		.nonce = nonce_##IDX,                                          \
		.personalization_string = personalization_string_##IDX,        \
		.returned_bits = returned_bits_##IDX,                          \
		.additional_input_1 = nullptr,                                 \
		.additional_input_2 = nullptr,                                 \
		.reseed = reseed_##IDX,                                        \
	}

static int esdm_botan_drbg_selftest_hmac()
{
	void *drng = NULL;
	uint8_t seed_material[32 + 16 + 32];
	uint8_t mod_seed[sizeof(seed_material)];
	uint8_t act[256];
	/* default to failure so an (empty) test table cannot return success */
	int ret = -EFAULT;

	/*
	 * Taken from NIST SP800-90A DRBG Test Vectors
	 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
	 * -> drbgvectors_no_reseed.zip -> SHA-512 with personalization string,
	 * COUNT = 0.
	 */
	static const uint8_t entropy_1[] = { 0xf8, 0x56, 0x49, 0xf8, 0xa8, 0xc0,
					     0x1f, 0x8a, 0x29, 0x25, 0xf7, 0xe9,
					     0x3e, 0x35, 0x6b, 0xe0, 0xfb, 0xc7,
					     0x52, 0x06, 0xd1, 0xce, 0x2f, 0x7e,
					     0x04, 0xa1, 0x42, 0x57, 0xc3, 0x33,
					     0x8a, 0x48 };
	static const uint8_t nonce_1[] = { 0x01, 0xa8, 0x84, 0x3b, 0x7a, 0x3d,
					   0xc0, 0xb1, 0xca, 0xb5, 0xf7, 0xc8,
					   0xb0, 0x01, 0x59, 0x8d };
	static const uint8_t personalization_string_1[] = {
		0x91, 0x02, 0x2d, 0x07, 0x28, 0x24, 0xcb, 0x58,
		0x0a, 0xc0, 0x75, 0x55, 0xc9, 0x0a, 0x31, 0x37,
		0x3f, 0x2d, 0xfc, 0x27, 0x2d, 0xe6, 0x0d, 0x3b,
		0xdb, 0xc0, 0x61, 0x2e, 0x17, 0x58, 0x74, 0xab
	};
	static const uint8_t returned_bits_1[] = {
		0x9f, 0x40, 0xaf, 0xfd, 0xa9, 0xc7, 0x97, 0x36, 0x3a, 0x7b,
		0x05, 0x8d, 0x7f, 0x5b, 0x84, 0x8f, 0x0b, 0xa3, 0x66, 0x80,
		0x8e, 0x7a, 0x87, 0xec, 0x94, 0x89, 0x40, 0x91, 0xca, 0x08,
		0x18, 0xdc, 0x38, 0x7a, 0x8a, 0xb2, 0x49, 0xaf, 0x32, 0x68,
		0xa9, 0xb0, 0xc9, 0x5f, 0x7a, 0x78, 0x1d, 0x3c, 0x7b, 0xa6,
		0x13, 0x46, 0x0a, 0x2a, 0x5f, 0x8e, 0xe4, 0xbf, 0x9e, 0xd2,
		0x37, 0xaf, 0xae, 0xf6, 0x9f, 0x04, 0x6e, 0x16, 0x37, 0x99,
		0x79, 0x42, 0x52, 0xd2, 0xc9, 0x70, 0x8e, 0xa3, 0x37, 0xb8,
		0xbc, 0xc6, 0x74, 0xc5, 0x01, 0x61, 0x72, 0xc5, 0x0d, 0x6d,
		0xe9, 0xd9, 0x41, 0xf4, 0x96, 0xcb, 0xde, 0x4a, 0x4e, 0x7a,
		0xbc, 0xdf, 0xd4, 0x2a, 0x98, 0x91, 0x19, 0x22, 0x4e, 0xa7,
		0xf3, 0xc4, 0x72, 0x71, 0x79, 0xf4, 0x2b, 0xbb, 0x54, 0x46,
		0x6f, 0x53, 0x0e, 0x43, 0x94, 0xcf, 0x18, 0xc1, 0x5b, 0x54,
		0x8c, 0xa6, 0x10, 0x51, 0x18, 0x00, 0xb3, 0x9d, 0xa6, 0x92,
		0x97, 0xa4, 0x6e, 0xd1, 0xb2, 0x37, 0x72, 0x2c, 0x6d, 0x50,
		0x24, 0x82, 0x45, 0xf7, 0xe9, 0x0f, 0x34, 0x36, 0x17, 0xac,
		0xa4, 0x4b, 0x62, 0x45, 0xc9, 0x9a, 0x71, 0x4f, 0x71, 0x9e,
		0x32, 0x4c, 0x2f, 0xd4, 0xb9, 0x5e, 0x84, 0xb3, 0xf7, 0xd3,
		0x21, 0x29, 0x86, 0xdd, 0x7f, 0x51, 0xf6, 0x0e, 0x38, 0xd1,
		0xa0, 0x77, 0x39, 0x8f, 0x5a, 0xf3, 0x1a, 0xda, 0xe8, 0x64,
		0x7b, 0xc9, 0x20, 0xe6, 0xa0, 0xc8, 0x65, 0xa2, 0x97, 0xbf,
		0xfc, 0x88, 0xb4, 0x07, 0xa2, 0x4e, 0x2d, 0x2a, 0xea, 0xd0,
		0xe7, 0x11, 0xfc, 0xf9, 0x6b, 0x83, 0xbb, 0xed, 0xe5, 0xbb,
		0x35, 0xa5, 0xf9, 0xb0, 0xdc, 0x5e, 0x23, 0x76, 0xa6, 0x93,
		0xaf, 0xa9, 0x07, 0x0a, 0x4b, 0x1a, 0xa8, 0x6d, 0xec, 0x23,
		0xe6, 0xe5, 0x97, 0xa7, 0x42, 0x37
	};
	/*
	 * The record carrying additional input into both generate calls, from
	 * the same file with AdditionalInputLen = 256.
	 */
	static const uint8_t entropy_2[] = { 0x09, 0xbc, 0x30, 0x30, 0xbe, 0x92,
					     0x04, 0x35, 0xcf, 0x5d, 0x5c, 0x81,
					     0x3f, 0xb2, 0x50, 0xbe, 0x9a, 0xc3,
					     0x28, 0x72, 0xc8, 0x3d, 0x96, 0x35,
					     0xdd, 0xcc, 0x38, 0x29, 0x13, 0x7d,
					     0x1d, 0x9a };
	static const uint8_t nonce_2[] = { 0x43, 0xe5, 0x77, 0xbb, 0xdc, 0x08,
					   0x4d, 0x4d, 0x03, 0x32, 0xc3, 0x11,
					   0x04, 0xeb, 0x2e, 0x4b };
	static const uint8_t personalization_string_2[] = {
		0x39, 0xf8, 0xde, 0x35, 0x16, 0x1a, 0x25, 0x09,
		0xa4, 0x07, 0x7c, 0xf9, 0xf9, 0x2e, 0xb6, 0x53,
		0x60, 0x38, 0x20, 0xdb, 0x6f, 0xa8, 0x64, 0x91,
		0x55, 0x3c, 0xae, 0xeb, 0x9a, 0xd4, 0x6c, 0xff
	};
	static const uint8_t returned_bits_2[] = {
		0x9d, 0x5e, 0xd4, 0xdf, 0xf9, 0x96, 0x2d, 0x28, 0x0c, 0x18,
		0xeb, 0x64, 0x99, 0x64, 0xc9, 0x60, 0xc8, 0x97, 0xca, 0x19,
		0x98, 0x02, 0xc9, 0x18, 0x62, 0x45, 0xf9, 0x87, 0xae, 0xa9,
		0x7d, 0x9a, 0x62, 0x31, 0x2e, 0xa5, 0xd8, 0xf6, 0xa6, 0x76,
		0xf6, 0xc7, 0x2f, 0xeb, 0xde, 0xe2, 0x32, 0x25, 0x7b, 0xc2,
		0xbd, 0x40, 0x07, 0x5a, 0xf9, 0x35, 0xd7, 0xdc, 0x62, 0xd9,
		0x88, 0xc8, 0xc0, 0x3f, 0x6d, 0x27, 0x6b, 0x1e, 0x8b, 0x74,
		0x49, 0x61, 0x88, 0xee, 0x82, 0x3c, 0xd4, 0x4b, 0xad, 0x8b,
		0xb0, 0x87, 0xdf, 0x4c, 0xb7, 0xc9, 0x0b, 0x94, 0xb9, 0x34,
		0x40, 0xbf, 0x5d, 0xcc, 0xbd, 0x11, 0x19, 0x37, 0x22, 0x16,
		0x98, 0xc1, 0x46, 0x93, 0xd2, 0xa1, 0x23, 0x65, 0x13, 0xdf,
		0x27, 0x11, 0x40, 0xbc, 0xf8, 0xaf, 0x22, 0xb5, 0x88, 0x4e,
		0x3d, 0x11, 0x68, 0x47, 0xc6, 0x3d, 0xce, 0x91, 0x01, 0xe2,
		0x76, 0x03, 0xd4, 0x8f, 0x8d, 0x94, 0x42, 0x1b, 0x92, 0xaa,
		0x38, 0x54, 0x7d, 0x12, 0xfd, 0x7a, 0xa4, 0x90, 0x26, 0x7d,
		0xbb, 0xb7, 0xca, 0x14, 0x2a, 0xb3, 0x92, 0xf4, 0xf0, 0xa5,
		0x95, 0x53, 0xba, 0x95, 0xba, 0x1c, 0x37, 0x0c, 0x2a, 0x55,
		0xaf, 0x5d, 0x63, 0xcf, 0xce, 0x6b, 0xb6, 0x18, 0x29, 0x45,
		0xea, 0xaf, 0xc5, 0x37, 0x6c, 0x11, 0x7b, 0x06, 0xe9, 0x9a,
		0x4f, 0x1e, 0xcc, 0x36, 0xa0, 0xa8, 0x68, 0x2d, 0x66, 0xe9,
		0xea, 0xdf, 0xfc, 0x15, 0x67, 0xb7, 0x58, 0xee, 0xc1, 0xb4,
		0xe3, 0xbd, 0xed, 0x98, 0x2c, 0x09, 0x7a, 0xef, 0x4f, 0xb5,
		0x79, 0x9c, 0xc6, 0x59, 0xa2, 0x62, 0x3f, 0xfc, 0x8f, 0xb6,
		0x9f, 0x52, 0x58, 0x08, 0x3d, 0x42, 0x32, 0x43, 0x44, 0xe6,
		0x15, 0x09, 0xaa, 0x29, 0xce, 0xa4, 0x8c, 0xc3, 0xc3, 0xe1,
		0x44, 0x9b, 0x01, 0xcf, 0x77, 0x32
	};
	static const uint8_t additional_input_1_2[] = {
		0x3d, 0x97, 0xfd, 0x3f, 0x3b, 0xc2, 0x7d, 0x28,
		0x06, 0xa4, 0x41, 0xe0, 0xc3, 0x00, 0xf3, 0x6e,
		0x04, 0x54, 0x2a, 0x4b, 0x9c, 0x34, 0x64, 0x21,
		0x17, 0x67, 0x67, 0x0e, 0xba, 0x8f, 0x97, 0x0b
	};
	static const uint8_t additional_input_2_2[] = {
		0xbb, 0xb6, 0x5d, 0xf7, 0x91, 0xd2, 0x10, 0x0a,
		0x6b, 0x81, 0xb3, 0x5f, 0x23, 0xc2, 0x7c, 0x1e,
		0xd3, 0x74, 0xde, 0x5c, 0xf6, 0x15, 0x7c, 0xe9,
		0xba, 0xd2, 0x83, 0x4d, 0x2a, 0x75, 0x7c, 0x63
	};

	/*
	 * The table is static, so it is built once and keeps its pointers for
	 * the life of the process. Every array it points at must be static as
	 * well - an automatic one leaves the table pointing into a stack frame
	 * that is gone by the second call, so every self test after the first
	 * compares whatever has since been written over that frame.
	 */

	/*
	 * The record that reseeds, from drbgvectors_pr_false/HMAC_DRBG.rsp,
	 * [SHA-512] with PredictionResistance = False, PersonalizationStringLen
	 * = 256, AdditionalInputLen = 0 and ReturnedBitsLen = 2048, COUNT = 0.
	 */
	static const uint8_t entropy_3[] = {
		0x97, 0xae, 0xf9, 0x35, 0xea, 0x33, 0x71, 0x7e,
		0x8e, 0x86, 0x44, 0xbb, 0x8c, 0x47, 0x89, 0xf3,
		0x75, 0xc4, 0x8a, 0x94, 0x5d, 0xed, 0x08, 0x77,
		0x11, 0x49, 0xe8, 0x28, 0xa2, 0x2d, 0xc8, 0x66
	};
	static const uint8_t nonce_3[] = { 0x82, 0x58, 0x0f, 0x51, 0x07, 0x0b,
					    0xa1, 0xe9, 0x91, 0xd9, 0x80, 0x3f,
					    0x51, 0xfd, 0x9a, 0x6f };
	static const uint8_t personalization_string_3[] = {
		0x21, 0x23, 0x00, 0xf9, 0x38, 0x99, 0xff, 0x7c,
		0xb1, 0x44, 0xf2, 0x04, 0x26, 0x02, 0x8b, 0x97,
		0x63, 0x80, 0xa3, 0x48, 0x25, 0x3b, 0xcc, 0x3f,
		0xf4, 0x2b, 0x52, 0x8c, 0xd1, 0x97, 0x25, 0x49
	};
	static const uint8_t reseed_3[] = { 0x63, 0xcd, 0x91, 0xc1, 0xeb, 0xb2,
					     0xca, 0xa1, 0x5f, 0x28, 0x37, 0xdf,
					     0x8f, 0x35, 0xcb, 0xb6, 0xfe, 0x96,
					     0xdf, 0x26, 0x74, 0xa1, 0x36, 0x99,
					     0x0a, 0x59, 0x76, 0xcb, 0xba, 0xb6,
					     0x3b, 0xc1 };
	static const uint8_t returned_bits_3[] = {
		0x0e, 0x85, 0x33, 0xf6, 0x4b, 0x60, 0xc2, 0x3a, 0x26, 0x55,
		0x82, 0x70, 0x37, 0xdb, 0x21, 0x8c, 0x2f, 0xe9, 0xce, 0x43,
		0x0f, 0xa4, 0xed, 0x6e, 0xd9, 0xbe, 0x34, 0x9c, 0x4b, 0xdc,
		0x6f, 0x40, 0x01, 0x8b, 0x42, 0xf4, 0x86, 0xfa, 0x04, 0x28,
		0x8b, 0x3b, 0x0c, 0x62, 0xa1, 0x28, 0x12, 0xe7, 0x6e, 0x08,
		0xc7, 0x60, 0x62, 0xa5, 0x10, 0xcc, 0x60, 0x84, 0x1f, 0x16,
		0x58, 0x69, 0xef, 0xac, 0xee, 0xf9, 0x08, 0x05, 0xbd, 0xde,
		0x2f, 0xd6, 0x6c, 0x36, 0xc3, 0x8a, 0x2a, 0xc9, 0xc3, 0xcb,
		0x86, 0xbf, 0xd3, 0x04, 0x06, 0x56, 0x9e, 0x0a, 0xfd, 0x24,
		0x51, 0x02, 0xf2, 0xea, 0x2d, 0x49, 0xe4, 0xee, 0x5f, 0x69,
		0x18, 0x72, 0x27, 0xa3, 0xf0, 0xed, 0xfb, 0xc1, 0x25, 0x9c,
		0xb6, 0x56, 0x4a, 0x2d, 0x4e, 0x82, 0x9b, 0x3f, 0xc3, 0xb6,
		0x99, 0x6e, 0x37, 0x54, 0x6f, 0x1d, 0x8a, 0x16, 0xfc, 0xd8,
		0x20, 0x1d, 0x1a, 0xd2, 0x86, 0x61, 0xbb, 0xb0, 0x01, 0x2d,
		0xaa, 0xd5, 0x5d, 0x54, 0x03, 0xe8, 0x33, 0xd8, 0xa0, 0x06,
		0x8d, 0x21, 0x6c, 0x87, 0x9b, 0xce, 0xbc, 0x05, 0x4d, 0xf0,
		0xc9, 0xcb, 0xa1, 0x4d, 0xad, 0x48, 0x63, 0xee, 0x1f, 0x75,
		0xb7, 0x8b, 0xc4, 0x88, 0x66, 0x2c, 0xb0, 0xc9, 0x1c, 0xa4,
		0xfd, 0xfc, 0xe7, 0xdf, 0x59, 0x16, 0xb4, 0xe6, 0x25, 0x80,
		0x90, 0x2c, 0x60, 0x1b, 0xe7, 0x06, 0xdc, 0xc7, 0x90, 0x38,
		0x58, 0xe6, 0xb9, 0x92, 0x07, 0x35, 0xbd, 0xaa, 0x63, 0x5a,
		0xdd, 0x5c, 0x06, 0x08, 0x0d, 0x82, 0x26, 0x53, 0x45, 0xb4,
		0x90, 0x37, 0xa3, 0x2f, 0xcf, 0x0a, 0x7c, 0x9e, 0xa6, 0x06,
		0x9e, 0x33, 0x69, 0xf9, 0xb4, 0xaa, 0x45, 0x49, 0x3e, 0xfd,
		0x73, 0x18, 0xda, 0x2a, 0xe9, 0xb4, 0xfc, 0x30, 0x04, 0x98,
		0x24, 0x8a, 0xfa, 0xad, 0x8d, 0x49
	};

	/*
	 * One record per shape the loop below can drive rather than every
	 * record of the NIST file: the self tests are repeated on their
	 * interval for as long as the ESDM runs, so what they cost is paid over
	 * and over, while a record that differs from another only in its values
	 * covers no line the other does not.
	 */
	static struct nist_test_vector_hmac_drbg test_vectors[] = {
		HMAC_TEST_VECTOR(1),
		HMAC_TEST_VECTOR_AI(2),
		HMAC_TEST_VECTOR_RESEED(3),
	};

	for (size_t i = 0;
	     i < sizeof(test_vectors) / sizeof(nist_test_vector_hmac_drbg);
	     ++i) {
		const size_t entropy_size = 32;
		const size_t nonce_size = 16;
		const size_t pers_size = 32;
		const size_t result_size = 256;
		const size_t additonal_input_len = 32;
		size_t seed_material_size =
			entropy_size + nonce_size + pers_size;
		size_t offset = 0;

		static_assert(sizeof(seed_material) ==
			      entropy_size + nonce_size + pers_size);
		static_assert(sizeof(act) == result_size);

		memcpy(seed_material + offset, test_vectors[i].entropy,
		       entropy_size);
		offset += entropy_size;
		memcpy(seed_material + offset, test_vectors[i].nonce,
		       nonce_size);
		offset += nonce_size;
		memcpy(seed_material + offset,
		       test_vectors[i].personalization_string, pers_size);
		offset += pers_size;

		CKINT(esdm_botan_drbg_alloc(&drng, 256));
		/*
		 * No additional data on the seeding call: the vector's
		 * personalization string is already concatenated into
		 * seed_material above, as SP800-90A instantiation expects.
		 */
		CKINT(esdm_botan_drbg_seed(drng, seed_material,
					   seed_material_size, NULL, 0));
		if (test_vectors[i].reseed) {
			CKINT(esdm_botan_drbg_seed(drng, test_vectors[i].reseed,
						   entropy_size, NULL, 0));
		}
		if (esdm_botan_drbg_generate_w_additional_data(
			    drng, act, result_size,
			    test_vectors[i].additional_input_1,
			    test_vectors[i].additional_input_1 ?
				    additonal_input_len :
				    0) != (ssize_t)result_size) {
			ret = -EFAULT;
			goto out;
		}
		if (esdm_botan_drbg_generate_w_additional_data(
			    drng, act, result_size,
			    test_vectors[i].additional_input_2,
			    test_vectors[i].additional_input_2 ?
				    additonal_input_len :
				    0) != (ssize_t)result_size) {
			ret = -EFAULT;
			goto out;
		}
		ret = esdm_kat_check(act, test_vectors[i].returned_bits,
				     result_size);
		if (ret)
			goto out;
		esdm_botan_drbg_dealloc(drng);
		drng = NULL;

		/*
		 * Seed material off by its first byte must not produce that
		 * output - from a DRNG instantiated afresh for it, as the one
		 * above is past the state the known answer belongs to.
		 */
		CKINT(esdm_kat_modify(mod_seed, seed_material,
				      seed_material_size));

		CKINT(esdm_botan_drbg_alloc(&drng, 256));
		CKINT(esdm_botan_drbg_seed(drng, mod_seed, seed_material_size,
					   NULL, 0));
		if (test_vectors[i].reseed) {
			CKINT(esdm_botan_drbg_seed(drng, test_vectors[i].reseed,
						   entropy_size, NULL, 0));
		}
		if (esdm_botan_drbg_generate_w_additional_data(
			    drng, act, result_size,
			    test_vectors[i].additional_input_1,
			    test_vectors[i].additional_input_1 ?
				    additonal_input_len :
				    0) != (ssize_t)result_size ||
		    esdm_botan_drbg_generate_w_additional_data(
			    drng, act, result_size,
			    test_vectors[i].additional_input_2,
			    test_vectors[i].additional_input_2 ?
				    additonal_input_len :
				    0) != (ssize_t)result_size) {
			ret = -EFAULT;
			goto out;
		}
		ret = esdm_kat_check_differs(act, test_vectors[i].returned_bits,
					     result_size);
		if (ret)
			goto out;
		esdm_botan_drbg_dealloc(drng);
		drng = NULL;
	}

out:
	esdm_botan_drbg_dealloc(drng);

	return ret;
}
#endif

static int esdm_botan_drbg_selftest(void)
{
#ifdef ESDM_BOTAN_DRNG_CHACHA20
	return esdm_botan_drbg_selftest_chacha20();
#endif

#ifdef ESDM_BOTAN_DRNG_HMAC
	return esdm_botan_drbg_selftest_hmac();
#endif
}

const struct esdm_drng_cb esdm_botan_drbg_cb = {
	.drng_name = esdm_botan_drbg_name,
	.drng_selftest = esdm_botan_drbg_selftest,
	.drng_alloc = esdm_botan_drbg_alloc,
	.drng_dealloc = esdm_botan_drbg_dealloc,
	.drng_seed = esdm_botan_drbg_seed,
	.drng_generate = esdm_botan_drbg_generate,
};
