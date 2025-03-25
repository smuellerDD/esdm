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

#include <errno.h>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <cassert>
#include <botan/hash.h>
#include <botan/exceptn.h>

#include "esdm_crypto.h"
#include "esdm_botan.h"
#include "esdm_logger.h"
#include "ret_checkers.h"

#include "config.h"

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
	} catch (const Botan::Lookup_Error &ex) {
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

	ctx->hash_fn->update(inbuf, inbuflen);

	return 0;
}

static int esdm_botan_hash_final(void *hash, uint8_t *digest)
{
	struct esdm_botan_hash_ctx *ctx =
		reinterpret_cast<esdm_botan_hash_ctx *>(hash);

	ctx->hash_fn->final(digest);

	return 0;
}

static int esdm_botan_hash_alloc(void **hash)
{
	struct esdm_botan_hash_ctx *tmp;
	struct esdm_botan_hash_ctx **ctx = (struct esdm_botan_hash_ctx **)hash;

	tmp = new struct esdm_botan_hash_ctx;
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

static int esdm_botan_hash_selftest(void)
{
	static const uint8_t msg_512[] = { 0x82, 0xD9, 0x19 };
	static const uint8_t exp_512[] = {
		0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5, 0x0A, 0x67, 0xFE, 0x69,
		0xBD, 0x3F, 0xCE, 0xFE, 0x12, 0xE7, 0x1D, 0xE0, 0x4F, 0xA2,
		0x51, 0xC6, 0x7E, 0x9C, 0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC,
		0x89, 0xCA, 0x9B, 0x28, 0x88, 0x3B, 0x2A, 0xDB, 0x22, 0x84,
		0x69, 0x5D, 0xD0, 0x43, 0x77, 0x55, 0x32, 0x19, 0xC8, 0xFD,
		0x07, 0xA9, 0x4C, 0x29, 0xD7, 0x46, 0xCC, 0xEF, 0xB1, 0x09,
		0x6E, 0xDE, 0x42, 0x91
	};
	uint8_t act[sizeof(exp_512)];
	void *hash = NULL;
	int ret;

	CKINT(esdm_botan_hash_alloc(&hash));
	CKINT(esdm_botan_hash_init(hash));
	CKINT(esdm_botan_hash_update(hash, msg_512, sizeof(msg_512)));
	CKINT(esdm_botan_hash_final(hash, act));

	if (memcmp(act, exp_512, sizeof(exp_512)))
		ret = -EFAULT;

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
#ifdef ESDM_BOTAN_DRNG_CHACHA20
	std::unique_ptr<Botan::ChaCha_RNG> drbg;
#endif
#ifdef ESDM_BOTAN_DRNG_HMAC
	std::unique_ptr<Botan::HMAC_DRBG> drbg;
#endif
};

static int esdm_botan_drbg_seed(void *drng, const uint8_t *inbuf,
				size_t inbuflen)
{
	struct esdm_botan_drng_state *state =
		reinterpret_cast<esdm_botan_drng_state *>(drng);

	state->drbg->add_entropy(inbuf, inbuflen);

	return 0;
}

static ssize_t esdm_botan_drbg_generate(void *drng, uint8_t *outbuf,
					size_t outbuflen)
{
	struct esdm_botan_drng_state *state =
		reinterpret_cast<esdm_botan_drng_state *>(drng);

	state->drbg->randomize(outbuf, outbuflen);

	return (ssize_t)outbuflen;
}

static void
esdm_botan_drbg_dealloc_internal(struct esdm_botan_drng_state *state)
{
	if (!state)
		return;

	state->drbg.reset();
}

static int esdm_botan_drbg_alloc(void **drng, uint32_t sec_strength)
{
	struct esdm_botan_drng_state *state = new struct esdm_botan_drng_state;

	(void)sec_strength;

	if (!state)
		return -ENOMEM;

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

	*drng = state;
	if (state->drbg == nullptr) {
		esdm_botan_drbg_dealloc_internal(state);
		return -1;
	}

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

static int esdm_botan_drbg_selftest(void)
{
	void *drng = NULL;
	int ret;

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
	CKINT(esdm_botan_drbg_seed(drng, ent_nonce, sizeof(ent_nonce)));
	CKINT(esdm_botan_drbg_seed(drng, reseed, sizeof(reseed)));

#ifdef ESDM_BOTAN_DRNG_CHACHA20
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
#endif

#ifdef ESDM_BOTAN_DRNG_HMAC
	static const uint8_t exp[] = {
		0x70, 0x21, 0x48, 0x5f, 0x5d, 0x6c, 0x65, 0x93, 0xe8, 0xe2,
		0x6d, 0x82, 0x98, 0x5a, 0x73, 0xaa, 0x17, 0x29, 0x24, 0xff,
		0x4e, 0x3a, 0x22, 0xf3, 0x94, 0x32, 0xd0, 0xe8, 0xf3, 0x26,
		0xdd, 0xbd, 0x73, 0xe8, 0x9e, 0xfe, 0xa9, 0xe8, 0x43, 0x11,
		0x7f, 0xcb, 0x77, 0xf4, 0xee, 0xa3, 0x63, 0xb7, 0x92, 0x21,
		0x66, 0x19, 0xee, 0x8e, 0x69, 0x23, 0x93, 0xfe, 0x14, 0xbf,
		0x53, 0x92, 0x93, 0xe5, 0xc5, 0xa9, 0x9b, 0xf9, 0xbb, 0x1a,
		0xb5, 0xd2, 0x2d, 0x09, 0x78, 0xc1, 0x0a, 0x8c, 0xb5, 0x35,
		0x3a, 0xdd, 0xf2, 0x3e, 0x35, 0xc6, 0xb7, 0xa4, 0xa0, 0x5c,
		0xa4, 0x4d, 0x9f, 0x05, 0x5d, 0x44, 0x09, 0xf9, 0xe1, 0xb8,
		0x53, 0xdf, 0x06, 0x5c, 0x4d, 0x41, 0xe4, 0xe0, 0x1d, 0xfd,
		0x75, 0x1b, 0xe5, 0xea, 0x9d, 0x74, 0x07, 0xa9, 0xf7, 0x43,
		0xbf, 0x2a, 0xb4, 0x7f, 0x51, 0x40, 0xeb, 0xa8
	};
	uint8_t act[sizeof(exp)];
#endif
	if (esdm_botan_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	if (esdm_botan_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	if (memcmp(act, exp, sizeof(exp))) {
		ret = -EFAULT;
		goto out;
	}

out:
	esdm_botan_drbg_dealloc(drng);
	return ret;
}

const struct esdm_drng_cb esdm_botan_drbg_cb = {
	.drng_name = esdm_botan_drbg_name,
	.drng_selftest = esdm_botan_drbg_selftest,
	.drng_alloc = esdm_botan_drbg_alloc,
	.drng_dealloc = esdm_botan_drbg_dealloc,
	.drng_seed = esdm_botan_drbg_seed,
	.drng_generate = esdm_botan_drbg_generate,
};
