/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
#include <botan/hmac_drbg.h>

#include "esdm_crypto.h"
#include "esdm_botan.h"
#include "logger.h"
#include "ret_checkers.h"

static const std::string DEFAULT_BOTAN_HASH{"SHA-3(512)"};

/* introduced, as Botan only exposes unique_ptr for its digests */
struct esdm_botan_hash_ctx {
    std::unique_ptr<Botan::HashFunction> hash_fn;
};

static uint32_t esdm_botan_hash_digestsize(void *hash)
{
	(void) hash;
	return 512 / 8;
}

static int esdm_botan_hash_init(void *hash)
{
	struct esdm_botan_hash_ctx *ctx = reinterpret_cast<esdm_botan_hash_ctx *>(hash);
    
    try {
        ctx->hash_fn = Botan::HashFunction::create_or_throw(DEFAULT_BOTAN_HASH);
    } catch(const Botan::Lookup_Error& ex) {
        logger(LOGGER_ERR, LOGGER_C_MD, "Botan::HashFunction::create() failed %s\n",
		       ex.what());
		return -EFAULT;
    }

	return 0;
}

static int
esdm_botan_hash_update(void *hash, const uint8_t *inbuf, size_t inbuflen)
{
	struct esdm_botan_hash_ctx *ctx = reinterpret_cast<esdm_botan_hash_ctx *>(hash);
	
    ctx->hash_fn->update(inbuf, inbuflen);

	return 0;
}

static int esdm_botan_hash_final(void *hash, uint8_t *digest)
{
	struct esdm_botan_hash_ctx *ctx = reinterpret_cast<esdm_botan_hash_ctx *>(hash);
	
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
	struct esdm_botan_hash_ctx *ctx = reinterpret_cast<esdm_botan_hash_ctx *>(hash);

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
	static const uint8_t exp_512[] = { 0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5,
					   0x0A, 0x67, 0xFE, 0x69, 0xBD, 0x3F,
					   0xCE, 0xFE, 0x12, 0xE7, 0x1D, 0xE0,
					   0x4F, 0xA2, 0x51, 0xC6, 0x7E, 0x9C,
					   0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC,
					   0x89, 0xCA, 0x9B, 0x28, 0x88, 0x3B,
					   0x2A, 0xDB, 0x22, 0x84, 0x69, 0x5D,
					   0xD0, 0x43, 0x77, 0x55, 0x32, 0x19,
					   0xC8, 0xFD, 0x07, 0xA9, 0x4C, 0x29,
					   0xD7, 0x46, 0xCC, 0xEF, 0xB1, 0x09,
					   0x6E, 0xDE, 0x42, 0x91 };
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
	.hash_name		= esdm_botan_hash_name,
	.hash_selftest		= esdm_botan_hash_selftest,
	.hash_digestsize	= esdm_botan_hash_digestsize,
	.hash_init		= esdm_botan_hash_init,
	.hash_update		= esdm_botan_hash_update,
	.hash_final		= esdm_botan_hash_final,
	.hash_desc_zero		= esdm_botan_hash_desc_zero,
	.hash_alloc		= esdm_botan_hash_alloc,
	.hash_dealloc		= esdm_botan_hash_dealloc,
};

struct esdm_botan_drng_state {
	std::unique_ptr<Botan::HMAC_DRBG> drbg;
};

static int esdm_botan_drbg_seed(void *drng, const uint8_t *inbuf,
				     size_t inbuflen)
{
    struct esdm_botan_drng_state *state = reinterpret_cast<esdm_botan_drng_state *>(drng);

	state->drbg->add_entropy(inbuf, inbuflen);

	return 0;
}

static ssize_t esdm_botan_drbg_generate(void *drng, uint8_t *outbuf,
					  size_t outbuflen)
{
	struct esdm_botan_drng_state *state = reinterpret_cast<esdm_botan_drng_state *>(drng);

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

	state->drbg.reset(new Botan::HMAC_DRBG("SHA-512"));

	*drng = state;
	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "DRBG core allocated\n");

	if (state->drbg == nullptr) {
		esdm_botan_drbg_dealloc_internal(state);
		return -1;
	}

	return 0;
}

static void esdm_botan_drbg_dealloc(void *drng)
{
	struct esdm_botan_drng_state *state = reinterpret_cast<esdm_botan_drng_state *>(drng);

	esdm_botan_drbg_dealloc_internal(state);

	logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			"DRBG core zeroized and freed\n");

	delete state;
}

static const char *esdm_botan_drbg_name(void)
{
	return "Botan SP800-90A DRBG";
}

static int esdm_botan_drbg_selftest(void)
{
	static const uint8_t ent_nonce[] = {
		0xDD, 0x3D, 0xC1, 0x24, 0x6B, 0xD1, 0xD5, 0xF1,
		0xAA, 0xF7, 0xAA, 0xF2, 0xD5, 0xA8, 0x6D, 0x94,
		0xA4, 0xE1, 0xF7, 0x0C, 0x20, 0x7D, 0x75, 0xE3,
		0x23, 0x44, 0x29, 0x64, 0xD4, 0xDF, 0xDC, 0xE8,
		0x22, 0xFF, 0xD9, 0x57, 0x8E, 0xE3, 0x35, 0xE5,
		0x3E, 0x5D, 0x76, 0x36, 0x41, 0x32, 0x37, 0x8B,
		0xE3, 0x7F, 0x7A, 0xE2, 0x40, 0x09, 0x4B, 0xF9,
		0xCC, 0x9A, 0xAD, 0x74, 0xA5, 0x21, 0x4F, 0xE4
	};
	static const uint8_t reseed[] = {
		0x4F, 0x4C, 0xDE, 0xAE, 0xC6, 0xDC, 0x6D, 0xDB,
		0x8B, 0x9B, 0x5F, 0xB6, 0xED, 0x6F, 0x3E, 0xF5,
		0xFE, 0x82, 0x54, 0x82, 0x09, 0x9F, 0x31, 0xBC,
		0xEC, 0x88, 0x01, 0xD8, 0xAD, 0x61, 0x8C, 0x0A
	};
	static const uint8_t exp[] = {
		0x18, 0x6e, 0xc4, 0x3e, 0x05, 0x95, 0xf6, 0xb1,
		0x81, 0xf2, 0x85, 0x78, 0x5c, 0x45, 0x65, 0x90,
		0x28, 0xd2, 0x2f, 0xc2, 0xe6, 0xc3, 0x0b, 0x6e,
		0xb8, 0x77, 0xa0, 0x1b, 0xb0, 0xbe, 0xc6, 0x21,
		0xfa, 0x94, 0x18, 0xff, 0x6e, 0xe2, 0x99, 0x29,
		0x1f, 0x97, 0x83, 0xb8, 0x8e, 0x3d, 0x8c, 0x71,
		0xe6, 0x6c, 0xfb, 0x0c, 0xf5, 0x4f, 0xf0, 0x75,
		0x14, 0x58, 0x45, 0x6c, 0x79, 0x9a, 0xa7, 0x78,
		0x4f, 0xfe, 0x1c, 0x01, 0xf6, 0xc2, 0xe6, 0xa2,
		0x76, 0x49, 0x97, 0xf6, 0xf1, 0x8b, 0x9c, 0x35,
		0xaa, 0x68, 0x95, 0x44, 0x15, 0xce, 0x67, 0xa0,
		0xa6, 0xfd, 0x3c, 0xcc, 0xad, 0x2b, 0xd7, 0xdb,
		0xa3, 0xf7, 0x71, 0xce, 0x17, 0xca, 0xa6, 0x2f,
		0x16, 0x6a, 0x81, 0x3f, 0xbc, 0x3a, 0x15, 0x91,
		0x20, 0x58, 0xe8, 0x98, 0xbb, 0x7e, 0x46, 0xbc,
		0xfe, 0x50, 0x82, 0x1a, 0xdf, 0xaa, 0xf1, 0x78
	};
	uint8_t act[sizeof(exp)];
	void *drng = NULL;
	int ret;

	CKINT(esdm_botan_drbg_alloc(&drng, 256));
	CKINT(esdm_botan_drbg_seed(drng, ent_nonce, sizeof(ent_nonce)));
	CKINT(esdm_botan_drbg_seed(drng, reseed, sizeof(reseed)));
	if (esdm_botan_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	if (esdm_botan_drbg_generate(drng, act, sizeof(act)) != sizeof(act)) {
		ret = -EFAULT;
		goto out;
	}

	if (!memcmp(act, exp, sizeof(exp))) {
		ret = -EFAULT;
	}

out:
	esdm_botan_drbg_dealloc(drng);
	return ret;
}

const struct esdm_drng_cb esdm_botan_drbg_cb = {
	.drng_name	= esdm_botan_drbg_name,
	.drng_selftest	= esdm_botan_drbg_selftest,
	.drng_alloc	= esdm_botan_drbg_alloc,
	.drng_dealloc	= esdm_botan_drbg_dealloc,
	.drng_seed	= esdm_botan_drbg_seed,
	.drng_generate	= esdm_botan_drbg_generate,
};
