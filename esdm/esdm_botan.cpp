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
#include <errno.h>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <cassert>
#include <botan/hash.h>
#include <botan/exceptn.h>

#include "binhexbin.h"
#include "esdm_crypto.h"
#include "esdm_botan.h"
#include "esdm_logger.h"
#include "ret_checkers.h"

#include "config.h"

#include <botan/stateful_rng.h>
#include <stdint.h>
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

struct nist_test_vector_sha3 {
	size_t len; /* in bit */
	const char *msg;
	const char *md;
};

static int esdm_botan_hash_selftest(void)
{
	/*
	 * taken from NIST FIPS 202 test vectors
	 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
	 *
	 * SHA3_512ShortMsg.rsp
	 */
	static struct nist_test_vector_sha3 test_vectors[] = {
		{ .len = 0,
		  .msg = "00",
		  .md = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" },
		{ .len = 24,
		  .msg = "37d518",
		  .md = "4aa96b1547e6402c0eee781acaa660797efe26ec00b4f2e0aec4a6d10688dd64cbd7f12b3b6c7f802e2096c041208b9289aec380d1a748fdfcd4128553d781e3" },
		{ .len = 48,
		  .msg = "71a986d2f662",
		  .md = "def6aac2b08c98d56a0501a8cb93f5b47d6322daf99e03255457c303326395f765576930f8571d89c01e727cc79c2d4497f85c45691b554e20da810c2bc865ef" },
		{ .len = 112,
		  .msg = "c61a9188812ae73994bc0d6d4021",
		  .md = "069e6ab1675fed8d44105f3b62bbf5b8ff7ae804098986879b11e0d7d9b1b4cb7bc47aeb74201f509ddc92e5633abd2cbe0ddca2480e9908afa632c8c8d5af2a" }
	};

	const size_t md_len = 512 / 8;
	uint8_t act[md_len];
	void *hash = NULL;
	uint8_t *msg;
	uint8_t *md;
	int ret;

	for (size_t i = 0;
	     i < sizeof(test_vectors) / sizeof(struct nist_test_vector_sha3);
	     ++i) {
		msg = (uint8_t *)malloc(test_vectors[i].len / 8);
		md = (uint8_t *)malloc(md_len);

		hex2bin(test_vectors[i].msg, strlen(test_vectors[i].msg), msg,
			test_vectors[i].len / 8);
		hex2bin(test_vectors[i].md, strlen(test_vectors[i].md), md,
			md_len);

		CKINT(esdm_botan_hash_alloc(&hash));
		CKINT(esdm_botan_hash_init(hash));
		CKINT(esdm_botan_hash_update(hash, msg,
					     test_vectors[i].len / 8));
		CKINT(esdm_botan_hash_final(hash, act));

		if (memcmp(act, md, md_len)) {
			ret = -EFAULT;
			goto out;
		}

		esdm_botan_hash_dealloc(hash);
		hash = NULL;

		free(msg);
		free(md);
		msg = NULL;
		md = NULL;
	}

out:
	esdm_botan_hash_dealloc(hash);

	/* does nothing if already NULL */
	free(msg);
	msg = NULL;

	/* does nothing if already NULL */
	free(md);
	md = NULL;

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
				size_t inbuflen)
{
	struct esdm_botan_drng_state *state =
		reinterpret_cast<esdm_botan_drng_state *>(drng);

	if (state->initialized) {
		state->drbg->add_entropy(inbuf, inbuflen);
	} else {
		state->drbg->initialize_with(inbuf, inbuflen);
		state->initialized = true;
	}

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
	state->initialized = false;
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

#ifdef ESDM_BOTAN_DRNG_CHACHA20
static int esdm_botan_drbg_selftest_chacha20(void)
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
#endif

#ifdef ESDM_BOTAN_DRNG_HMAC
/* we need to use test vectors with personalization strings,
 * otherwise Botan receive's too short seeds.
 * They have to be at least OutLen(HMAC_SHA512) = 512 long.
 */
struct nist_test_vector_hmac_drbg {
	std::string entropy;
	std::string nonce;
	std::string personalization_string;
	std::string returned_bits;
};

static int esdm_botan_drbg_selftest_hmac()
{
	void *drng = NULL;
	uint8_t *seed_material;
	uint8_t *exp;
	uint8_t *act;
	int ret;

	/*
	 * Taken from NIST SP800-90A DRBG Test Vectors 
	 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
	 * -> drbgvectors_no_reseed.zip -> SHA-512 with personalization string
	 */
	static struct nist_test_vector_hmac_drbg test_vectors[] = {
		{
			.entropy =
				"f85649f8a8c01f8a2925f7e93e356be0fbc75206d1ce2f7e04a14257c3338a48",
			.nonce = "01a8843b7a3dc0b1cab5f7c8b001598d",
			.personalization_string =
				"91022d072824cb580ac07555c90a31373f2dfc272de60d3bdbc0612e175874ab",
			.returned_bits =
				"9f40affda9c797363a7b058d7f5b848f0ba366808e7a87ec94894091ca0818dc387a8ab249af3268a9b0c95f7a781d3c7ba613460a2a5f8ee4bf9ed237afaef69f046e163799794252d2c9708ea337b8bcc674c5016172c50d6de9d941f496cbde4a4e7abcdfd42a989119224ea7f3c4727179f42bbb54466f530e4394cf18c15b548ca610511800b39da69297a46ed1b237722c6d50248245f7e90f343617aca44b6245c99a714f719e324c2fd4b95e84b3f7d3212986dd7f51f60e38d1a077398f5af31adae8647bc920e6a0c865a297bffc88b407a24e2d2aead0e711fcf96b83bbede5bb35a5f9b0dc5e2376a693afa9070a4b1aa86dec23e6e597a74237",
		},
		{
			.entropy =
				"58b81001b76e248d9a4eab5e7371a97dd0992bd4ed6de18084b2321b8c292b30",
			.nonce = "d4e9df171d09a7b93949907ca65fd5b0",
			.personalization_string =
				"a36d996ecf48058ac850d66e56d812e8c58ec0d89a30dcf30475d3830c4a33c4",
			.returned_bits =
				"22d8e1f50c301208c5f198f29cf9f97704f2df46f662bfd7bd2883c22b49ab5d7bed1a2b6cf0c55a0aa0b695c52695b57919dbbe8381fc56e72553158e10ab59d4e682dfc3a07199876c266dcbe07735382d8ec079ab4ef5e622a2329092cde45c53f71aebe43b34990f55ad037eb33a87abbcd3ada3112ec43b9bb20b61bac549733222313de2bd91d532f1c17bc3de3fa34f7d3aebb2b59d6c8b90ce211e184fbe54ac0cb97d7a03e057a6bf69c4deb4f11cab49bcef323e9ca2eca1f4dec50a02ae1deea1d56f037d53da03da870dde13ac7a084d1e2aa4f095b3cbb1276a4f5815cde03a1ead7d5ff87fe7453cc603c0a1d1f6af1eaedec35835a6ce0c9b",
		},
		{
			.entropy =
				"aa1cfe4c9f03a9990c2dd55c0775ec36f3daf3d64873ef843692b5887b7d7a4c",
			.nonce = "70484796fff90a01cfc2168d1d0f5ed9",
			.personalization_string =
				"21b468ff6f1e92ca410177941ec0bea74990555071cb7d7fc0844fb24cefd511",
			.returned_bits =
				"72ca74671d10f6aa0607c3abf4e86f022af34cd8c32cbc274eff9bd38bcd4b79c64b09e68f44a3b1c6592b7f458f743f99a3971becf6acd974792dd5812d473891766460b028f3724036496188bfd2fae5d3bf734d2503316db5c9b408496e9d99712dec355865c240d3209c1793fcc815df057ffe555d2bbf47e7370031893aefec6ef0e71d137e16c416dbe52df3b98f280f5e6b29636d7d9bb0999139fb5e46bfec53bb22c8fd68d2a15df7d4e1a2c813ae363bf3055e6def008ae16343ded598a0c08548801189ced03e6f81b31286dd8e3eab82d648b6a9fe5aa6fa1f951789cf4f5815e10188d2d9755e04f283373ce7da806cd92935aea243d6a566f9",
		},
		{
			.entropy =
				"2625400a6130e77fa20f0b7c58cc0f9d0f22ef5ea54e5cfa6e6e648933d62322",
			.nonce = "dff0eb02fc7ce93e4be2e294a24509b4",
			.personalization_string =
				"cdb1072fd83114ef83323ccb03d702f68a550d7a0e8b153a95eb9f771a271861",
			.returned_bits =
				"4fa6071756afe972853072ba73e203773937f7d6e1dcd7982c37ef7566369e27add7889b32ed2e2c2669d00633c22d91fd98f2223789681fd3b1d93a16c2278b8e4007286dc1273e5abdce7845f87c066a59b0d8152f9c13230ce488f9cf00e7c3e1e0c3719e6087fa251e8bb4ddd3e778c6149a14db3217f172a8bfd656bfe6fe2c4960768adeca843f1f36671b722fcc62dde8b2e0c5765c6232ada6a4504b21f350786d0879408d8979e19a3aa16f0ec47df3d0836296fb88363d1fbc687bed75f14ccceafb185ce90c2b0f5cef3247f1573e822c19b1b9944204d42a6101326b127262b7023e89824a3f2d4fbc4c072ed3dbb7325e77eccc70cd82218f43",
		},
		{
			.entropy =
				"4943e0c725cba7ac3bba16d1de3444eb367129fa38d1bd6e0032ec1b3e0b767c",
			.nonce = "743775b879b22ba24d0b08ded6298ef0",
			.personalization_string =
				"1d8d1abc5f597648889bc220040cfe3bd49ad771ebf7ff2ffc9a7bb8ce2cb285",
			.returned_bits =
				"1cd45a83f0236d70908291a0cb24e8af67268ba14492c0ee4f7f736e48a3da7c5bc80a0aafb54ab028907477463d7587a11c59cf2add25aa799fc39290c2284da916790985dd1d842421a24186aec5acad4ed5e511dab8c28f2a2a0b2449d1aaeb5265e5df2e708e761a42df5304dc92dd2c10028cbdabf5f21c1cf572cb0d55c194a273c166df5dce469ddaef537b3f5e72b6ec8c3f32e2a69d90a640ed3f219832117615c209251a467f7343df9a6fb891c6646f01f896d83319bec63cfb0e36d35d5b554f08a0635c3605d51f9e7cb8c32cf69cf3cbddb02f68c321ae08cd185de20256c9c78efd667a35a3c423e6a0d83213fe0acc1a11693b641037daec",
		},
		{
			.entropy =
				"c90ef2a9a1cf4936689ec66acf771e3b0faaabbae4af866d4595d20823d04df7",
			.nonce = "624caf43c3fb18b0a9b9b7b56245ce60",
			.personalization_string =
				"ef05d14650114038c30f441f8484301d2442f6b9167f57f1f2c0a77b5c91212a",
			.returned_bits =
				"f89763a96ebbc1c4b5d5730501dd5a5910a9b907b1939442562ed880bca94724f9392d31eced9bb670cf355d5113a78f6b6993a85954c8e52d450f14815e8d25f3c5af5e0791fc9f94220994d58b7e3decdaa01993428bb597f1129c7c9a0643c413d0696df191ab0b18691c77e79d5705ed144a3b54ccb3e025f4f71d62cbbab9aca0804b15325d335a35b8ad9d06435ca2b847fcf45a2bd0afc95583cc11dd66f63596c9a81ec1244a58aee352b59cd4173e1b5b51e88f1d64ed887dc7c23efbf7ef49e34bc1324e91d17403052741dcd7e1e5a866ce3e2e424096a4c67ad818220a36a4ef8379f7650a2e49a953fe488202f1a95fb55a929b0e3261f181b7",
		},
		{
			.entropy =
				"fc9e6a14f9614e1430dfc99640633f2195e35532342ccede226e0896d0c07319",
			.nonce = "a43c19082988a2a1609150d903106415",
			.personalization_string =
				"ec6f5aea1cff91b0b798b1247a2e79bd62173d8ccdb5daf9492b3958ad82c48f",
			.returned_bits =
				"852a9d864504846fda05677c567bd9fff95221e620b8473c5e51580697ae193d7bf1f3237fd094363bef04f9231d95b8531a837ad43c7ff18d165acb2502f9e645460e06e2da19bd10c2df17ef2a6c0791921d74f72f91db4f80484f4fe3eb0aedac4e6417cef76e75c68c041be290f955a6121499842549ea9251bf892107614a1ee94110ca401c096c5a88adc4b39bfa5f821fb980b6e6455ee75cfdb8cfb31756565c3c836cc8e96b537080facd6c4c38c5d15c405e904a9d708e92a626cec63a5f88e3fb2b597348a7798559d612fce9013e6cda53b8eef61d5c874ea030d377639f93f3c83b5f7f634da201ce392d9799102ba9ca4c6126dd9fb77b33e1",
		},
		{
			.entropy =
				"a5e0b94b0efb6e1df2b691bdd3e15d68ba602e25a4e1fa7b17fe124f280b722b",
			.nonce = "3be26657fd44368efebe93c16b230e4f",
			.personalization_string =
				"652fce43407146c069c6d20e557eb75bbb7c72c10afeaffbdb9ff4bb6b2d0558",
			.returned_bits =
				"bc9379fca8507d562434c8d54d35dfece72c18197593480bfa7b63b262d79667d8184c9026682b4a42b73ee237ce5ff46d8cf58df4cd7f145ba4ae3964838a787f353f82c7ba02f9680b0b72bd37473dc98fea004ba5f3b87c193170f00aba61d16eca612efc101c9db916d9ad9f34c20595a4df87106b952b9d3d47f3ee346f150e8e4e21d1d3892008ed163c0cde88a6d8d6d6ee7aa2511e15d583e3f286462f9d3d13966f955898d0c0c7a369e886caf2c3df6d41238ba85086e47fa78028f3dc01545834dc73b25509ee6577a6e8f159c70407bb7b05ca9bfe2580e8ab864543fbe67c286230dfb3c792ad050e79ce16ca3fabf73387e85a68faa44ee95d",
		}
	};

	for (size_t i = 0;
	     i < sizeof(test_vectors) / sizeof(nist_test_vector_hmac_drbg);
	     ++i) {
		size_t entropy_size = test_vectors[i].entropy.length() / 2;
		size_t nonce_size = test_vectors[i].nonce.length() / 2;
		size_t pers_size =
			test_vectors[i].personalization_string.length() / 2;
		size_t result_size = test_vectors[i].returned_bits.length() / 2;
		size_t seed_material_size =
			entropy_size + nonce_size + pers_size;
		size_t offset = 0;

		seed_material = (uint8_t *)malloc(seed_material_size);
		exp = (uint8_t *)malloc(result_size);
		act = (uint8_t *)malloc(result_size);

		hex2bin(test_vectors[i].entropy.c_str(),
			test_vectors[i].entropy.length(),
			seed_material + offset, entropy_size);
		offset += entropy_size;
		hex2bin(test_vectors[i].nonce.c_str(),
			test_vectors[i].nonce.length(), seed_material + offset,
			nonce_size);
		offset += nonce_size;
		hex2bin(test_vectors[i].personalization_string.c_str(),
			test_vectors[i].personalization_string.length(),
			seed_material + offset, pers_size);
		hex2bin(test_vectors[i].returned_bits.c_str(),
			test_vectors[i].returned_bits.length(), exp,
			result_size);

		CKINT(esdm_botan_drbg_alloc(&drng, 256));
		CKINT(esdm_botan_drbg_seed(drng, seed_material,
					   seed_material_size));
		if (esdm_botan_drbg_generate(drng, act, result_size) !=
		    (ssize_t)result_size) {
			ret = -EFAULT;
			goto out;
		}
		if (esdm_botan_drbg_generate(drng, act, result_size) !=
		    (ssize_t)result_size) {
			ret = -EFAULT;
			goto out;
		}
		if (memcmp(act, exp, result_size)) {
			ret = -EFAULT;
			goto out;
		}
		esdm_botan_drbg_dealloc(drng);
		drng = NULL;

		free(seed_material);
		seed_material = NULL;

		free(exp);
		exp = NULL;

		free(act);
		act = NULL;
	}

out:
	esdm_botan_drbg_dealloc(drng);

	/* does nothing if already NULL */
	free(seed_material);
	seed_material = NULL;

	/* does nothing if already NULL */
	free(exp);
	exp = NULL;

	/* does nothing if already NULL */
	free(act);
	act = NULL;

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
