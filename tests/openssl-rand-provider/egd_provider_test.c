/*
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

/*
 * The OpenSSL EGD provider, driven against the EGD test peer.
 *
 * The provider tests next to this one start an esdm-server and need root, which
 * leaves most of this provider out of an ordinary run. None of it needs the
 * ESDM: the provider speaks the EGD protocol over a Unix domain socket, and
 * tests/egd/egd_peer.c speaks the other side.
 *
 * Against the peer this test reaches what a server cannot be made to do on
 * demand - a socket that stops answering mid-life, reaching the transfer errors
 * and their reason strings, and one that cannot be used at all, reaching the
 * refusal to load. The peer also answers reads with a counter, so a request
 * split across several transfers is checkable as reassembled in order.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common_test.h"
#include "egd_peer.h"

/* The provider module, and the property that selects its algorithms */
#define TEST_EGD_PROVIDER "libesdm-egd-provider"
#define TEST_EGD_PROPERTY "provider=esdm-egd"

#define TEST_EGD_SOCKET_ENV "ESDM_EGD_SOCKET"

static const char *provider_path;
static char tmpdir[] = "/tmp/esdm-egd-prov-XXXXXX";
static char sockpath[sizeof(tmpdir) + 16];

/* What the last error in the OpenSSL stack says, for a failure message */
static const char *last_error(void)
{
	static char buf[256];
	unsigned long err = ERR_peek_last_error();

	if (!err)
		return "(no error reported)";

	ERR_error_string_n(err, buf, sizeof(buf));

	return buf;
}

/*
 * The provider reports itself, and answers its self test. The self test is a
 * complete round trip over the protocol - the entropy count command - so it is
 * also the check that the provider is really talking to the peer.
 */
static void test_provider_params(OSSL_PROVIDER *prov)
{
	OSSL_PARAM params[4];
	char *name = NULL, *version = NULL, *buildinfo = NULL;

	CHECK(OSSL_PROVIDER_get0_name(prov) != NULL,
	      "the provider does not report a module name");

	params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &name,
						  0);
	params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION,
						  &version, 0);
	params[2] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO,
						  &buildinfo, 0);
	params[3] = OSSL_PARAM_construct_end();

	CHECK(OSSL_PROVIDER_get_params(prov, params) == 1,
	      "the provider parameters cannot be read: %s", last_error());
	CHECK(name && strstr(name, "EGD") != NULL,
	      "the provider does not name itself as the EGD one (got \"%s\")",
	      name ? name : "(null)");
	CHECK(version != NULL, "the provider reports no version");
	CHECK(buildinfo != NULL, "the provider reports no build information");

	CHECK(OSSL_PROVIDER_self_test(prov) == 1,
	      "the provider self test failed: %s", last_error());
}

/* Fetch one of the provider's RAND algorithms and set it up for use */
static EVP_RAND_CTX *rand_ctx_new(const char *algorithm)
{
	EVP_RAND_CTX *rctx;
	EVP_RAND *rand = EVP_RAND_fetch(NULL, algorithm, TEST_EGD_PROPERTY);

	if (!rand) {
		CHECK(0, "%s is not provided by " TEST_EGD_PROVIDER ": %s",
		      algorithm, last_error());
		return NULL;
	}

	rctx = EVP_RAND_CTX_new(rand, NULL);
	EVP_RAND_free(rand);
	if (!rctx) {
		CHECK(0, "no %s context could be created: %s", algorithm,
		      last_error());
		return NULL;
	}

	return rctx;
}

/*
 * Every algorithm the provider declares is the same implementation - what
 * matters is that each of the names OpenSSL looks for resolves to it, because
 * an application asking for any of them is what loads this provider at all.
 */
static void test_algorithms_provided(void)
{
	static const char *const names[] = { "CTR-DRBG", "HASH-DRBG",
					     "HMAC-DRBG", "SEED-SRC" };
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		EVP_RAND *rand = EVP_RAND_fetch(NULL, names[i],
						TEST_EGD_PROPERTY);

		CHECK(rand != NULL, "%s is not provided: %s", names[i],
		      last_error());
		EVP_RAND_free(rand);
	}
}

static void test_generate(void)
{
	EVP_RAND_CTX *rctx = rand_ctx_new("CTR-DRBG");
	unsigned char buf[600];
	size_t i;

	if (!rctx)
		return;

	/* The context is usable from several threads once locking is on */
	CHECK(EVP_RAND_enable_locking(rctx) == 1,
	      "locking could not be enabled: %s", last_error());

	CHECK(EVP_RAND_instantiate(rctx, 256, 0, NULL, 0, NULL) == 1,
	      "the RNG could not be instantiated: %s", last_error());

	/*
	 * More than the 255 bytes a single EGD transfer carries, so the request
	 * has to be split and put back together. The peer answers with a
	 * counter, which is what makes a piece delivered twice or out of order
	 * visible.
	 */
	memset(buf, 0, sizeof(buf));
	CHECK(EVP_RAND_generate(rctx, buf, sizeof(buf), 256, 0, NULL, 0) == 1,
	      "generating %zu bytes failed: %s", sizeof(buf), last_error());
	for (i = 0; i < sizeof(buf); i++) {
		if (buf[i] != egd_peer_data_byte(i)) {
			CHECK(0, "byte %zu of the answer is 0x%02x, expected 0x%02x",
			      i, buf[i], egd_peer_data_byte(i));
			break;
		}
	}

	/* Reseeding is the ESDM's business, and is accepted as a no-op */
	CHECK(EVP_RAND_reseed(rctx, 0, NULL, 0, NULL, 0) == 1,
	      "the reseed was refused: %s", last_error());

	/* A nonce is ordinary random data over this interface */
	CHECK(EVP_RAND_nonce(rctx, buf, 16) == 1,
	      "no nonce was delivered: %s", last_error());

	CHECK(EVP_RAND_verify_zeroization(rctx) == 1,
	      "the zeroization check failed: %s", last_error());

	CHECK(EVP_RAND_uninstantiate(rctx) == 1,
	      "the RNG could not be uninstantiated: %s", last_error());

	EVP_RAND_CTX_free(rctx);
}

/*
 * What the provider says about itself to a caller sizing its requests. The
 * maximum request is the one that matters: it is deliberately not the 255 bytes
 * of a single EGD transfer, because larger requests are split internally.
 */
static void test_ctx_params(void)
{
	EVP_RAND_CTX *rctx = rand_ctx_new("CTR-DRBG");
	OSSL_PARAM params[4];
	unsigned int strength = 0;
	size_t max_request = 0;
	int state = 0;

	if (!rctx)
		return;

	params[0] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST,
						&max_request);
	params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH,
					      &strength);
	params[2] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE, &state);
	params[3] = OSSL_PARAM_construct_end();

	CHECK(EVP_RAND_CTX_get_params(rctx, params) == 1,
	      "the context parameters cannot be read: %s", last_error());
	CHECK(max_request > 255,
	      "the maximum request is %zu, which is a single EGD transfer",
	      max_request);
	CHECK_EQ(strength, 256);
	CHECK_EQ(state, EVP_RAND_STATE_READY);

	EVP_RAND_CTX_free(rctx);
}

/*
 * The EGD protocol has no way to ask for prediction resistance, so a request
 * that insists on it is refused rather than answered with ordinary data. That
 * is the one property this provider cannot deliver, and quietly pretending
 * otherwise is the failure worth guarding against.
 */
static void test_prediction_resistance_refused(void)
{
	EVP_RAND_CTX *rctx = rand_ctx_new("CTR-DRBG");
	unsigned char buf[32];

	if (!rctx)
		return;

	CHECK(EVP_RAND_instantiate(rctx, 256, 1, NULL, 0, NULL) == 0,
	      "a prediction resistant instantiation was accepted");

	/* And again on the request itself, for a context instantiated without */
	CHECK(EVP_RAND_instantiate(rctx, 256, 0, NULL, 0, NULL) == 1,
	      "the RNG could not be instantiated: %s", last_error());
	CHECK(EVP_RAND_generate(rctx, buf, sizeof(buf), 256, 1, NULL, 0) == 0,
	      "a prediction resistant request was answered");

	EVP_RAND_CTX_free(rctx);
}

/*
 * The provider used as the seed source of another DRBG, which is what the
 * SEED-SRC algorithm is for: OpenSSL then pulls seed material through the
 * get_seed entry point rather than through generate().
 */
static void test_as_seed_source(void)
{
	EVP_RAND_CTX *parent = rand_ctx_new("SEED-SRC");
	EVP_RAND_CTX *rctx = NULL;
	unsigned char buf[64];
	OSSL_PARAM params[2];
	EVP_RAND *rand;

	if (!parent)
		return;

	/*
	 * A parent is used from the child's lock, so OpenSSL requires it to
	 * support locking before it will take it as one.
	 */
	CHECK(EVP_RAND_enable_locking(parent) == 1,
	      "locking could not be enabled on the seed source: %s",
	      last_error());
	CHECK(EVP_RAND_instantiate(parent, 0, 0, NULL, 0, NULL) == 1,
	      "the seed source could not be instantiated: %s", last_error());

	rand = EVP_RAND_fetch(NULL, "CTR-DRBG", "provider=default");
	if (!rand) {
		CHECK(0, "the default CTR-DRBG is not available: %s",
		      last_error());
		goto out;
	}

	rctx = EVP_RAND_CTX_new(rand, parent);
	EVP_RAND_free(rand);
	if (!rctx) {
		CHECK(0, "no DRBG could be created on the seed source: %s",
		      last_error());
		goto out;
	}

	/*
	 * Strength 0: the DRBG takes its own, and asking for more than the
	 * seed source reports would be refused before it ever pulls seed.
	 */
	/*
	 * The cipher decides the DRBG's own strength, and a seed request has to
	 * be for as much as it has: with the default cipher it would ask for
	 * less than the seed source offers and be refused for it.
	 */
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
						     (char *)"AES-256-CTR", 0);
	params[1] = OSSL_PARAM_construct_end();

	CHECK(EVP_RAND_instantiate(rctx, 256, 0, NULL, 0, params) == 1,
	      "the DRBG could not be seeded from the EGD provider: %s",
	      last_error());
	CHECK(EVP_RAND_generate(rctx, buf, sizeof(buf), 256, 0, NULL, 0) == 1,
	      "the DRBG seeded from the EGD provider produced nothing: %s",
	      last_error());

out:
	EVP_RAND_CTX_free(rctx);
	EVP_RAND_CTX_free(parent);
}

/*
 * What happens once the other side is gone. Every request has to fail rather
 * than hand back whatever was in the buffer, and it has to say so in the error
 * stack - the reason strings the provider registers are what a caller sees.
 */
static void test_peer_gone(struct egd_peer *peer)
{
	EVP_RAND_CTX *rctx = rand_ctx_new("CTR-DRBG");
	unsigned char buf[32];
	unsigned char *seed = NULL;

	if (!rctx)
		return;

	CHECK(EVP_RAND_instantiate(rctx, 256, 0, NULL, 0, NULL) == 1,
	      "the RNG could not be instantiated: %s", last_error());

	/* The socket goes away with the peer */
	egd_peer_stop(peer);

	memset(buf, 0xa5, sizeof(buf));
	ERR_clear_error();
	CHECK(EVP_RAND_generate(rctx, buf, sizeof(buf), 256, 0, NULL, 0) == 0,
	      "a request was answered although the peer is gone");
	CHECK(ERR_peek_last_error() != 0,
	      "the failed request left nothing in the error stack");

	CHECK(EVP_RAND_nonce(rctx, buf, 16) == 0,
	      "a nonce was delivered although the peer is gone");

	(void)seed;
	EVP_RAND_CTX_free(rctx);
}

/*
 * A socket path that cannot be used at all. The provider has nowhere to
 * connect, so it refuses to load - which is the one failure it does report,
 * because it cannot be worked around later.
 */
static void test_socket_path_too_long(void)
{
	char toolong[512];
	OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
	OSSL_PROVIDER *prov;

	if (!libctx) {
		CHECK(0, "no library context could be created");
		return;
	}

	memset(toolong, 'x', sizeof(toolong) - 1);
	toolong[0] = '/';
	toolong[sizeof(toolong) - 1] = '\0';
	setenv(TEST_EGD_SOCKET_ENV, toolong, 1);

	CHECK(OSSL_PROVIDER_set_default_search_path(libctx, provider_path) == 1,
	      "the provider search path could not be set");

	ERR_clear_error();
	prov = OSSL_PROVIDER_load(libctx, TEST_EGD_PROVIDER);
	CHECK(prov == NULL,
	      "the provider loaded with a socket path that cannot be used");
	if (prov)
		OSSL_PROVIDER_unload(prov);

	setenv(TEST_EGD_SOCKET_ENV, sockpath, 1);
	OSSL_LIB_CTX_free(libctx);
}

int main(int argc, char *argv[])
{
	OSSL_PROVIDER *prov_esdm = NULL, *prov_default = NULL;
	struct egd_peer *peer = NULL;

	if (argc < 2) {
		printf("usage: %s <provider search path>\n", argv[0]);
		return 1;
	}
	provider_path = argv[1];

	if (!mkdtemp(tmpdir)) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		return 1;
	}
	snprintf(sockpath, sizeof(sockpath), "%s/egd.sock", tmpdir);

	if (egd_peer_start(&peer, sockpath, EGD_PEER_NORMAL)) {
		printf("Cannot start the EGD test peer\n");
		rmdir(tmpdir);
		return 1;
	}

	/* The provider picks up its socket from here when nothing configures it */
	setenv(TEST_EGD_SOCKET_ENV, sockpath, 1);

	if (OSSL_PROVIDER_set_default_search_path(NULL, provider_path) != 1) {
		printf("Cannot set the provider search path\n");
		goto out;
	}

	prov_esdm = OSSL_PROVIDER_load(NULL, TEST_EGD_PROVIDER);
	if (!prov_esdm) {
		printf("Cannot load " TEST_EGD_PROVIDER ": %s\n", last_error());
		goto out;
	}

	/* For the DRBG that takes this provider as its seed source */
	prov_default = OSSL_PROVIDER_load(NULL, "default");
	if (!prov_default) {
		printf("Cannot load the default provider: %s\n", last_error());
		goto out;
	}

	test_provider_params(prov_esdm);
	test_algorithms_provided();
	test_generate();
	test_ctx_params();
	test_prediction_resistance_refused();
	test_as_seed_source();

	/* Takes the peer down, so everything that needs it has run by now */
	test_peer_gone(peer);
	peer = NULL;

	test_socket_path_too_long();

out:
	if (prov_default)
		OSSL_PROVIDER_unload(prov_default);
	if (prov_esdm)
		OSSL_PROVIDER_unload(prov_esdm);
	if (peer)
		egd_peer_stop(peer);
	rmdir(tmpdir);

	return common_test_result("egd_provider");
}
