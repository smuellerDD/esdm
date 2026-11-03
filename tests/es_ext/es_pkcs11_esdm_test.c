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
 * esdm-es-pkcs11 serving a SoftHSM token, read by the external source of the
 * ESDM configured for its socket and its user, as esdm-server --es_ext and
 * --es_ext_uid do - the ESDM needs nothing that knows of PKCS#11.
 *
 * - The source passes its self test and delivers data of the token, credited
 *   at the rate the daemon declares, or at the one configured - higher or
 *   lower, as the daemon claims all bits of its data.
 * - The ESDM shows the name the daemon declares, and its status.
 *
 * The source is compiled in and called as the ES manager calls it; how it
 * handles a provider is tested by es_extsock_test.c.
 *
 * Usage: es_pkcs11_esdm_test <esdm-es-pkcs11> <es_pkcs11_shim module>
 */

#include "config.h"

/* The unit under test */
#include "esdm_es_extsock.c"

#include "common_test.h"
#include "../es_state_check.h"
#include "es_pkcs11_test_util.h"

#define ES (&esdm_es_extsock)
#define BITS ESDM_DRNG_SECURITY_STRENGTH_BITS
#define LEVEL esdm_fast_noise_entropylevel(ESDM_PKCS11_ENTROPY_RATE, BITS)

/* A block from the source, its data into @data: the bits credited */
static uint32_t test_get(uint8_t *data)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	ES->get_ent(&eb_es, BITS, true);
	if (data)
		memcpy(data, eb_es.e, BITS / 8);
	return eb_es.e_bits;
}

static bool test_daemon_start(void)
{
	const char *const args[] = { "--module",
				     pk.shim,
				     "--token_label",
				     PK_TOKEN_LABEL,
				     "--pin_file",
				     "pin",
				     NULL };

	return pk_start(args, NULL);
}

static void test_credited(void)
{
	uint8_t first[BITS / 8], second[BITS / 8];
	struct json_object *state, *provider = NULL, *plugin = NULL;

	CHECK_EQ(esdm_es_ext_set_path(pk.socket), 0);
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the source is not active");
	CHECK_EQ(ES->selftest(), 0);

	CHECK(LEVEL > 0, "the build credits the PKCS#11 source with nothing");
	CHECK_EQ(test_get(first), LEVEL);
	CHECK_EQ(test_get(second), LEVEL);
	CHECK(memcmp(first, second, sizeof(first)),
	      "two blocks of the token are the same");
	CHECK_EQ(ES->curr_entropy(BITS), LEVEL);

	/* A rate configured takes precedence, higher or lower */
	esdm_config_es_ext_entropy_rate_set(64);
	CHECK_EQ(test_get(NULL), esdm_fast_noise_entropylevel(64, BITS));
	esdm_config_es_ext_entropy_rate_set(256);
	CHECK_EQ(test_get(NULL), esdm_fast_noise_entropylevel(256, BITS));
	esdm_config_es_ext_entropy_rate_set(ESDM_ES_EXT_ENTROPY_RATE_AUTO);

	state = es_state_get(ES);
	json_object_object_get_ex(state, "provider", &provider);
	json_object_object_get_ex(provider, "plugin", &plugin);
	CHECK(es_state_str_is(state, "name", "PKCS#11 " PK_TOKEN_LABEL) &&
		      es_state_str_is(state, "instance", ES->name) &&
		      es_state_int(state, "assessed_rate", -1) ==
			      ESDM_PKCS11_ENTROPY_RATE &&
		      es_state_str_is(state, "assessed_rate_source",
				      "provider") &&
		      es_state_str_has(state, "status", "connected (uid") &&
		      !es_state_str_has(state, "status", "failing") &&
		      es_state_int(state, "available_entropy", 0) > 0 &&
		      es_state_str_is(plugin, "token", PK_TOKEN_LABEL) &&
		      json_object_get_boolean(
			      json_object_object_get(plugin, "logged_in")),
	      "not the state of the source and its token logged in to: %s",
	      es_state_print(state));
	json_object_put(state);
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 3) {
		printf("Usage: %s <esdm-es-pkcs11> <shim module>\n", argv[0]);
		return 1;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);
	signal(SIGPIPE, SIG_IGN);

	ret = pk_setup(argv[1], argv[2]);
	if (ret || !test_daemon_start()) {
		printf("cannot serve a SoftHSM token\n");
		pk_cleanup();
		return ret ? ret : 1;
	}

	/* The daemon runs as the user of the test */
	CHECK_EQ(esdm_es_ext_set_peer_uid((int64_t)getuid()), 0);
	test_credited();

	ES->fini();
	CHECK(pk_stop(), "esdm-es-pkcs11 did not end cleanly");
	ret = common_test_result("es_pkcs11_esdm");
	pk_cleanup();
	return ret;
}
