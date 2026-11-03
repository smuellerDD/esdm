/*
 * ESDM external entropy source: PKCS#11 token via libp11
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

/*
 * The random number generator of a PKCS#11 token as an external entropy
 * source, served by esdm-es-pkcs11(8). In a process of its own, the module -
 * vendor code - runs with the privileges the token needs, the PIN is a secret
 * of this process alone, and a module that hangs or crashes takes the ESDM
 * nowhere: it reconnects once the daemon is back.
 *
 * - The slot is the first one holding an initialized token with a random
 *   number generator, of the configured label if there is one.
 * - The user logs in only with a PIN, and if the token asks for it. A failed
 *   login wipes the PIN, which is never tried again: every one uses up a PIN
 *   retry of the token. The token is used without a login then.
 * - A token not there - pulled, not inserted yet, or lost to a failed read -
 *   is looked for again on demand, at most every
 *   ESDM_PKCS11_RETRY_INTERVAL_SEC, the module loaded anew when its slots
 *   hold none: SoftHSM, for one, sees a new token only then.
 * - A token is tested - two reads that have to differ - when it is bound and
 *   on every self test. Its data is claimed in full while the last test
 *   passed, and the ESDM credits the declared entropy rate of it.
 *
 * The callbacks are called from one thread: no lock.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <json-c/json.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libp11.h>

#include "esdm_es_ext_json.h"
#include "esdm_es_ext_proto.h"
#include "esdm_es_pkcs11.h"
#include "esdm_logger.h"
#include "memset_secure.h"

/* Several tokens choke on large C_GenerateRandom requests */
#define ESDM_PKCS11_CHUNK_BYTES 32

/* A token not there is looked for again at most once per this many seconds */
#define ESDM_PKCS11_RETRY_INTERVAL_SEC 5

enum esdm_pkcs11_test {
	ESDM_PKCS11_TEST_NONE,
	ESDM_PKCS11_TEST_PASSED,
	ESDM_PKCS11_TEST_FAILED,
};

static struct {
	/* The PIN is owned by the source */
	struct esdm_es_pkcs11_config config;
	bool pin_refused;

	PKCS11_CTX *ctx;
	bool module_loaded;
	PKCS11_SLOT *slots;
	unsigned int nslots;
	/* The slot of the token in use, NULL for none */
	PKCS11_SLOT *slot;
	bool logged_in;

	/* The last test of the token */
	enum esdm_pkcs11_test test;

	/* Earliest time to look for a token again, monotonic seconds */
	time_t retry_at;

	/* Why the source does not deliver (a constant), and what was logged */
	const char *last_error;
	const char *last_logged;
} pkcs11;

/* "PKCS#11 <token label>", see esdm_es_pkcs11_configure() */
static char esdm_es_pkcs11_name[ESDM_ES_EXT_NAME_MAX + 1];

static void esdm_es_pkcs11_error(enum esdm_logger_verbosity level,
				 const char *msg)
{
	pkcs11.last_error = msg;
	if (pkcs11.last_logged == msg)
		return;
	pkcs11.last_logged = msg;
	esdm_logger(level, LOGGER_C_ES, "PKCS#11 entropy source: %s\n", msg);
}

static const char *esdm_es_pkcs11_label(void)
{
	return pkcs11.slot->token->label ? pkcs11.slot->token->label :
					   "(no label)";
}

static void esdm_es_pkcs11_drop_slot(void)
{
	if (pkcs11.logged_in && pkcs11.slot)
		PKCS11_logout(pkcs11.slot);
	pkcs11.logged_in = false;
	pkcs11.slot = NULL;
}

static void esdm_es_pkcs11_release_slots(void)
{
	esdm_es_pkcs11_drop_slot();
	if (pkcs11.slots)
		PKCS11_release_all_slots(pkcs11.ctx, pkcs11.slots,
					 pkcs11.nslots);
	pkcs11.slots = NULL;
	pkcs11.nslots = 0;
}

static void esdm_es_pkcs11_finalize(void)
{
	esdm_es_pkcs11_release_slots();
	if (pkcs11.ctx) {
		if (pkcs11.module_loaded)
			PKCS11_CTX_unload(pkcs11.ctx);
		PKCS11_CTX_free(pkcs11.ctx);
	}
	pkcs11.ctx = NULL;
	pkcs11.module_loaded = false;
}

static void esdm_es_pkcs11_pin_drop(void)
{
	if (pkcs11.config.pin) {
		memset_secure(pkcs11.config.pin, 0, strlen(pkcs11.config.pin));
		free(pkcs11.config.pin);
	}
	pkcs11.config.pin = NULL;
}

/* Log in once, with a PIN, if the token asks for it */
static void esdm_es_pkcs11_login(void)
{
	PKCS11_TOKEN *token = pkcs11.slot->token;
	int logged_in = 0;

	if (!pkcs11.config.pin || !token->loginRequired ||
	    PKCS11_is_logged_in(pkcs11.slot, 0, &logged_in))
		return;

	/* On stderr: logged at the default verbosity, this would go unseen */
	if (!logged_in && PKCS11_login(pkcs11.slot, 0, pkcs11.config.pin)) {
		fprintf(stderr,
			"PKCS#11 entropy source: login to token '%s' failed, the PIN is not tried again\n",
			esdm_es_pkcs11_label());
		esdm_es_pkcs11_pin_drop();
		pkcs11.pin_refused = true;
		return;
	}
	pkcs11.logged_in = true;
}

static const char esdm_es_pkcs11_repeated[] = "the token repeated its output";

/*
 * Two reads of the bound token that have to differ: 0, -EFAULT if it repeated
 * its output, -EIO if it did not deliver - it is looked for again then
 */
static int esdm_es_pkcs11_test_token(void)
{
	uint8_t first[16], second[16];
	int ret = 0;

	if (PKCS11_generate_random(pkcs11.slot, first, sizeof(first)) ||
	    PKCS11_generate_random(pkcs11.slot, second, sizeof(second))) {
		esdm_es_pkcs11_drop_slot();
		esdm_es_pkcs11_error(LOGGER_ERR, "the token did not deliver");
		ret = -EIO;
	} else if (!memcmp(first, second, sizeof(first))) {
		pkcs11.test = ESDM_PKCS11_TEST_FAILED;
		esdm_es_pkcs11_error(LOGGER_ERR, esdm_es_pkcs11_repeated);
		ret = -EFAULT;
	} else {
		pkcs11.test = ESDM_PKCS11_TEST_PASSED;
		pkcs11.last_error = pkcs11.last_logged = NULL;
	}

	memset_secure(first, 0, sizeof(first));
	memset_secure(second, 0, sizeof(second));
	return ret;
}

/* Take a usable slot of those enumerated: 0, -ENOENT for none, or -EIO */
static int esdm_es_pkcs11_bind(void)
{
	const char *label = pkcs11.config.token_label;
	unsigned int i;

	for (i = 0; i < pkcs11.nslots && !pkcs11.slot; i++) {
		PKCS11_TOKEN *token = pkcs11.slots[i].token;

		if (token && token->initialized && token->hasRng &&
		    (!label || !label[0] ||
		     (token->label && !strcmp(token->label, label))))
			pkcs11.slot = &pkcs11.slots[i];
	}
	if (!pkcs11.slot) {
		esdm_es_pkcs11_error(
			LOGGER_WARN,
			"no usable token with a random number generator found, looked for again on demand");
		return -ENOENT;
	}

	esdm_es_pkcs11_login();
	/* A repeated output keeps the token bound, credited with nothing */
	if (esdm_es_pkcs11_test_token() == -EIO)
		return -EIO;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
		    "PKCS#11 entropy source using token '%s' (module %s)\n",
		    esdm_es_pkcs11_label(), pkcs11.config.module_path);
	return 0;
}

/* (Re)load the module and bind a token: 0 or a negative errno */
static int esdm_es_pkcs11_open_module(void)
{
	esdm_es_pkcs11_finalize();

	pkcs11.ctx = PKCS11_CTX_new();
	if (!pkcs11.ctx) {
		esdm_es_pkcs11_error(LOGGER_WARN, "PKCS11_CTX_new failed");
		return -ENOMEM;
	}

	if (PKCS11_CTX_load(pkcs11.ctx, pkcs11.config.module_path)) {
		esdm_es_pkcs11_error(
			LOGGER_WARN,
			"the PKCS#11 module cannot be loaded, retried on demand");
		PKCS11_CTX_free(pkcs11.ctx);
		pkcs11.ctx = NULL;
		return -ENODEV;
	}
	pkcs11.module_loaded = true;

	if (PKCS11_enumerate_slots(pkcs11.ctx, &pkcs11.slots, &pkcs11.nslots) <
	    0) {
		esdm_es_pkcs11_error(
			LOGGER_WARN,
			"the slots of the module cannot be enumerated, retried on demand");
		pkcs11.slots = NULL;
		pkcs11.nslots = 0;
		return -EIO;
	}

	return esdm_es_pkcs11_bind();
}

/*
 * Bind a token again, rate limited - in the slots enumerated anew, which is
 * how PKCS#11 sees a token re-inserted, or with the module loaded anew
 */
static void esdm_es_pkcs11_reacquire(void)
{
	struct timespec now = { 0 };

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (pkcs11.slot || now.tv_sec < pkcs11.retry_at)
		return;
	pkcs11.retry_at = now.tv_sec + ESDM_PKCS11_RETRY_INTERVAL_SEC;

	if (!pkcs11.ctx) {
		esdm_es_pkcs11_open_module();
		return;
	}
	esdm_es_pkcs11_release_slots();
	if (PKCS11_enumerate_slots(pkcs11.ctx, &pkcs11.slots, &pkcs11.nslots) <
	    0) {
		esdm_es_pkcs11_open_module();
		return;
	}
	if (esdm_es_pkcs11_bind() == -ENOENT)
		esdm_es_pkcs11_open_module();
}

static int esdm_es_pkcs11_init(void **ctx)
{
	*ctx = NULL;
	pkcs11.retry_at = 0;
	pkcs11.test = ESDM_PKCS11_TEST_NONE;

	/*
	 * No module or no token is no reason not to serve: they are looked for
	 * on demand, and the ESDM credits nothing until the source delivers
	 */
	esdm_es_pkcs11_open_module();
	return 0;
}

static void esdm_es_pkcs11_fini(void *ctx)
{
	(void)ctx;
	esdm_es_pkcs11_finalize();
	esdm_es_pkcs11_pin_drop();
}

static int esdm_es_pkcs11_get(void *ctx, uint8_t *buf, size_t buflen,
			      uint32_t *entropy_bits)
{
	size_t done, len;

	(void)ctx;
	*entropy_bits = 0;

	esdm_es_pkcs11_reacquire();
	if (!pkcs11.slot)
		return -ENODEV;

	for (done = 0; done < buflen; done += len) {
		len = buflen - done;
		if (len > ESDM_PKCS11_CHUNK_BYTES)
			len = ESDM_PKCS11_CHUNK_BYTES;

		/* A token pulled: the next request looks for it again */
		if (PKCS11_generate_random(pkcs11.slot, buf + done,
					   (unsigned int)len)) {
			esdm_es_pkcs11_drop_slot();
			esdm_es_pkcs11_error(
				LOGGER_WARN,
				"C_GenerateRandom failed, the token is looked for again");
			return -EIO;
		}
	}

	if (pkcs11.test == ESDM_PKCS11_TEST_PASSED)
		*entropy_bits = (uint32_t)(buflen * 8);
	return 0;
}

/* Only a repeated output fails: a token not there is tested once bound */
static int esdm_es_pkcs11_selftest(void *ctx)
{
	int ret = 0;

	(void)ctx;
	if (pkcs11.slot)
		ret = esdm_es_pkcs11_test_token();
	return ret == -EFAULT ? -EFAULT : 0;
}

/*
 * { "module": "/usr/lib/softhsm/libsofthsm2.so", "token_label": null,
 *   "token": "my-token", "slot": 1, "token_present": true,
 *   "logged_in": true, "pin": "set", "repetition_test": "passed",
 *   "last_error": null }
 *
 * A module path too long is shortened to its file name.
 */
static int esdm_es_pkcs11_status(void *ctx, char *buf, size_t buflen)
{
	const char *module = pkcs11.config.module_path, *text;
	unsigned int attempt;

	(void)ctx;
	for (attempt = 0; attempt < 2; attempt++) {
		struct json_object *obj = json_object_new_object();

		if (!obj)
			return -ENOMEM;

		json_object_object_add(obj, "module",
				       esdm_es_ext_json_text(module));
		json_object_object_add(
			obj, "token_label",
			esdm_es_ext_json_text(pkcs11.config.token_label));
		json_object_object_add(
			obj, "token",
			pkcs11.slot ?
				esdm_es_ext_json_text(esdm_es_pkcs11_label()) :
				NULL);
		json_object_object_add(
			obj, "slot",
			pkcs11.slot ? json_object_new_uint64(
					      PKCS11_get_slotid_from_slot(
						      pkcs11.slot)) :
				      NULL);
		json_object_object_add(obj, "token_present",
				       json_object_new_boolean(!!pkcs11.slot));
		json_object_object_add(
			obj, "logged_in",
			json_object_new_boolean(pkcs11.logged_in));
		json_object_object_add(
			obj, "pin",
			json_object_new_string(pkcs11.pin_refused ? "refused" :
					       pkcs11.config.pin  ? "set" :
								    "none"));
		json_object_object_add(
			obj, "repetition_test",
			json_object_new_string(
				pkcs11.test == ESDM_PKCS11_TEST_PASSED ?
					"passed" :
				pkcs11.test == ESDM_PKCS11_TEST_FAILED ?
					"failed" :
					"none"));
		json_object_object_add(
			obj, "last_error",
			esdm_es_ext_json_text(pkcs11.last_error));

		text = json_object_to_json_string_ext(
			obj, JSON_C_TO_STRING_PLAIN |
				     JSON_C_TO_STRING_NOSLASHESCAPE);
		if (text && strlen(text) < buflen) {
			memcpy(buf, text, strlen(text) + 1);
			json_object_put(obj);
			return 0;
		}
		json_object_put(obj);

		if (module && strrchr(module, '/'))
			module = strrchr(module, '/') + 1;
	}

	return -EMSGSIZE;
}

static uint32_t esdm_es_pkcs11_entropy_rate(void *ctx)
{
	(void)ctx;
	return pkcs11.config.entropy_rate;
}

struct esdm_es_ext_plugin esdm_es_pkcs11_plugin = {
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.name = ESDM_PKCS11_NAME,
	.init = esdm_es_pkcs11_init,
	.fini = esdm_es_pkcs11_fini,
	.get_entropy = esdm_es_pkcs11_get,
	.selftest = esdm_es_pkcs11_selftest,
	.status_json = esdm_es_pkcs11_status,
	.entropy_rate = esdm_es_pkcs11_entropy_rate,
};

void esdm_es_pkcs11_configure(struct esdm_es_pkcs11_config *config)
{
	int len;

	pkcs11.config = *config;
	config->pin = NULL;

	/* "PKCS#11" and the label, which tells one daemon from the next */
	esdm_es_pkcs11_plugin.name = ESDM_PKCS11_NAME;
	if (!config->token_label || !config->token_label[0])
		return;
	len = snprintf(esdm_es_pkcs11_name, sizeof(esdm_es_pkcs11_name),
		       "%s %s", ESDM_PKCS11_NAME, config->token_label);
	if (len > 0 && (size_t)len < sizeof(esdm_es_pkcs11_name) &&
	    esdm_es_ext_name_valid(esdm_es_pkcs11_name, (size_t)len))
		esdm_es_pkcs11_plugin.name = esdm_es_pkcs11_name;
}
