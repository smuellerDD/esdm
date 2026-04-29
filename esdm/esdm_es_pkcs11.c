/*
 * ESDM Entropy Source: PKCS#11 token via libp11
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libp11.h>

#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_mgr.h"
#include "esdm_es_pkcs11.h"
#include "helper.h"
#include "mutex.h"

/*
 * Per call we ask the token for at most this many bytes. C_GenerateRandom is
 * not bounded by the standard but several tokens choke on large requests.
 */
#define ESDM_PKCS11_CHUNK_BYTES 32

static PKCS11_CTX *pkcs11_ctx = NULL;
static PKCS11_SLOT *pkcs11_slots = NULL;
static unsigned int pkcs11_nslots = 0;
static PKCS11_SLOT *pkcs11_slot = NULL;
static bool pkcs11_logged_in = false;
static bool pkcs11_module_loaded = false;
static DEFINE_MUTEX_UNLOCKED(pkcs11_mutex);

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
static struct esdm_es_buf pkcs11_buf;
static bool pkcs11_buf_alloced = false;
#endif

static bool esdm_es_pkcs11_active(void);

/* Caller must hold pkcs11_mutex (write lock). */
static void esdm_es_pkcs11_finalize_locked(void)
{
	if (pkcs11_logged_in && pkcs11_slot)
		PKCS11_logout(pkcs11_slot);
	pkcs11_logged_in = false;

	if (pkcs11_slots && pkcs11_ctx) {
		PKCS11_release_all_slots(pkcs11_ctx, pkcs11_slots,
					 pkcs11_nslots);
	}
	pkcs11_slots = NULL;
	pkcs11_nslots = 0;
	pkcs11_slot = NULL;

	if (pkcs11_ctx) {
		if (pkcs11_module_loaded)
			PKCS11_CTX_unload(pkcs11_ctx);
		PKCS11_CTX_free(pkcs11_ctx);
	}
	pkcs11_ctx = NULL;
	pkcs11_module_loaded = false;
}

static void esdm_es_pkcs11_finalize(void)
{
	mutex_lock(&pkcs11_mutex);
	esdm_es_pkcs11_finalize_locked();
	mutex_unlock(&pkcs11_mutex);

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
	if (pkcs11_buf_alloced) {
		esdm_es_buf_free(&pkcs11_buf);
		pkcs11_buf_alloced = false;
	}
#endif
}

/* Caller must hold pkcs11_mutex (write lock). */
static PKCS11_SLOT *esdm_es_pkcs11_pick_slot(void)
{
	const char *want_label = ESDM_PKCS11_TOKEN_LABEL;
	PKCS11_SLOT *slot;
	unsigned int i;

	for (i = 0; i < pkcs11_nslots; i++) {
		slot = &pkcs11_slots[i];
		if (!slot->token)
			continue;
		if (!slot->token->initialized)
			continue;
		if (!slot->token->hasRng)
			continue;
		if (want_label[0] != '\0' &&
		    (!slot->token->label ||
		     strcmp(slot->token->label, want_label) != 0))
			continue;
		return slot;
	}

	return NULL;
}

static int esdm_es_pkcs11_init(void)
{
	const char *module_path = ESDM_PKCS11_MODULE_PATH;
	const char *pin = ESDM_PKCS11_PIN;
	int logged_in = 0;

	mutex_lock(&pkcs11_mutex);

	/* Allow init to be called multiple times. */
	esdm_es_pkcs11_finalize_locked();

	if (module_path[0] == '\0') {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: no module path configured\n");
		goto out;
	}

	pkcs11_ctx = PKCS11_CTX_new();
	if (!pkcs11_ctx) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: PKCS11_CTX_new failed\n");
		goto out;
	}

	if (PKCS11_CTX_load(pkcs11_ctx, module_path) != 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: failed to load module %s\n",
			module_path);
		PKCS11_CTX_free(pkcs11_ctx);
		pkcs11_ctx = NULL;
		goto out;
	}
	pkcs11_module_loaded = true;

	if (PKCS11_enumerate_slots(pkcs11_ctx, &pkcs11_slots, &pkcs11_nslots) <
	    0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: failed to enumerate slots\n");
		pkcs11_slots = NULL;
		pkcs11_nslots = 0;
		esdm_es_pkcs11_finalize_locked();
		goto out;
	}

	pkcs11_slot = esdm_es_pkcs11_pick_slot();
	if (!pkcs11_slot) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: no usable token with RNG found\n");
		esdm_es_pkcs11_finalize_locked();
		goto out;
	}

	if (pin[0] != '\0' && pkcs11_slot->token->loginRequired) {
		if (PKCS11_is_logged_in(pkcs11_slot, 0, &logged_in) == 0 &&
		    !logged_in) {
			if (PKCS11_login(pkcs11_slot, 0, pin) != 0) {
				esdm_logger(
					LOGGER_WARN, LOGGER_C_ES,
					"Disabling PKCS#11 entropy source: login to token '%s' failed\n",
					pkcs11_slot->token->label ?
						pkcs11_slot->token->label :
						"(no label)");
				esdm_es_pkcs11_finalize_locked();
				goto out;
			}
			pkcs11_logged_in = true;
		}
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
		    "PKCS#11 entropy source using token '%s' (module %s)\n",
		    pkcs11_slot->token->label ? pkcs11_slot->token->label :
						"(no label)",
		    module_path);

out:
	mutex_unlock(&pkcs11_mutex);

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
	if (pkcs11_buf_alloced) {
		esdm_es_buf_reset(&pkcs11_buf);
	} else if (esdm_es_buf_alloc(&pkcs11_buf, ESDM_PKCS11_ENTROPY_BLOCKS,
				     "PKCS11") == 0) {
		pkcs11_buf_alloced = true;
	}
#endif

	return 0;
}

/* Caller must hold pkcs11_mutex. */
static uint32_t esdm_es_pkcs11_entropylevel_locked(uint32_t requested_bits)
{
	if (!pkcs11_slot)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_pkcs11_entropy_rate(), requested_bits);
}

static uint32_t esdm_es_pkcs11_entropylevel(uint32_t requested_bits)
{
	uint32_t ret;

	mutex_reader_lock(&pkcs11_mutex);
	ret = esdm_es_pkcs11_entropylevel_locked(requested_bits);
	mutex_reader_unlock(&pkcs11_mutex);

	return ret;
}

static uint32_t esdm_es_pkcs11_poolsize(void)
{
	uint32_t ret;

	mutex_reader_lock(&pkcs11_mutex);
	ret = esdm_es_pkcs11_entropylevel_locked(esdm_security_strength());
	mutex_reader_unlock(&pkcs11_mutex);

	return ret;
}

static void esdm_es_pkcs11_get_sync(struct entropy_es *eb_es,
				    uint32_t requested_bits)
{
	uint8_t buffer[ESDM_PKCS11_CHUNK_BYTES];
	uint32_t done_bits = 0;

	/*
	 * Take an exclusive lock: PKCS11_generate_random touches per-slot
	 * state and on errors we tear the connection down (write to shared
	 * state).
	 */
	mutex_lock(&pkcs11_mutex);

	if (!pkcs11_slot)
		goto err;

	while (done_bits < requested_bits) {
		uint32_t chunk_bits = min_uint32(
			ESDM_PKCS11_CHUNK_BYTES << 3, requested_bits - done_bits);
		uint32_t chunk_bytes = chunk_bits >> 3;

		if (PKCS11_generate_random(pkcs11_slot, buffer,
					   ESDM_PKCS11_CHUNK_BYTES) != 0) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"PKCS#11 C_GenerateRandom failed, disabling source\n");
			esdm_es_pkcs11_finalize_locked();
			goto err;
		}

		memcpy(eb_es->e + (done_bits >> 3), buffer, chunk_bytes);
		done_bits += chunk_bits;
	}

	eb_es->e_bits = esdm_es_pkcs11_entropylevel_locked(requested_bits);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from PKCS#11 entropy source\n",
		    eb_es->e_bits);

	mutex_unlock(&pkcs11_mutex);
	memset_secure(buffer, 0, sizeof(buffer));
	return;

err:
	mutex_unlock(&pkcs11_mutex);
	memset_secure(buffer, 0, sizeof(buffer));
	eb_es->e_bits = 0;
}

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)

static void esdm_es_pkcs11_buf_fill(struct entropy_es *eb_es,
				    uint32_t requested_bits, void *ctx)
{
	(void)ctx;
	esdm_es_pkcs11_get_sync(eb_es, requested_bits);
}

static int esdm_es_pkcs11_monitor(void)
{
	uint32_t requested_bits = esdm_get_seed_entropy_osr(false, false);

	if (!esdm_es_pkcs11_active())
		return 0;

	return esdm_es_buf_monitor(&pkcs11_buf, requested_bits,
				   esdm_es_pkcs11_buf_fill, NULL);
}

static void esdm_es_pkcs11_get(struct entropy_es *eb_es,
			       uint32_t requested_bits,
			       bool __unused unused)
{
	if (requested_bits == esdm_get_seed_entropy_osr(false, false) &&
	    esdm_es_buf_try_get(&pkcs11_buf, eb_es))
		return;

	esdm_es_pkcs11_get_sync(eb_es, requested_bits);
}

#else /* ESDM_PKCS11_ENTROPY_BLOCKS == 0 */

static void esdm_es_pkcs11_get(struct entropy_es *eb_es,
			       uint32_t requested_bits,
			       bool __unused unused)
{
	esdm_es_pkcs11_get_sync(eb_es, requested_bits);
}

#endif

static void esdm_es_pkcs11_es_state(char *buf, size_t buflen)
{
	uint32_t poolsize, entropy_rate;
	const char *token_label = "(none)";
	const char *module_path = ESDM_PKCS11_MODULE_PATH;

	mutex_reader_lock(&pkcs11_mutex);
	poolsize = esdm_es_pkcs11_entropylevel_locked(esdm_security_strength());
	entropy_rate = esdm_es_pkcs11_entropylevel_locked(256);
	if (pkcs11_slot && pkcs11_slot->token && pkcs11_slot->token->label)
		token_label = pkcs11_slot->token->label;
	mutex_reader_unlock(&pkcs11_mutex);

	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n"
		 " Module: %s\n"
		 " Token: %s\n",
		 poolsize, entropy_rate,
		 module_path[0] != '\0' ? module_path : "(unset)", token_label);
}

static bool esdm_es_pkcs11_active(void)
{
	bool ret;

	mutex_reader_lock(&pkcs11_mutex);
	ret = pkcs11_slot != NULL;
	mutex_reader_unlock(&pkcs11_mutex);

	return ret;
}

struct esdm_es_cb esdm_es_pkcs11 = {
	.name = "PKCS11",
	.init = esdm_es_pkcs11_init,
	.fini = esdm_es_pkcs11_finalize,
#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
	.monitor_es = esdm_es_pkcs11_monitor,
#else
	.monitor_es = NULL,
#endif
	.get_ent = esdm_es_pkcs11_get,
	.curr_entropy = esdm_es_pkcs11_entropylevel,
	.max_entropy = esdm_es_pkcs11_poolsize,
	.state = esdm_es_pkcs11_es_state,
	.reset = NULL,
	.active = esdm_es_pkcs11_active,
	.switch_hash = NULL,
};
