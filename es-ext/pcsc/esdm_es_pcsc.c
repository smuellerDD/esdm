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
 * The random number generator of a smart card: GET CHALLENGE of ISO/IEC
 * 7816-4 over PC/SC, which nearly every card answers without an application
 * or a PIN. Set up on demand, and anew after a failure: a card pulled, or
 * pcscd restarted, costs the requests in between only.
 *
 * A card is tested - two challenges that have to differ - when it is
 * connected and on every self test. Its data is claimed at 8 bits per byte
 * while the last test passed, but no rate is declared: what the card is worth
 * is for its assessment to say - configured in the ESDM, or --entropy_rate.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <PCSC/winscard.h>
#include <json-c/json.h>

#include "esdm_es_ext_json.h"
#include "esdm_es_pcsc.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"

/* GET CHALLENGE: CLA, INS, P1, P2, then Le */
#define PCSC_INS_GET_CHALLENGE 0x84

/* Within the 2 s of a request: a GET CHALLENGE takes 10 to 50 ms */
#define PCSC_REQUEST_TIMEOUT_NS (1500 * 1000000ULL)

/* Compared by the test: a healthy card hardly repeats as many by chance */
#define PCSC_TEST_BYTES 16

struct esdm_es_pcsc_config esdm_es_pcsc_config = {
	.reader = NULL,
	.challenge_len = ESDM_ES_PCSC_CHALLENGE_LEN,
};

enum pcsc_test {
	PCSC_TEST_NONE,
	PCSC_TEST_PASSED,
	PCSC_TEST_FAILED,
};

struct pcsc_ctx {
	SCARDCONTEXT context;
	bool have_context;
	SCARDHANDLE card;
	bool connected;
	DWORD protocol;
	char reader[256];
	uint8_t atr[MAX_ATR_SIZE];
	DWORD atr_len;
	/* The last test of the card connected */
	enum pcsc_test test;

	unsigned long requests;
	unsigned long bytes;
	unsigned long failures;
	unsigned long connects;
	/* Why the card does not deliver, logged once; empty while it does */
	char last_error[128];
};

static void pcsc_error(struct pcsc_ctx *c, enum esdm_logger_verbosity level,
		       const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static void pcsc_error(struct pcsc_ctx *c, enum esdm_logger_verbosity level,
		       const char *fmt, ...)
{
	char msg[sizeof(c->last_error)];
	va_list args;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	if (!strcmp(msg, c->last_error))
		return;
	memcpy(c->last_error, msg, sizeof(msg));
	esdm_logger(level, LOGGER_C_ES, "PC/SC: %s\n", msg);
}

static void pcsc_disconnect(struct pcsc_ctx *c)
{
	if (c->connected)
		SCardDisconnect(c->card, SCARD_LEAVE_CARD);
	c->connected = false;
}

static void pcsc_release(struct pcsc_ctx *c)
{
	pcsc_disconnect(c);
	if (c->have_context)
		SCardReleaseContext(c->context);
	c->have_context = false;
}

/*
 * On failure, drop the card connection; if pcscd is gone, also release the
 * context
 */
static int pcsc_failed(struct pcsc_ctx *c, const char *what, LONG rv)
{
	pcsc_error(c, LOGGER_VERBOSE, "%s failed: %s", what,
		   pcsc_stringify_error(rv));

	if (rv == SCARD_E_NO_SERVICE || rv == SCARD_E_SERVICE_STOPPED ||
	    rv == SCARD_E_INVALID_HANDLE)
		pcsc_release(c);
	else
		pcsc_disconnect(c);

	return rv == SCARD_E_NO_SMARTCARD || rv == SCARD_W_REMOVED_CARD ||
			       rv == SCARD_E_NO_READERS_AVAILABLE ?
		       -ENODEV :
		       -EIO;
}

/* Connect to the card of the configured reader, or of the first one holding one */
static int pcsc_connect_card(struct pcsc_ctx *c)
{
	DWORD len = 0, reader_len, state, atr_len = sizeof(c->atr);
	char *readers, *r;
	LONG rv;

	if (!c->have_context) {
		rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
					   &c->context);
		if (rv != SCARD_S_SUCCESS)
			return pcsc_failed(c, "SCardEstablishContext", rv);
		c->have_context = true;
	}

	rv = SCardListReaders(c->context, NULL, NULL, &len);
	if (rv != SCARD_S_SUCCESS)
		return pcsc_failed(c, "SCardListReaders", rv);
	readers = calloc(1, (size_t)len + 1);
	if (!readers)
		return -ENOMEM;
	rv = SCardListReaders(c->context, NULL, readers, &len);
	if (rv != SCARD_S_SUCCESS) {
		free(readers);
		return pcsc_failed(c, "SCardListReaders", rv);
	}

	/* A multi-string: names ended by a NUL each, the list by another */
	for (r = readers; *r; r += strlen(r) + 1) {
		if (esdm_es_pcsc_config.reader &&
		    !strstr(r, esdm_es_pcsc_config.reader))
			continue;

		/* No card in this one: the next reader may have one */
		if (SCardConnect(c->context, r, SCARD_SHARE_SHARED,
				 SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
				 &c->card, &c->protocol) != SCARD_S_SUCCESS)
			continue;

		reader_len = 0;
		if (SCardStatus(c->card, NULL, &reader_len, &state, NULL,
				c->atr, &atr_len) != SCARD_S_SUCCESS)
			atr_len = 0;
		c->atr_len = atr_len;
		snprintf(c->reader, sizeof(c->reader), "%s", r);
		c->connected = true;
		c->connects++;
		c->test = PCSC_TEST_NONE;
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "PC/SC: reading the card in %s (T=%d)\n", c->reader,
			    c->protocol == SCARD_PROTOCOL_T1 ? 1 : 0);
		break;
	}
	free(readers);

	if (c->connected)
		return 0;
	pcsc_error(c, LOGGER_VERBOSE, "no card in %s",
		   esdm_es_pcsc_config.reader ? esdm_es_pcsc_config.reader :
						"any reader");
	return -ENODEV;
}

/*
 * One GET CHALLENGE for up to @len bytes into @buf. A card that does not
 * deliver as many tells how many it does (SW 6Cxx), and is asked again for
 * those.
 *
 * @return the bytes received, or a negative errno
 */
static int pcsc_challenge(struct pcsc_ctx *c, uint8_t *buf, size_t len)
{
	uint8_t apdu[5] = { 0x00, PCSC_INS_GET_CHALLENGE, 0x00, 0x00,
			    (uint8_t)len };
	uint8_t rsp[256 + 2], sw1, sw2;
	unsigned int attempt;
	int ret = -EIO;

	for (attempt = 0; attempt < 2; attempt++) {
		DWORD rsp_len = sizeof(rsp), datalen;
		size_t le = apdu[4] ? apdu[4] : 256;
		LONG rv;

		rv = SCardTransmit(c->card,
				   c->protocol == SCARD_PROTOCOL_T1 ?
					   SCARD_PCI_T1 :
					   SCARD_PCI_T0,
				   apdu, sizeof(apdu), NULL, rsp, &rsp_len);
		if (rv != SCARD_S_SUCCESS)
			return pcsc_failed(c, "SCardTransmit", rv);
		if (rsp_len < 2)
			rsp_len = 0;
		datalen = rsp_len ? rsp_len - 2 : 0;
		sw1 = rsp_len ? rsp[datalen] : 0;
		sw2 = rsp_len ? rsp[datalen + 1] : 0;

		/* Wrong length: Le is to be what the card says */
		if (sw1 == 0x6c && !datalen && !attempt) {
			apdu[4] = sw2;
			continue;
		}

		if (sw1 != 0x90 || sw2 != 0x00 || !datalen || datalen > le) {
			pcsc_error(
				c, LOGGER_WARN,
				"the card answers GET CHALLENGE with SW %02x%02x and %u bytes",
				sw1, sw2, (unsigned int)datalen);
			break;
		}

		ret = (int)(datalen < len ? datalen : len);
		memcpy(buf, rsp, (size_t)ret);
		break;
	}

	memset_secure(rsp, 0, sizeof(rsp));
	return ret;
}

/*
 * Fill @buf of @buflen bytes from the card connected, within one transaction
 * so that no other program's command comes in between
 */
static int pcsc_transact(struct pcsc_ctx *c, uint8_t *buf, size_t buflen)
{
	uint64_t start = esdm_monotonic_now_ns();
	size_t done = 0;
	LONG rv;
	int ret = 0;

	rv = SCardBeginTransaction(c->card);
	if (rv != SCARD_S_SUCCESS)
		return pcsc_failed(c, "SCardBeginTransaction", rv);

	while (done < buflen) {
		size_t chunk = buflen - done;

		if (chunk > esdm_es_pcsc_config.challenge_len)
			chunk = esdm_es_pcsc_config.challenge_len;
		ret = pcsc_challenge(c, buf + done, chunk);
		if (ret < 0)
			break;
		done += (size_t)ret;
		ret = 0;

		if (done < buflen && esdm_monotonic_now_ns() - start >=
					     PCSC_REQUEST_TIMEOUT_NS) {
			pcsc_error(c, LOGGER_WARN, "the card is too slow");
			ret = -ETIMEDOUT;
			break;
		}
	}

	/* The connection may be gone with a failure above already */
	if (c->connected)
		SCardEndTransaction(c->card, SCARD_LEAVE_CARD);
	return ret;
}

/*
 * Two reads of the card connected that have to differ: 0, -EFAULT if it
 * repeated itself, or why it did not deliver
 */
static int pcsc_test(struct pcsc_ctx *c)
{
	uint8_t first[PCSC_TEST_BYTES], second[PCSC_TEST_BYTES];
	int ret;

	ret = pcsc_transact(c, first, sizeof(first));
	if (!ret)
		ret = pcsc_transact(c, second, sizeof(second));
	if (!ret && !memcmp(first, second, sizeof(first))) {
		c->test = PCSC_TEST_FAILED;
		pcsc_error(c, LOGGER_ERR, "the card repeats its challenge");
		ret = -EFAULT;
	} else if (!ret) {
		c->test = PCSC_TEST_PASSED;
		c->last_error[0] = '\0';
	}

	memset_secure(first, 0, sizeof(first));
	memset_secure(second, 0, sizeof(second));
	return ret;
}

/*
 * A card connected and tested: one repeating itself stays connected, claimed
 * with nothing
 */
static int pcsc_connect(struct pcsc_ctx *c)
{
	int ret;

	if (!c->connected) {
		ret = pcsc_connect_card(c);
		if (ret)
			return ret;
	}
	if (c->test != PCSC_TEST_NONE)
		return 0;

	ret = pcsc_test(c);
	return ret == -EFAULT ? 0 : ret;
}

static int pcsc_init(void **ctx)
{
	struct pcsc_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return -ENOMEM;
	if (!esdm_es_pcsc_config.challenge_len ||
	    esdm_es_pcsc_config.challenge_len > 255) {
		free(c);
		return -EINVAL;
	}

	/* No card yet is no failure: it is looked for on every request */
	(void)pcsc_connect(c);

	*ctx = c;
	return 0;
}

static void pcsc_fini(void *ctx)
{
	struct pcsc_ctx *c = ctx;

	pcsc_release(c);
	free(c);
}

static int pcsc_get_entropy(void *ctx, uint8_t *buf, size_t buflen,
			    uint32_t *entropy_bits)
{
	struct pcsc_ctx *c = ctx;
	int ret = pcsc_connect(c);

	if (!ret)
		ret = pcsc_transact(c, buf, buflen);
	/* A card pulled and put back: it is there again on a new connection */
	if (ret == -EIO && !c->connected) {
		ret = pcsc_connect(c);
		if (!ret)
			ret = pcsc_transact(c, buf, buflen);
	}
	if (ret) {
		c->failures++;
		return ret;
	}

	c->requests++;
	c->bytes += buflen;
	*entropy_bits = 0;
	if (c->test == PCSC_TEST_PASSED) {
		c->last_error[0] = '\0';
		*entropy_bits = (uint32_t)(buflen * 8);
	}
	return 0;
}

/* Only a repeated challenge fails: a card not there is tested once connected */
static int pcsc_selftest(void *ctx)
{
	struct pcsc_ctx *c = ctx;
	int ret = 0;

	if (c->connected)
		ret = pcsc_test(c);
	return ret == -EFAULT ? -EFAULT : 0;
}

static int pcsc_status_json(void *ctx, char *buf, size_t buflen)
{
	static const char hex[] = "0123456789abcdef";
	struct pcsc_ctx *c = ctx;
	struct json_object *obj = json_object_new_object();
	char atr[2 * MAX_ATR_SIZE + 1];
	const char *text;
	DWORD i;
	int ret = -EMSGSIZE;

	if (!obj)
		return -ENOMEM;

	for (i = 0; i < c->atr_len && i < MAX_ATR_SIZE; i++) {
		atr[2 * i] = hex[c->atr[i] >> 4];
		atr[2 * i + 1] = hex[c->atr[i] & 0xf];
	}
	atr[2 * i] = '\0';

	json_object_object_add(obj, "connected",
			       json_object_new_boolean(c->connected));
	json_object_object_add(obj, "reader",
			       c->connected ? esdm_es_ext_json_text(c->reader) :
					      NULL);
	json_object_object_add(
		obj, "atr", c->connected ? json_object_new_string(atr) : NULL);
	json_object_object_add(
		obj, "repetition_test",
		json_object_new_string(c->test == PCSC_TEST_PASSED ? "passed" :
				       c->test == PCSC_TEST_FAILED ? "failed" :
								     "none"));
	json_object_object_add(
		obj, "challenge_len",
		json_object_new_int64(
			(int64_t)esdm_es_pcsc_config.challenge_len));
	json_object_object_add(obj, "requests",
			       json_object_new_int64((int64_t)c->requests));
	json_object_object_add(obj, "bytes",
			       json_object_new_int64((int64_t)c->bytes));
	json_object_object_add(obj, "failures",
			       json_object_new_int64((int64_t)c->failures));
	json_object_object_add(obj, "connects",
			       json_object_new_int64((int64_t)c->connects));
	json_object_object_add(obj, "last_error",
			       esdm_es_ext_json_text(c->last_error));

	text = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
	if (text && strlen(text) < buflen) {
		memcpy(buf, text, strlen(text) + 1);
		ret = 0;
	}
	json_object_put(obj);
	return ret;
}

const struct esdm_es_ext_plugin esdm_es_pcsc_plugin = {
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.name = "PC/SC",
	.init = pcsc_init,
	.fini = pcsc_fini,
	.get_entropy = pcsc_get_entropy,
	.selftest = pcsc_selftest,
	.status_json = pcsc_status_json,
};
