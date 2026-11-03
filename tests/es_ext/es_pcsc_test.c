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
 * Test the PC/SC entropy source against a smart card of its own making
 *
 * The source, es-ext/pcsc/esdm_es_pcsc.c, is compiled in; the PC/SC functions
 * it calls are defined here, emulating pcscd with readers and cards whose
 * answers the test steers. Covered:
 *
 *   - GET CHALLENGE as ISO/IEC 7816-4 has it, in chunks of the configured
 *     length within one transaction, and the data handed out as the card gave
 *     it, claimed at 8 bits per byte,
 *   - a card delivering fewer bytes than asked for (SW 6Cxx) asked again,
 *   - no reader, no card, and the configured reader picked by its name,
 *   - a card reset during a request reconnected in the same request, a
 *     pcscd gone set up anew on the next one,
 *   - a card refusing GET CHALLENGE, the transaction ended all the same, the
 *     failure logged once and cleared once the card delivers,
 *   - every card connected tested, 16 bytes twice: one repeating itself is
 *     claimed with nothing until a self test passes; no card fails no self
 *     test,
 *   - the status, a reader name with a control character in it,
 *   - esdm-es-pcsc refusing a challenge length out of range.
 *
 * Usage: es_pcsc_test [<esdm-es-pcsc>]
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <PCSC/winscard.h>

#include "common_test.h"
#include "es_ext_test_util.h"
#include "esdm_es_pcsc.h"

/******************************** The fake pcscd ******************************/

/* It implements an API, most of whose arguments it has no use for */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define TEST_READERS 2

static struct {
	bool service;
	const char *reader[TEST_READERS];
	bool card[TEST_READERS];
	/* The card answers GET CHALLENGE for at most this many bytes */
	unsigned int max_len;
	/* SW 6D00: no GET CHALLENGE */
	bool refuse;
	/* The same bytes every time */
	bool stuck;
	/* The next transmission fails with this */
	LONG fail_once;

	/* The byte the next challenge starts with */
	uint8_t next;
	unsigned int contexts, connects, transmits, transactions;
	bool in_transaction;
	int connected_reader;
	uint8_t last_le;
} card;

const SCARD_IO_REQUEST g_rgSCardT0Pci = { SCARD_PROTOCOL_T0,
					  sizeof(SCARD_IO_REQUEST) };
const SCARD_IO_REQUEST g_rgSCardT1Pci = { SCARD_PROTOCOL_T1,
					  sizeof(SCARD_IO_REQUEST) };
const SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW,
					   sizeof(SCARD_IO_REQUEST) };

/* One card in the first of two readers, the source asking 8 bytes at a time */
static void test_card_reset(void)
{
	memset(&card, 0, sizeof(card));
	card.service = true;
	card.reader[0] = "Fake Reader 00 00";
	card.reader[1] = "Second Fake Reader 01 00";
	card.card[0] = true;
	card.max_len = 255;
	card.connected_reader = -1;
	esdm_es_pcsc_config.reader = NULL;
	esdm_es_pcsc_config.challenge_len = 8;
}

const char *pcsc_stringify_error(const LONG rv)
{
	static char buf[32];

	snprintf(buf, sizeof(buf), "error 0x%08x", (unsigned int)rv);
	return buf;
}

LONG SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1,
			   LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
	if (!card.service)
		return SCARD_E_NO_SERVICE;
	card.contexts++;
	*phContext = 1;
	return SCARD_S_SUCCESS;
}

LONG SCardReleaseContext(SCARDCONTEXT hContext)
{
	return SCARD_S_SUCCESS;
}

LONG SCardListReaders(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders,
		      LPDWORD pcchReaders)
{
	char list[256];
	size_t len = 0;
	unsigned int i;

	if (!card.service)
		return SCARD_E_NO_SERVICE;
	for (i = 0; i < TEST_READERS; i++) {
		if (!card.reader[i])
			continue;
		memcpy(list + len, card.reader[i], strlen(card.reader[i]) + 1);
		len += strlen(card.reader[i]) + 1;
	}
	if (!len)
		return SCARD_E_NO_READERS_AVAILABLE;
	list[len++] = '\0';

	if (mszReaders) {
		if (*pcchReaders < len)
			return SCARD_E_INSUFFICIENT_BUFFER;
		memcpy(mszReaders, list, len);
	}
	*pcchReaders = (DWORD)len;
	return SCARD_S_SUCCESS;
}

LONG SCardConnect(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode,
		  DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
		  LPDWORD pdwActiveProtocol)
{
	unsigned int i;

	for (i = 0; i < TEST_READERS; i++) {
		if (!card.reader[i] || strcmp(card.reader[i], szReader))
			continue;
		if (!card.card[i])
			return SCARD_E_NO_SMARTCARD;
		card.connects++;
		card.connected_reader = (int)i;
		*phCard = (SCARDHANDLE)(10 + i);
		*pdwActiveProtocol = SCARD_PROTOCOL_T1;
		return SCARD_S_SUCCESS;
	}
	return SCARD_E_UNKNOWN_READER;
}

LONG SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition)
{
	card.connected_reader = -1;
	card.in_transaction = false;
	return SCARD_S_SUCCESS;
}

LONG SCardBeginTransaction(SCARDHANDLE hCard)
{
	CHECK(!card.in_transaction, "a transaction begun inside another");
	card.in_transaction = true;
	card.transactions++;
	return SCARD_S_SUCCESS;
}

LONG SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition)
{
	CHECK(card.in_transaction, "a transaction ended that was not begun");
	card.in_transaction = false;
	return SCARD_S_SUCCESS;
}

LONG SCardStatus(SCARDHANDLE hCard, LPSTR mszReaderName, LPDWORD pcchReaderLen,
		 LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr,
		 LPDWORD pcbAtrLen)
{
	static const uint8_t atr[] = { 0x3b, 0x02, 0x14, 0x50 };

	*pcchReaderLen = 0;
	*pdwState = SCARD_SPECIFIC;
	memcpy(pbAtr, atr, sizeof(atr));
	*pcbAtrLen = sizeof(atr);
	return SCARD_S_SUCCESS;
}

LONG SCardTransmit(SCARDHANDLE hCard, const SCARD_IO_REQUEST *pioSendPci,
		   LPCBYTE pbSendBuffer, DWORD cbSendLength,
		   SCARD_IO_REQUEST *pioRecvPci, LPBYTE pbRecvBuffer,
		   LPDWORD pcbRecvLength)
{
	unsigned int le, i;

	CHECK(pioSendPci == SCARD_PCI_T1, "not the PCI of T=1");
	CHECK(card.in_transaction, "a command outside of a transaction");
	CHECK(cbSendLength == 5 && pbSendBuffer[0] == 0x00 &&
		      pbSendBuffer[1] == 0x84 && pbSendBuffer[2] == 0x00 &&
		      pbSendBuffer[3] == 0x00,
	      "no GET CHALLENGE");
	card.transmits++;

	if (card.fail_once) {
		LONG rv = card.fail_once;

		card.fail_once = 0;
		return rv;
	}

	le = pbSendBuffer[4] ? pbSendBuffer[4] : 256;
	card.last_le = pbSendBuffer[4];
	if (card.refuse || le > card.max_len) {
		pbRecvBuffer[0] = card.refuse ? 0x6d : 0x6c;
		pbRecvBuffer[1] = card.refuse ? 0 : (uint8_t)card.max_len;
		*pcbRecvLength = 2;
		return SCARD_S_SUCCESS;
	}

	CHECK(*pcbRecvLength >= le + 2, "a receive buffer too small");
	for (i = 0; i < le; i++)
		pbRecvBuffer[i] = card.stuck ? 0x42 : card.next++;
	pbRecvBuffer[le] = 0x90;
	pbRecvBuffer[le + 1] = 0x00;
	*pcbRecvLength = le + 2;
	return SCARD_S_SUCCESS;
}

/********************************** The tests *********************************/

static const struct esdm_es_ext_plugin *src = &esdm_es_pcsc_plugin;

/* The source set up, the test of its card done: counted from here on */
static void *test_init(void)
{
	void *ctx = NULL;

	CHECK_EQ(src->init(&ctx), 0);
	card.next = 0;
	card.transmits = card.transactions = 0;
	return ctx;
}

static int test_status_has(void *ctx, const char *what)
{
	static char status[1024];

	CHECK_EQ(src->status_json(ctx, status, sizeof(status)), 0);
	if (strstr(status, what))
		return 1;
	printf("no %s in %s\n", what, status);
	return 0;
}

/* The bytes a card counting from @from gives for @len */
static int test_counted(const uint8_t *buf, size_t len, uint8_t from)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i] != (uint8_t)(from + i))
			return 0;
	}
	return 1;
}

static void test_read(void)
{
	uint8_t buf[32];
	uint32_t bits = 0;
	void *ctx = NULL;

	test_card_reset();
	ctx = test_init();
	CHECK_EQ(card.connects, 1);

	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(bits, 256);
	CHECK(test_counted(buf, sizeof(buf), 0), "not the bytes of the card");
	/* 4 GET CHALLENGE of 8 bytes, in one transaction */
	CHECK_EQ(card.transmits, 4);
	CHECK_EQ(card.last_le, 8);
	CHECK_EQ(card.transactions, 1);
	CHECK(!card.in_transaction, "the transaction is left open");

	/* A request not a multiple of the chunk: the last one is shorter */
	CHECK_EQ(src->get_entropy(ctx, buf, 13, &bits), 0);
	CHECK_EQ(bits, 104);
	CHECK(test_counted(buf, 13, 32), "not the bytes of the card");
	CHECK_EQ(card.last_le, 5);

	CHECK_EQ(card.connects, 1);
	src->fini(ctx);

	/* Asked for 16, the card gives 4 at a time: asked again for those */
	test_card_reset();
	card.max_len = 4;
	esdm_es_pcsc_config.challenge_len = 16;
	ctx = test_init();
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK(test_counted(buf, sizeof(buf), 0), "not the bytes of the card");
	CHECK_EQ(card.last_le, 4);
	/* Twice for 7 chunks, once for the last 4 bytes asked for as such */
	CHECK_EQ(card.transmits, 15);
	src->fini(ctx);

	/* The test compares 16 bytes, whatever the chunk */
	test_card_reset();
	esdm_es_pcsc_config.challenge_len = 1;
	CHECK_EQ(src->init(&ctx), 0);
	CHECK_EQ(card.transmits, 32);
	src->fini(ctx);
}

static void test_readers(void)
{
	char status[1024];
	uint8_t buf[8];
	uint32_t bits = 0;
	void *ctx = NULL;

	/* No reader: no failure to start, but no data */
	test_card_reset();
	card.reader[0] = card.reader[1] = NULL;
	CHECK_EQ(src->init(&ctx), 0);
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), -ENODEV);
	CHECK_EQ(src->status_json(ctx, status, sizeof(status)), 0);
	CHECK(strstr(status, "\"connected\":false"), "%s", status);

	/* A reader shows up: taken on the next request */
	card.reader[0] = "Fake Reader 00 00";
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	src->fini(ctx);

	/* The card in the second reader, found there */
	test_card_reset();
	card.card[0] = false;
	card.card[1] = true;
	CHECK_EQ(src->init(&ctx), 0);
	CHECK_EQ(card.connected_reader, 1);
	src->fini(ctx);

	/* The reader configured, none other: no card there, no data */
	test_card_reset();
	card.card[1] = false;
	esdm_es_pcsc_config.reader = "Second";
	CHECK_EQ(src->init(&ctx), 0);
	CHECK_EQ(card.connected_reader, -1);
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), -ENODEV);
	card.card[1] = true;
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(card.connected_reader, 1);

	CHECK_EQ(src->status_json(ctx, status, sizeof(status)), 0);
	CHECK(strstr(status, "\"reader\":\"Second Fake Reader 01 00\"") &&
		      strstr(status, "\"atr\":\"3b021450\"") &&
		      strstr(status, "\"requests\":1"),
	      "%s", status);
	/* Too small for it: refused, not cut short */
	CHECK_EQ(src->status_json(ctx, status, 16), -EMSGSIZE);
	src->fini(ctx);

	/* A control character in the name of the reader is not passed on */
	test_card_reset();
	card.reader[0] = "Odd\x1b[2J Reader";
	CHECK_EQ(src->init(&ctx), 0);
	CHECK(test_status_has(ctx, "\"reader\":\"Odd?[2J Reader\""),
	      "the reader name as it is");
	src->fini(ctx);
}

static void test_recovery(void)
{
	uint8_t buf[16];
	uint32_t bits = 0;
	void *ctx = NULL;

	/* A card reset by another program: reconnected in the same request */
	test_card_reset();
	CHECK_EQ(src->init(&ctx), 0);
	card.fail_once = SCARD_W_RESET_CARD;
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(card.connects, 2);
	CHECK(!card.in_transaction, "the transaction is left open");

	/* pcscd gone: this request fails, the next sets everything up anew */
	card.fail_once = SCARD_E_NO_SERVICE;
	card.service = false;
	CHECK(src->get_entropy(ctx, buf, sizeof(buf), &bits) < 0,
	      "data without pcscd");
	card.service = true;
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(card.contexts, 2);
	CHECK_EQ(card.connects, 3);

	/* A card refusing GET CHALLENGE: no data, the transaction ended */
	card.refuse = true;
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), -EIO);
	CHECK(!card.in_transaction, "the transaction is left open");
	CHECK(test_status_has(ctx, "\"last_error\":\"the card answers GET "
				   "CHALLENGE with SW 6d00 and 0 bytes\""),
	      "the refusal not told");
	card.refuse = false;
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK(test_status_has(ctx, "\"last_error\":null"),
	      "the refusal told after the card delivered");
	src->fini(ctx);
}

static void test_selftest(void)
{
	uint8_t buf[16];
	uint32_t bits = 0;
	void *ctx = NULL;

	/* A card repeating itself is claimed with nothing until it passes */
	test_card_reset();
	CHECK_EQ(src->init(&ctx), 0);
	CHECK_EQ(src->selftest(ctx), 0);
	card.stuck = true;
	CHECK_EQ(src->selftest(ctx), -EFAULT);
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(bits, 0);
	CHECK(test_status_has(ctx, "\"repetition_test\":\"failed\""),
	      "the failed test not told");
	card.stuck = false;
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(bits, 0);
	CHECK_EQ(src->selftest(ctx), 0);
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(bits, 128);
	src->fini(ctx);

	/* No card is no failure; one put in is tested before it is claimed */
	test_card_reset();
	card.card[0] = false;
	CHECK_EQ(src->init(&ctx), 0);
	CHECK_EQ(src->selftest(ctx), 0);
	card.card[0] = true;
	card.stuck = true;
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(bits, 0);

	/* Swapped for one that is fine: tested on the new connection */
	card.stuck = false;
	card.fail_once = SCARD_W_RESET_CARD;
	CHECK_EQ(src->get_entropy(ctx, buf, sizeof(buf), &bits), 0);
	CHECK_EQ(bits, 128);
	CHECK_EQ(card.connects, 2);
	src->fini(ctx);

	/* A length out of range is refused by the init */
	esdm_es_pcsc_config.challenge_len = 0;
	CHECK_EQ(src->init(&ctx), -EINVAL);
	esdm_es_pcsc_config.challenge_len = 256;
	CHECK_EQ(src->init(&ctx), -EINVAL);
}

/* What esdm-es-pcsc cannot run with, it refuses to start with */
static void test_cli(const char *pcsc)
{
	static const char *const bad[] = { "0", "256", "-1", "8x", "" };
	char *argv[] = { (char *)pcsc,	    "--socket", "/nonexistent/s",
			 "--challenge_len", NULL,	NULL };
	unsigned int i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		argv[4] = (char *)bad[i];
		CHECK(es_ext_test_wait(es_ext_test_spawn(argv, NULL)) == 1,
		      "--challenge_len \"%s\" is not refused", bad[i]);
	}
	argv[1] = "--help";
	argv[2] = NULL;
	CHECK_EQ(es_ext_test_wait(es_ext_test_spawn(argv, NULL)), 0);
}

int main(int argc, char *argv[])
{
	test_read();
	test_readers();
	test_recovery();
	test_selftest();
	if (argc > 1)
		test_cli(argv[1]);

	return common_test_result("es_pcsc");
}
