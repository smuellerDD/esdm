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
 * The messages of the external entropy source protocol, as es_ext.proto and
 * esdm_es_ext.h document them, and everything either side has to refuse.
 */

#include <stdio.h>

#include "common_test.h"
#include "esdm_es_ext_proto.h"

#define GET ESDM_ES_EXT_PROTO_GET_ENTROPY
#define SELF ESDM_ES_EXT_PROTO_SELFTEST
#define STAT ESDM_ES_EXT_PROTO_STATUS
#define INFO ESDM_ES_EXT_PROTO_INFO

/* A request of @version, whatever its values: its size */
static size_t test_req(uint8_t *out, uint32_t version, uint32_t type,
		       uint32_t length)
{
	EsExtRequest msg = ES_EXT_REQUEST__INIT;

	msg.version = version;
	msg.type = (EsExtType)type;
	msg.length = length;
	return es_ext_request__pack(&msg, out);
}

static void test_request(void)
{
	/* version 1, type 1, length 48: tag and varint each */
	static const uint8_t expected[] = { 0x08, 1, 0x10, 1, 0x18, 48 };
	static const struct {
		uint16_t type;
		uint32_t length;
		int ret;
	} cases[] = {
		{ GET, 1, 0 },
		{ GET, ESDM_ES_EXT_PROTO_MAX_DATA, 0 },
		{ GET, 0, -EPROTO },
		{ GET, ESDM_ES_EXT_PROTO_MAX_DATA + 1, -EPROTO },
		{ SELF, 0, 0 },
		{ SELF, 1, -EPROTO },
		{ STAT, 1, 0 },
		{ STAT, ESDM_ES_EXT_PROTO_STATUS_MAX, 0 },
		{ STAT, 0, -EPROTO },
		{ STAT, ESDM_ES_EXT_PROTO_STATUS_MAX + 1, -EPROTO },
		{ INFO, 0, 0 },
		{ INFO, 1, -EPROTO },
		{ 0, 0, -EPROTO },
		{ 3, 0, -EPROTO },
		{ INFO + 1, 0, -EPROTO },
	};
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_MAX + 1] = { 0 };
	uint32_t length;
	uint16_t type;
	unsigned int i;
	size_t len;
	int ret;

	len = esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_REQ_MAX, GET,
					 48);
	CHECK_EQ(len, sizeof(expected));
	CHECK_MEM_EQ(req, expected, sizeof(expected));
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, len, &type, &length), 0);
	CHECK(type == GET && length == 48, "the request is not decoded");
	CHECK_EQ(esdm_es_ext_proto_req_pack(req, len - 1, GET, 48), 0);

	/* Cut short, and a zero byte after it - no tag of any field */
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, len - 1, &type, &length),
		 -EPROTO);
	req[len] = 0;
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, len + 1, &type, &length),
		 -EPROTO);

	/* Another version, and none */
	len = test_req(req, 2, GET, 48);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, len, &type, &length),
		 -EPROTO);
	len = test_req(req, 0, GET, 48);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, len, &type, &length),
		 -EPROTO);

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		len = test_req(req, ESDM_ES_EXT_PROTO_VERSION, cases[i].type,
			       cases[i].length);
		ret = esdm_es_ext_proto_req_unpack(req, len, &type, &length);
		CHECK(ret == cases[i].ret &&
			      (ret || (type == cases[i].type &&
				       length == cases[i].length)),
		      "request %u: %d", i, ret);
	}
}

/* A response of @version, whatever its values: its size */
static size_t test_rsp(uint8_t *out, uint32_t version, uint32_t type,
		       int32_t status, uint32_t bits, size_t datalen,
		       size_t namelen)
{
	static uint8_t bytes[ESDM_ES_EXT_PROTO_MAX_RSP_DATA + 1];
	EsExtResponse msg = ES_EXT_RESPONSE__INIT;

	msg.version = version;
	msg.type = (EsExtType)type;
	msg.status = status;
	msg.entropy_bits = bits;
	msg.data.data = bytes;
	msg.data.len = datalen;
	msg.name.data = bytes;
	msg.name.len = namelen;
	return es_ext_response__pack(&msg, out);
}

static void test_response(void)
{
	/* INFO: version 1, type 5, no rate (5 byte varint), name "noise" */
	static const uint8_t expected[] = { 0x08, 1,	0x10, 5,    0x30, 0xff,
					    0xff, 0xff, 0xff, 0x0f, 0x3a, 5,
					    'n',  'o',	'i',  's',  'e' };
	/* The answer to @req of @length: @status, @bits, data and name */
	static const struct {
		uint16_t req, rsp;
		uint32_t length;
		int32_t status;
		uint32_t bits;
		size_t datalen, namelen;
		int ret;
	} cases[] = {
		/* The data asked for, at most 8 bits of entropy per byte */
		{ GET, GET, 32, 0, 256, 32, 0, 0 },
		{ GET, GET, 32, 0, 257, 32, 0, -EPROTO },
		{ GET, GET, 32, 0, 0, 31, 0, -EPROTO },
		{ GET, GET, 32, 0, 0, 33, 0, -EPROTO },
		{ GET, GET, 32, 0, 0, 32, 1, -EPROTO },
		/* An errno, with neither data nor entropy */
		{ GET, GET, 32, -EIO, 0, 0, 0, 0 },
		{ GET, GET, 32, -EIO, 8, 0, 0, -EPROTO },
		{ GET, GET, 32, -EIO, 0, 32, 0, -EPROTO },
		{ SELF, SELF, 0, -ESDM_ES_EXT_PROTO_MAX_ERRNO, 0, 0, 0, 0 },
		{ SELF, SELF, 0, -ESDM_ES_EXT_PROTO_MAX_ERRNO - 1, 0, 0, 0,
		  -EPROTO },
		{ SELF, SELF, 0, INT32_MIN, 0, 0, 0, -EPROTO },
		{ SELF, SELF, 0, 5, 0, 0, 0, -EPROTO },
		/* The answer to another request */
		{ GET, SELF, 32, 0, 0, 0, 0, -EPROTO },
		{ INFO, STAT, 0, 0, 0, 4, 0, -EPROTO },
		/* Nothing for a self test */
		{ SELF, SELF, 0, 0, 0, 1, 0, -EPROTO },
		{ SELF, SELF, 0, 0, 1, 0, 0, -EPROTO },
		/* 1 to length bytes of status */
		{ STAT, STAT, 100, 0, 0, 1, 0, 0 },
		{ STAT, STAT, 100, 0, 0, 100, 0, 0 },
		{ STAT, STAT, 100, 0, 0, 0, 0, -EPROTO },
		{ STAT, STAT, 100, 0, 0, 101, 0, -EPROTO },
		{ STAT, STAT, 100, 0, 8, 10, 0, -EPROTO },
		{ STAT, STAT, 100, -EOPNOTSUPP, 0, 0, 0, 0 },
		/* Up to ESDM_ES_EXT_NAME_MAX bytes of name, no data */
		{ INFO, INFO, 0, 0, 0, 0, 0, 0 },
		{ INFO, INFO, 0, 0, 0, 0, ESDM_ES_EXT_NAME_MAX, 0 },
		{ INFO, INFO, 0, 0, 0, 0, ESDM_ES_EXT_NAME_MAX + 1, -EPROTO },
		{ INFO, INFO, 0, 0, 0, 1, 0, -EPROTO },
		{ INFO, INFO, 0, 0, 1, 0, 0, -EPROTO },
		{ INFO, INFO, 0, -EIO, 0, 0, 4, -EPROTO },
	};
	uint8_t msg[ESDM_ES_EXT_PROTO_MSG_MAX];
	struct esdm_es_ext_proto_rsp rsp = { .type = INFO,
					     .rate = ESDM_ES_EXT_PROTO_RATE_NONE,
					     .name = "noise",
					     .namelen = 5 };
	unsigned int i;
	size_t len;
	int ret;

	len = esdm_es_ext_proto_rsp_pack(msg, sizeof(msg), &rsp);
	CHECK_EQ(len, sizeof(expected));
	CHECK_MEM_EQ(msg, expected, sizeof(expected));
	CHECK_EQ(esdm_es_ext_proto_rsp_pack(msg, len - 1, &rsp), 0);
	memset(&rsp, 0, sizeof(rsp));
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(msg, len, INFO, 0, &rsp), 0);
	CHECK(rsp.rate == ESDM_ES_EXT_PROTO_RATE_NONE && rsp.namelen == 5 &&
		      !memcmp(rsp.name, "noise", 5),
	      "INFO is not decoded");

	/* An errno sends neither entropy nor data */
	rsp = (struct esdm_es_ext_proto_rsp){
		.type = GET, .status = -EIO, .entropy_bits = 8, .datalen = 32
	};
	len = esdm_es_ext_proto_rsp_pack(msg, sizeof(msg), &rsp);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(msg, len, GET, 32, &rsp), 0);
	CHECK(rsp.status == -EIO && !rsp.entropy_bits && !rsp.datalen,
	      "an errno is sent with entropy or data");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		len = test_rsp(msg, ESDM_ES_EXT_PROTO_VERSION, cases[i].rsp,
			       cases[i].status, cases[i].bits, cases[i].datalen,
			       cases[i].namelen);
		ret = esdm_es_ext_proto_rsp_unpack(msg, len, cases[i].req,
						   cases[i].length, &rsp);
		CHECK(ret == cases[i].ret &&
			      (ret || (rsp.status == cases[i].status &&
				       rsp.entropy_bits == cases[i].bits &&
				       rsp.datalen == cases[i].datalen &&
				       rsp.namelen == cases[i].namelen)),
		      "response %u: %d", i, ret);
	}

	/* Cut short, another version, a zero byte after it */
	len = test_rsp(msg, ESDM_ES_EXT_PROTO_VERSION, SELF, 0, 0, 0, 0);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(msg, len, SELF, 0, &rsp), 0);
	msg[len] = 0;
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(msg, len + 1, SELF, 0, &rsp),
		 -EPROTO);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(msg, len - 1, SELF, 0, &rsp),
		 -EPROTO);
	len = test_rsp(msg, 2, SELF, 0, 0, 0, 0);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(msg, len, SELF, 0, &rsp),
		 -EPROTO);
}

static void test_helpers(void)
{
	CHECK_EQ(esdm_es_ext_errno(0), 0);
	CHECK_EQ(esdm_es_ext_errno(-ENODEV), -ENODEV);
	CHECK_EQ(esdm_es_ext_errno(-ESDM_ES_EXT_PROTO_MAX_ERRNO),
		 -ESDM_ES_EXT_PROTO_MAX_ERRNO);
	CHECK_EQ(esdm_es_ext_errno(-ESDM_ES_EXT_PROTO_MAX_ERRNO - 1), -EIO);
	CHECK_EQ(esdm_es_ext_errno(INT32_MIN), -EIO);
	CHECK_EQ(esdm_es_ext_errno(1), -EIO);

	CHECK_EQ(esdm_es_ext_rate_cap(0), 0);
	CHECK_EQ(esdm_es_ext_rate_cap(256), 256);
	CHECK_EQ(esdm_es_ext_rate_cap(257), 256);
	CHECK_EQ(esdm_es_ext_rate_cap(ESDM_ES_EXT_PROTO_RATE_NONE - 1), 256);
	CHECK_EQ(esdm_es_ext_rate_cap(ESDM_ES_EXT_PROTO_RATE_NONE),
		 ESDM_ES_EXT_PROTO_RATE_NONE);
}

/* What esdm_es_ext_utf8_valid() takes, and the names a source may declare */
static void test_utf8(void)
{
	/* Bit 0: ESDM_ES_EXT_UTF8, 1: _UTF8_SHOWN, 2: _UTF8_NAME */
	static const struct {
		const char *s;
		unsigned int kinds;
	} cases[] = {
		{ "a\xc3\xa4\xe2\x82\xac\xf0\x9f\x8e\xb2\xf4\x8f\xbf\xbf", 7 },
		/* C0 and DEL, C1 - U+009B is a CSI - next to NBSP */
		{ "\t", 3 },
		{ "\x1b", 3 },
		{ "\x7f", 3 },
		{ "\xc2\x80", 1 },
		{ "\xc2\x9b", 1 },
		{ "\xc2\x9f", 1 },
		{ "\xc2\xa0", 7 },
		/* Bidirectional controls next to what is none */
		{ "\xd8\x9c", 1 },
		{ "\xe2\x80\x8e", 1 },
		{ "\xe2\x80\x8f", 1 },
		{ "\xe2\x80\xaa", 1 },
		{ "\xe2\x80\xae", 1 },
		{ "\xe2\x81\xa6", 1 },
		{ "\xe2\x81\xa9", 1 },
		{ "\xd8\x9b\xd8\x9d\xe2\x80\x8d\xe2\x80\xa9\xe2\x80\xaf"
		  "\xe2\x81\xa5\xe2\x81\xaa",
		  7 },
		/* Overlong, surrogate, beyond U+10FFFF, cut short, stray */
		{ "\xc0\xaf", 0 },
		{ "\xe0\x82\xac", 0 },
		{ "\xf0\x82\x82\xac", 0 },
		{ "\xed\xa0\x80", 0 },
		{ "\xf4\x90\x80\x80", 0 },
		{ "\xf5\x80\x80\x80", 0 },
		{ "\xe2\x82", 0 },
		{ "\x80", 0 },
		{ "\xff", 0 },
	};
	unsigned int i, kind;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		for (kind = ESDM_ES_EXT_UTF8; kind <= ESDM_ES_EXT_UTF8_NAME;
		     kind++)
			CHECK(esdm_es_ext_utf8_valid(
				      cases[i].s, strlen(cases[i].s),
				      (enum esdm_es_ext_utf8)kind) ==
				      !!(cases[i].kinds & (1U << kind)),
			      "string %u, kind %u", i, kind);
	}
	CHECK(esdm_es_ext_utf8_valid("\0", 1, ESDM_ES_EXT_UTF8_SHOWN) &&
		      !esdm_es_ext_utf8_valid("\0", 1, ESDM_ES_EXT_UTF8_NAME),
	      "a NUL");

	/* 1 to ESDM_ES_EXT_NAME_MAX bytes */
	CHECK(esdm_es_ext_name_or_null("a") &&
		      esdm_es_ext_name_or_null(
			      "0123456789abcdef0123456789abcdef"),
	      "a name is refused");
	CHECK(!esdm_es_ext_name_or_null("") &&
		      !esdm_es_ext_name_or_null(
			      "0123456789abcdef0123456789abcdef0") &&
		      !esdm_es_ext_name_or_null("x\ny") &&
		      !esdm_es_ext_name_or_null(NULL) &&
		      !esdm_es_ext_name_valid(NULL, 1) &&
		      !esdm_es_ext_name_valid("a\0b", 3),
	      "a name is taken that is none");
}

int main(void)
{
	test_request();
	test_response();
	test_helpers();
	test_utf8();

	return common_test_result("es_ext_proto");
}
