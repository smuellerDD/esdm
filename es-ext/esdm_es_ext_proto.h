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
 * The external entropy source protocol of esdm_es_ext.h, shared by the ESDM
 * and libesdm_es_ext: the messages of pb/es_ext.proto and the checks of their
 * values. Static inline, as both the ESDM and the library compile it; the
 * generated code is a file of its own, in both from es_ext_proto_src.
 */

#ifndef _ESDM_ES_EXT_PROTO_H
#define _ESDM_ES_EXT_PROTO_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "es_ext.pb-c.h"
#include "esdm_es_ext.h"
#include "memset_secure.h"

/* The largest errno, as the kernel has it - negating INT32_MIN is undefined */
#define ESDM_ES_EXT_PROTO_MAX_ERRNO 4095

/* The largest data of any response */
#define ESDM_ES_EXT_PROTO_MAX_RSP_DATA ESDM_ES_EXT_PROTO_STATUS_MAX

#if ESDM_ES_EXT_PROTO_MAX_DATA > ESDM_ES_EXT_PROTO_STATUS_MAX ||               \
	ESDM_ES_EXT_STATUS_MAX > ESDM_ES_EXT_PROTO_STATUS_MAX
#error "A response does not fit its buffer"
#endif

/*
 * Bounds of an encoded request and response: a field takes a tag byte, a
 * varint at most 5 bytes, bytes their length as a varint and themselves.
 */
#define ESDM_ES_EXT_PROTO_REQ_MAX 32
#define ESDM_ES_EXT_PROTO_MSG_MAX                                              \
	(64 + ESDM_ES_EXT_PROTO_MAX_RSP_DATA + ESDM_ES_EXT_NAME_MAX)

/* 0, a negative errno, or -EIO for what is neither */
static inline int esdm_es_ext_errno(int ret)
{
	return ret > 0 || ret < -ESDM_ES_EXT_PROTO_MAX_ERRNO ? -EIO : ret;
}

/* A declared entropy rate, capped; ESDM_ES_EXT_PROTO_RATE_NONE stays */
static inline uint32_t esdm_es_ext_rate_cap(uint32_t rate)
{
	return rate != ESDM_ES_EXT_PROTO_RATE_NONE &&
			       rate > ESDM_ES_EXT_ENTROPY_RATE_MAX ?
		       ESDM_ES_EXT_ENTROPY_RATE_MAX :
		       rate;
}

/*
 * The code point of the UTF-8 sequence at @s[*@i] of @len bytes, *@i moved
 * past it: RFC 3629, no overlong form, no surrogate, nothing beyond U+10FFFF.
 */
static inline bool esdm_es_ext_utf8_next(const unsigned char *s, size_t len,
					 size_t *i, uint32_t *cp)
{
	size_t n, j;

	if (s[*i] < 0x80) {
		*cp = s[(*i)++];
		return true;
	}

	if (s[*i] >= 0xc2 && s[*i] <= 0xdf) {
		n = 1;
		*cp = s[*i] & 0x1f;
	} else if (s[*i] >= 0xe0 && s[*i] <= 0xef) {
		n = 2;
		*cp = s[*i] & 0x0f;
	} else if (s[*i] >= 0xf0 && s[*i] <= 0xf4) {
		n = 3;
		*cp = s[*i] & 0x07;
	} else {
		return false;
	}

	if (len - *i <= n)
		return false;
	for (j = 1; j <= n; j++) {
		if ((s[*i + j] & 0xc0) != 0x80)
			return false;
		*cp = (*cp << 6) | (s[*i + j] & 0x3f);
	}

	if ((n == 2 && *cp < 0x800) || (n == 3 && *cp < 0x10000) ||
	    (*cp >= 0xd800 && *cp <= 0xdfff) || *cp > 0x10ffff)
		return false;

	*i += n + 1;
	return true;
}

/* What esdm_es_ext_utf8_allowed() refuses, next to what is no UTF-8 */
enum esdm_es_ext_utf8 {
	ESDM_ES_EXT_UTF8,
	/*
	 * C1 controls (U+009B is a CSI) and bidirectional controls, which
	 * reorder the text around them: either steers the terminal of whoever
	 * reads the ESDM status
	 */
	ESDM_ES_EXT_UTF8_SHOWN,
	/* As above, and C0 controls and DEL - NUL among them */
	ESDM_ES_EXT_UTF8_NAME,
};

static inline bool esdm_es_ext_utf8_allowed(uint32_t cp,
					    enum esdm_es_ext_utf8 kind)
{
	if (kind >= ESDM_ES_EXT_UTF8_SHOWN &&
	    ((cp >= 0x80 && cp <= 0x9f) || cp == 0x61c || cp == 0x200e ||
	     cp == 0x200f || (cp >= 0x202a && cp <= 0x202e) ||
	     (cp >= 0x2066 && cp <= 0x2069)))
		return false;
	return kind != ESDM_ES_EXT_UTF8_NAME || (cp >= 0x20 && cp != 0x7f);
}

static inline bool esdm_es_ext_utf8_valid(const char *s, size_t len,
					  enum esdm_es_ext_utf8 kind)
{
	size_t i = 0;
	uint32_t cp;

	while (i < len) {
		if (!esdm_es_ext_utf8_next((const unsigned char *)s, len, &i,
					   &cp) ||
		    !esdm_es_ext_utf8_allowed(cp, kind))
			return false;
	}

	return true;
}

/* Is @name of @len bytes one a source may declare - see esdm_es_ext.h? */
static inline bool esdm_es_ext_name_valid(const char *name, size_t len)
{
	return name && len && len <= ESDM_ES_EXT_NAME_MAX &&
	       esdm_es_ext_utf8_valid(name, len, ESDM_ES_EXT_UTF8_NAME);
}

/* The NUL-terminated @name if it is valid, NULL otherwise */
static inline const char *esdm_es_ext_name_or_null(const char *name)
{
	return name && esdm_es_ext_name_valid(
			       name, strnlen(name, ESDM_ES_EXT_NAME_MAX + 1)) ?
		       name :
		       NULL;
}

/*
 * A response: what a provider packs, what the ESDM unpacks. It holds entropy,
 * so it is wiped after use.
 *
 * @data: GET_ENTROPY: the data; STATUS: the JSON object
 * @rate: INFO: the rate declared, ESDM_ES_EXT_PROTO_RATE_NONE for none
 * @name: INFO: the name declared, not NUL terminated
 */
struct esdm_es_ext_proto_rsp {
	uint16_t type;
	int32_t status;
	uint32_t entropy_bits;
	uint8_t data[ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	size_t datalen;
	uint32_t rate;
	char name[ESDM_ES_EXT_NAME_MAX];
	size_t namelen;
};

/*
 * Unpacking allocates from memory on the stack, wiped afterwards: a bump
 * allocator that frees nothing. A message that needs more is no valid one.
 */
struct esdm_es_ext_proto_mem {
	uint8_t *buf;
	size_t len;
	size_t used;
};

static inline void *esdm_es_ext_proto_alloc(void *data, size_t size)
{
	struct esdm_es_ext_proto_mem *mem = data;
	size_t at = (mem->used + 15) & ~(size_t)15;

	if (at > mem->len || size > mem->len - at)
		return NULL;
	mem->used = at + size;
	return mem->buf + at;
}

static inline void esdm_es_ext_proto_free(void *data, void *ptr)
{
	(void)data;
	(void)ptr;
}

/* Encode a request into @out: its size, 0 if @outlen is too small */
static inline size_t esdm_es_ext_proto_req_pack(uint8_t *out, size_t outlen,
						uint16_t type, uint32_t length)
{
	EsExtRequest msg = ES_EXT_REQUEST__INIT;

	msg.version = ESDM_ES_EXT_PROTO_VERSION;
	msg.type = (EsExtType)type;
	msg.length = length;
	if (es_ext_request__get_packed_size(&msg) > outlen)
		return 0;
	return es_ext_request__pack(&msg, out);
}

/* @return 0, or -EPROTO for what is no valid request */
static inline int esdm_es_ext_proto_req_unpack(const uint8_t *in, size_t len,
					       uint16_t *type, uint32_t *length)
{
	_Alignas(16) uint8_t
		buf[sizeof(EsExtRequest) + ESDM_ES_EXT_PROTO_REQ_MAX + 64];
	struct esdm_es_ext_proto_mem mem = { .buf = buf, .len = sizeof(buf) };
	ProtobufCAllocator allocator = { .alloc = esdm_es_ext_proto_alloc,
					 .free = esdm_es_ext_proto_free,
					 .allocator_data = &mem };
	EsExtRequest *msg = es_ext_request__unpack(&allocator, len, in);
	uint32_t max = 0, min = 0;

	if (!msg || msg->version != ESDM_ES_EXT_PROTO_VERSION)
		return -EPROTO;

	switch ((uint32_t)msg->type) {
	case ESDM_ES_EXT_PROTO_GET_ENTROPY:
		min = 1;
		max = ESDM_ES_EXT_PROTO_MAX_DATA;
		break;
	case ESDM_ES_EXT_PROTO_STATUS:
		min = 1;
		max = ESDM_ES_EXT_PROTO_STATUS_MAX;
		break;
	case ESDM_ES_EXT_PROTO_SELFTEST:
	case ESDM_ES_EXT_PROTO_INFO:
		break;
	default:
		return -EPROTO;
	}
	if (msg->length < min || msg->length > max)
		return -EPROTO;

	*type = (uint16_t)msg->type;
	*length = msg->length;
	return 0;
}

/*
 * Encode the response @rsp into @out of @outlen bytes - with a status other
 * than 0 nothing but the status. Its size, 0 if it does not fit.
 */
static inline size_t
esdm_es_ext_proto_rsp_pack(uint8_t *out, size_t outlen,
			   const struct esdm_es_ext_proto_rsp *rsp)
{
	EsExtResponse msg = ES_EXT_RESPONSE__INIT;

	msg.version = ESDM_ES_EXT_PROTO_VERSION;
	msg.type = (EsExtType)rsp->type;
	msg.status = rsp->status;
	if (!rsp->status) {
		msg.entropy_bits = rsp->entropy_bits;
		msg.data.data = (uint8_t *)rsp->data;
		msg.data.len = rsp->datalen;
		if (rsp->type == ESDM_ES_EXT_PROTO_INFO) {
			msg.rate = rsp->rate;
			msg.name.data = (uint8_t *)rsp->name;
			msg.name.len = rsp->namelen;
		}
	}
	if (es_ext_response__get_packed_size(&msg) > outlen)
		return 0;
	return es_ext_response__pack(&msg, out);
}

/*
 * Decode the response of @len bytes at @in to a request of @type for @length
 * bytes into @rsp - checked in size, not in content.
 *
 * @return 0, or -EPROTO for what is no valid response to the request
 */
static inline int
esdm_es_ext_proto_rsp_unpack(const uint8_t *in, size_t len, uint16_t type,
			     uint32_t length, struct esdm_es_ext_proto_rsp *rsp)
{
	_Alignas(16) uint8_t
		buf[sizeof(EsExtResponse) + ESDM_ES_EXT_PROTO_MSG_MAX + 64];
	struct esdm_es_ext_proto_mem mem = { .buf = buf, .len = sizeof(buf) };
	ProtobufCAllocator allocator = { .alloc = esdm_es_ext_proto_alloc,
					 .free = esdm_es_ext_proto_free,
					 .allocator_data = &mem };
	EsExtResponse *msg = es_ext_response__unpack(&allocator, len, in);
	size_t min = 0, max = 0, namemax = 0;
	uint64_t bitsmax = 0;
	int ret = -EPROTO;

	if (!msg || msg->version != ESDM_ES_EXT_PROTO_VERSION ||
	    (uint32_t)msg->type != type || msg->status > 0 ||
	    msg->status < -ESDM_ES_EXT_PROTO_MAX_ERRNO)
		goto out;

	if (!msg->status && type == ESDM_ES_EXT_PROTO_GET_ENTROPY) {
		min = max = length;
		bitsmax = (uint64_t)length * 8;
	} else if (!msg->status && type == ESDM_ES_EXT_PROTO_STATUS) {
		min = 1;
		max = length;
	} else if (!msg->status && type == ESDM_ES_EXT_PROTO_INFO) {
		namemax = ESDM_ES_EXT_NAME_MAX;
	}
	if (msg->data.len < min || msg->data.len > max ||
	    msg->name.len > namemax || msg->entropy_bits > bitsmax)
		goto out;

	rsp->type = type;
	rsp->status = msg->status;
	rsp->entropy_bits = msg->entropy_bits;
	rsp->datalen = msg->data.len;
	if (rsp->datalen)
		memcpy(rsp->data, msg->data.data, rsp->datalen);
	rsp->rate = msg->rate;
	rsp->namelen = msg->name.len;
	if (rsp->namelen)
		memcpy(rsp->name, msg->name.data, rsp->namelen);
	ret = 0;

out:
	memset_secure(buf, 0, sizeof(buf));
	return ret;
}

#endif /* _ESDM_ES_EXT_PROTO_H */
