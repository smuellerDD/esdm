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
 * A client of the external entropy source protocol for the tests, speaking
 * to a provider as the ESDM does - see esdm_es_ext.h.
 */

#ifndef _ES_EXT_TEST_CLIENT_H
#define _ES_EXT_TEST_CLIENT_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "esdm_es_ext_json.h"

/* A byte more than the largest answer, to tell a longer one */
#define ES_EXT_TEST_CLIENT_RSP_MAX (ESDM_ES_EXT_PROTO_MSG_MAX + 1)

/* The connection, and the answer es_ext_test_client_ask() got last */
struct es_ext_test_client {
	int fd;
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	struct esdm_es_ext_proto_rsp ans;
	int32_t status;
	uint32_t bits;
	const uint8_t *data;
	size_t datalen;
};

static inline void es_ext_test_client_close(struct es_ext_test_client *c)
{
	if (c->fd >= 0)
		close(c->fd);
	c->fd = -1;
}

/* Connect to the provider on @path: 0, or a negative errno */
static inline int es_ext_test_client_open(struct es_ext_test_client *c,
					  const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	/* How long an answer may take */
	struct timeval tv = { .tv_sec = 5 };
	int ret = 0;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	c->fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (c->fd < 0 ||
	    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) ||
	    connect(c->fd, (struct sockaddr *)&addr, sizeof(addr))) {
		ret = -errno;
		es_ext_test_client_close(c);
	}

	return ret;
}

/*
 * Send a request of @type for @length bytes and receive the answer into @rsp
 * of @rsplen bytes
 *
 * @return the size of the answer, 0 if the provider closed the connection, a
 *	   negative errno
 */
static inline ssize_t es_ext_test_client_request(struct es_ext_test_client *c,
						 uint16_t type, uint32_t length,
						 uint8_t *rsp, size_t rsplen)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_MAX];
	size_t reqlen =
		esdm_es_ext_proto_req_pack(req, sizeof(req), type, length);
	ssize_t n;

	if (!reqlen ||
	    send(c->fd, req, reqlen, MSG_NOSIGNAL) != (ssize_t)reqlen)
		return -EIO;
	n = recv(c->fd, rsp, rsplen, 0);
	return n < 0 ? -errno : n;
}

/*
 * Ask for @type of @length bytes, the answer decoded into @c: its status, 1
 * for no valid answer - none, or the connection closed
 */
static inline int es_ext_test_client_ask(struct es_ext_test_client *c,
					 uint16_t type, uint32_t length)
{
	ssize_t n = es_ext_test_client_request(c, type, length, c->rsp,
					       sizeof(c->rsp));

	c->data = NULL;
	c->datalen = 0;
	c->bits = 0;
	if (n <= 0 || esdm_es_ext_proto_rsp_unpack(c->rsp, (size_t)n, type,
						   length, &c->ans))
		return 1;
	c->status = c->ans.status;
	c->bits = c->ans.entropy_bits;
	c->data = c->ans.datalen ? c->ans.data : NULL;
	c->datalen = c->ans.datalen;
	return c->status;
}

/* INFO: 0 with the name - "" for none - and the rate, -1 for none */
static inline int es_ext_test_client_info(struct es_ext_test_client *c,
					  char *name, size_t size,
					  uint32_t *rate)
{
	if (es_ext_test_client_ask(c, ESDM_ES_EXT_PROTO_INFO, 0) ||
	    c->ans.namelen >= size)
		return -1;
	*rate = c->ans.rate;
	memcpy(name, c->ans.name, c->ans.namelen);
	name[c->ans.namelen] = '\0';
	return 0;
}

/* STATUS for @length bytes, checked as the ESDM checks it: NULL for none */
static inline struct json_object *
es_ext_test_client_status(struct es_ext_test_client *c, uint32_t length)
{
	if (es_ext_test_client_ask(c, ESDM_ES_EXT_PROTO_STATUS, length))
		return NULL;
	return esdm_es_ext_json_object((const char *)c->data, c->datalen,
				       ESDM_ES_EXT_PROTO_STATUS_MAX,
				       ESDM_ES_EXT_STATUS_MAX_DEPTH + 1);
}

#endif /* _ES_EXT_TEST_CLIENT_H */
