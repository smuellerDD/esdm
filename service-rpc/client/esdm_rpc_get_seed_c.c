/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "esdm_rpc_client_helper.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_service.h"
#include "math_helper.h"
#include "esdm_logger.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_get_seed_buf {
	ssize_t ret;
	uint8_t *buf;
	/* Capacity of buf - set by the caller and never modified here. */
	size_t buflen;
	/* Number of bytes the callback copied into buf. */
	size_t copied;
};

static void esdm_rpcc_get_seed_cb(const RandValResponse *response,
				  void *closure_data)
{
	struct esdm_get_seed_buf *buffer =
		(struct esdm_get_seed_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);

	buffer->ret = response->ret;

	/*
	 * Track the copied length separately from the caller's capacity: the
	 * request is retried while the server responds -EAGAIN (which it does
	 * whenever another caller currently holds the server-side seed lock)
	 * and such a response carries no payload. Folding that zero length back
	 * into the capacity would clamp it to 0 for good, so the retry that
	 * finally succeeds would copy nothing while still reporting the
	 * server's positive byte count to the caller.
	 */
	buffer->copied = min_size(response->randval.len, buffer->buflen);

	/*
	 * Copy whatever payload the response carries, not only the one of a
	 * successful call.
	 *
	 * esdm_get_seed() documents that a buffer of at least uint64_t but too
	 * small for the whole seed is answered with -EMSGSIZE and the required
	 * length written into it, which is the only way a caller can learn how
	 * much to allocate. The server implements that and attaches the length
	 * to the failing response, so gating the copy on a positive return code
	 * discarded it: the caller's size stayed whatever it was - zero for the
	 * documented "ask with a small buffer first" sequence - and the request
	 * it sized from that then failed with -EINVAL for good.
	 *
	 * Responses without a payload keep the buffer untouched: a retried
	 * -EAGAIN carries none, and neither does the length check the server
	 * performs before it ever calls esdm_get_seed().
	 */
	if (buffer->copied && response->randval.data != NULL &&
	    buffer->buf != NULL) {
		memcpy(buffer->buf, response->randval.data, buffer->copied);
	}

	/* Zeroization of response is handled in esdm_rpc_client_read_handler */
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_seed_int(uint8_t *buf, size_t buflen, unsigned int flags,
			       void *int_data)
{
	GetSeedRequest msg = GET_SEED_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_get_seed_buf buffer = {
		.ret = -ETIMEDOUT,
		.buf = buf,
		.buflen = buflen,
		.copied = 0,
	};
	ssize_t ret = 0;
	int noblock = flags & ESDM_GET_SEED_NONBLOCK;

	CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));

	msg.len = buflen;
	msg.flags = flags;

	for (;;) {
		/*
		 * Re-arm the placeholder for every attempt: a retry whose
		 * callback does not run must not inherit the previous round's
		 * result.
		 */
		buffer.ret = -ETIMEDOUT;
		buffer.copied = 0;

		unpriv_access__rpc_get_seed(&rpc_conn->service, &msg,
					    esdm_rpcc_get_seed_cb, &buffer);

		/*
		 * The callback only runs once a response was received. When the
		 * request failed before that - no server listening, a refused
		 * or broken connection - buffer.ret still holds the placeholder
		 * set above, which would report every such failure as a
		 * timeout. Report what actually went wrong instead.
		 */
		ret = esdm_rpcc_last_error(rpc_conn);
		if (ret)
			goto out;

		ret = buffer.ret;
		if (ret >= 0)
			esdm_test_shm_status_add_rpc_client_written(
				buffer.copied);
		if (noblock || ret != -EAGAIN)
			break;

		/*
		 * The server-side always invokes the command non-blocking.
		 * Thus, we need to loop, in case the caller did not request
		 * non-blocking and ESDM cannot deliver data.
		 */
		nanosleep(&esdm_client_poll_ts, NULL);
	}

out:
	esdm_rpcc_put_unpriv_service(rpc_conn);
	return ret;
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_seed(uint8_t *buf, size_t buflen, unsigned int flags)
{
	return esdm_rpcc_get_seed_int(buf, buflen, flags, NULL);
}
