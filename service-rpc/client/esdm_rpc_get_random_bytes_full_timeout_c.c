/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

struct esdm_get_random_bytes_full_timeout_buf {
	ssize_t ret;
	uint8_t *buf;
	size_t buflen;
};

static void
esdm_rpcc_get_random_bytes_full_timeout_cb(
	const GetRandomBytesFullTimeoutResponse *response,
	void *closure_data)
{
	struct esdm_get_random_bytes_full_timeout_buf *buffer =
		(struct esdm_get_random_bytes_full_timeout_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);

	if (response->ret < 0) {
		buffer->ret = response->ret;
		return;
	}

	buffer->ret = (ssize_t)min_size(response->randval.len, buffer->buflen);
	memcpy(buffer->buf, response->randval.data, (size_t)buffer->ret);

	/* Zeroization of response is handled in esdm_rpc_client_read_handler */
}

static bool esdm_time_after(struct timespec *curr, struct timespec *timeout)
{
	if (curr == NULL || timeout == NULL) {
		return false;
	}

	if (curr->tv_sec > timeout->tv_sec)
		return true;
	if (curr->tv_sec == timeout->tv_sec && curr->tv_nsec > timeout->tv_nsec)
		return true;

	return false;
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_full_timeout_int(uint8_t *buf, size_t buflen,
						    struct timespec *ts,
						    void *int_data)
{
	GetRandomBytesFullTimeoutRequest msg =
		GET_RANDOM_BYTES_FULL_TIMEOUT_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_get_random_bytes_full_timeout_buf buffer;
	size_t maxbuflen = buflen, orig_buflen = buflen;
	struct timespec timeout;
	ssize_t ret = 0;

	CKNULL(ts, -EINVAL);

	CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));

	CKINT(clock_gettime(CLOCK_MONOTONIC, &timeout));
	timeout.tv_sec += ts->tv_sec;
	timeout.tv_nsec += ts->tv_nsec;
	if (timeout.tv_nsec > 1000000000) {
		timeout.tv_sec += timeout.tv_nsec / 1000000000;
		timeout.tv_nsec = timeout.tv_nsec % 1000000000;
	}

	while (buflen) {
		buffer.ret = -ETIMEDOUT;
		buffer.buf = buf;
		buffer.buflen = buflen;

		msg.len = min_size(maxbuflen, buflen);
		msg.tv_sec = (uint64_t)ts->tv_sec;
		msg.tv_nsec = (uint32_t)ts->tv_nsec;

		unpriv_access__rpc_get_random_bytes_full_timeout(
			&rpc_conn->service, &msg,
			esdm_rpcc_get_random_bytes_full_timeout_cb, &buffer);

		if (buffer.ret < -255) {
			maxbuflen = (size_t)(-buffer.ret);
			continue;
		} else if (buffer.ret == -EAGAIN) {
			struct timespec curr;
			CKINT(clock_gettime(CLOCK_MONOTONIC, &curr));

			/* Terminate the endless loop if the timeout hits */
			if (esdm_time_after(&curr, &timeout))
				break;

			nanosleep(&esdm_client_poll_ts, NULL);
			continue;
		} else if (buffer.ret < 0) {
			ret = buffer.ret;
			goto out;
		}

		esdm_test_shm_status_add_rpc_client_written((size_t)buffer.ret);
		buflen -= (size_t)buffer.ret;
		buf += buffer.ret;
	}

out:
	esdm_rpcc_put_unpriv_service(rpc_conn);
	return (ret < 0) ? ret : (ssize_t)orig_buflen;
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_full_timeout(uint8_t *buf, size_t buflen,
						struct timespec *ts)
{
	return esdm_rpcc_get_random_bytes_full_timeout_int(buf, buflen, ts,
							   NULL);
}
