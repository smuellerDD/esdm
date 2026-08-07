/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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

static void esdm_rpcc_get_random_bytes_full_timeout_cb(
	const RandValResponse *response, void *closure_data)
{
	struct esdm_get_random_bytes_full_timeout_buf *buffer =
		(struct esdm_get_random_bytes_full_timeout_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);

	if (response->ret < 0) {
		buffer->ret = response->ret;
		return;
	}

	if (!response->randval.data || !response->randval.len) {
		buffer->ret = -EFAULT;
		return;
	}

	buffer->ret = (ssize_t)min_size(response->randval.len, buffer->buflen);
	memcpy(buffer->buf, response->randval.data, (size_t)buffer->ret);

	/* Zeroization of response is handled in esdm_rpc_client_read_handler */
}

static bool esdm_time_after(struct timespec *curr, struct timespec *timeout)
{
	if (curr == NULL || timeout == NULL)
		return false;

	if (curr->tv_sec > timeout->tv_sec)
		return true;
	if (curr->tv_sec == timeout->tv_sec && curr->tv_nsec > timeout->tv_nsec)
		return true;

	return false;
}

static int int_connection_after_timeout(void *time)
{
	struct timespec *timeout = (struct timespec *)time;
	struct timespec cur_time;

	clock_gettime(CLOCK_MONOTONIC, &cur_time);

	return esdm_time_after(&cur_time, timeout);
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_full_timeout_int(uint8_t *buf, size_t buflen,
						    struct timespec *ts,
						    void *int_data)
{
	GetRandomBytesRequest msg = GET_RANDOM_BYTES_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_get_random_bytes_full_timeout_buf buffer;
	size_t maxbuflen = buflen, orig_buflen = buflen;
	struct timespec timeout;
	ssize_t ret = 0;
	esdm_rpcc_interrupt_func_t old_interrupt_func = NULL;
	bool interrupt_func_replaced = false;

	CKNULL(ts, -EINVAL);

	CKINT(clock_gettime(CLOCK_MONOTONIC, &timeout));
	timeout.tv_sec += ts->tv_sec;
	timeout.tv_nsec += ts->tv_nsec;
	if (timeout.tv_nsec > 1000000000) {
		timeout.tv_sec += timeout.tv_nsec / 1000000000;
		timeout.tv_nsec = timeout.tv_nsec % 1000000000;
	}

	/* register default timeout handler if no one is already set */
	if (int_data == NULL) {
		int_data = &timeout;
		CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));
		old_interrupt_func = rpc_conn->interrupt_func;
		rpc_conn->interrupt_func = int_connection_after_timeout;
		interrupt_func_replaced = true;
	} else {
		CKINT(esdm_rpcc_get_unpriv_service(&rpc_conn, int_data));
	}

	while (buflen) {
		buffer.ret = -ETIMEDOUT;
		buffer.buf = buf;
		buffer.buflen = buflen;

		/* only perform short waits in server,
		 * as they are blocking termination */
		msg.len = min_size(maxbuflen, buflen);

		unpriv_access__rpc_get_random_bytes_full(
			&rpc_conn->service, &msg,
			esdm_rpcc_get_random_bytes_full_timeout_cb, &buffer);

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

		/*
		 * Our own interrupt handler firing means the deadline passed.
		 * It surfaces differently depending on the phase it hit: the
		 * write phase leaves the -ETIMEDOUT placeholder untouched (no
		 * closure call, and esdm_rpcc_last_error() deliberately hides
		 * the -EAGAIN behind it), while the read phase invokes the
		 * closure with -EINTR. Report the deadline as -ETIMEDOUT in
		 * both cases - propagating -EINTR would make the caller's
		 * esdm_invoke() restart the request up to five more times, each
		 * with a freshly computed deadline, so a call could block for
		 * several times the requested timeout.
		 */
		if (interrupt_func_replaced && buffer.ret == -EINTR &&
		    int_connection_after_timeout(&timeout)) {
			ret = -ETIMEDOUT;
			goto out;
		}

		if (buffer.ret < -255) {
			size_t new_max = (size_t)(-buffer.ret);

			/*
			 * The server signals the largest size it can serve by
			 * returning its negated value, asking us to retry with a
			 * smaller request. Only honor it if it actually shrinks
			 * the request; a buggy or hostile peer returning a
			 * non-shrinking value must not be able to spin this loop
			 * forever.
			 */
			if (new_max >= maxbuflen) {
				ret = -EPROTO;
				goto out;
			}
			maxbuflen = new_max;
			continue;
		} else if (buffer.ret == -EAGAIN) {
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
	/*
	 * Restore whatever was registered before - including NULL, which is
	 * what a service initialized without an interrupt function has. Keying
	 * this off old_interrupt_func being non-NULL would leave our handler
	 * installed on the shared connection for good in exactly that case,
	 * together with an interrupt_data pointing at this stack frame.
	 */
	if (interrupt_func_replaced) {
		rpc_conn->interrupt_func = old_interrupt_func;
	}

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
