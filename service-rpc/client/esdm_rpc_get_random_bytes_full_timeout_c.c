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

static bool esdm_time_after(const struct timespec *curr,
			    const struct timespec *timeout)
{
	if (curr == NULL || timeout == NULL)
		return false;

	if (curr->tv_sec > timeout->tv_sec)
		return true;
	if (curr->tv_sec == timeout->tv_sec && curr->tv_nsec > timeout->tv_nsec)
		return true;

	return false;
}

/*
 * The deadline is enforced by an interrupt function chained in front of the
 * connection's own, which keeps getting the caller's interrupt data.
 */
struct esdm_rpcc_timeout_int {
	struct timespec deadline;
	esdm_rpcc_interrupt_func_t interrupt_func;
	void *int_data;
};

static bool esdm_rpcc_timeout_passed(const struct esdm_rpcc_timeout_int *t)
{
	struct timespec cur_time;

	clock_gettime(CLOCK_MONOTONIC, &cur_time);

	return esdm_time_after(&cur_time, &t->deadline);
}

static int esdm_rpcc_timeout_interrupt(void *data)
{
	struct esdm_rpcc_timeout_int *t = data;

	if (esdm_rpcc_timeout_passed(t))
		return 1;

	return t->interrupt_func ? t->interrupt_func(t->int_data) : 0;
}

static int esdm_rpcc_timeout_get(esdm_rpc_client_connection_t **rpc_conn,
				 struct esdm_rpcc_timeout_int *t)
{
	int ret = esdm_rpcc_get_unpriv_service(rpc_conn, t);

	if (ret)
		return ret;

	t->interrupt_func = (*rpc_conn)->interrupt_func;
	(*rpc_conn)->interrupt_func = esdm_rpcc_timeout_interrupt;

	return 0;
}

/*
 * Restore what was registered before, NULL included: our handler must not
 * stay on the shared connection with interrupt_data pointing into the
 * caller's stack frame.
 */
static void esdm_rpcc_timeout_put(esdm_rpc_client_connection_t *rpc_conn,
				  struct esdm_rpcc_timeout_int *t)
{
	if (!rpc_conn)
		return;

	rpc_conn->interrupt_func = t->interrupt_func;
	esdm_rpcc_put_unpriv_service(rpc_conn);
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_full_timeout_int(uint8_t *buf, size_t buflen,
						    struct timespec *ts,
						    void *int_data)
{
	GetRandomBytesRequest msg = GET_RANDOM_BYTES_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_get_random_bytes_full_timeout_buf buffer;
	struct esdm_rpcc_timeout_int timeout = { .int_data = int_data };
	size_t maxbuflen = buflen, orig_buflen = buflen;
	ssize_t ret = 0;

	CKNULL(ts, -EINVAL);

	CKINT(clock_gettime(CLOCK_MONOTONIC, &timeout.deadline));
	timeout.deadline.tv_sec += ts->tv_sec;
	timeout.deadline.tv_nsec += ts->tv_nsec;
	if (timeout.deadline.tv_nsec >= 1000000000) {
		timeout.deadline.tv_sec +=
			timeout.deadline.tv_nsec / 1000000000;
		timeout.deadline.tv_nsec =
			timeout.deadline.tv_nsec % 1000000000;
	}

	CKINT(esdm_rpcc_timeout_get(&rpc_conn, &timeout));

	while (buflen) {
		if (esdm_rpcc_timeout_passed(&timeout)) {
			ret = -ETIMEDOUT;
			goto out;
		}

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
		 * The deadline passing interrupts the request. The connect and
		 * write phases leave the -ETIMEDOUT placeholder untouched (no
		 * closure call), the read phase invokes the closure with
		 * -EINTR. Report -ETIMEDOUT for both: propagating -EINTR would
		 * make the caller's esdm_invoke() restart the request up to five
		 * more times, each with a fresh deadline. An earlier -EINTR is
		 * the caller's own interrupt and is handed on.
		 */
		if (buffer.ret == -EINTR &&
		    esdm_rpcc_timeout_passed(&timeout)) {
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
			struct timespec sleep_ts = esdm_client_poll_ts;
			struct timespec cur_time;

			/* Sleep no further than to the deadline */
			clock_gettime(CLOCK_MONOTONIC, &cur_time);
			if (!esdm_time_after(&cur_time, &timeout.deadline)) {
				struct timespec left = {
					.tv_sec = timeout.deadline.tv_sec -
						  cur_time.tv_sec,
					.tv_nsec = timeout.deadline.tv_nsec -
						   cur_time.tv_nsec,
				};

				if (left.tv_nsec < 0) {
					left.tv_sec--;
					left.tv_nsec += 1000000000;
				}
				if (esdm_time_after(&sleep_ts, &left))
					sleep_ts = left;
				nanosleep(&sleep_ts, NULL);
			}

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
	esdm_rpcc_timeout_put(rpc_conn, &timeout);
	return (ret < 0) ? ret : (ssize_t)orig_buflen;
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_full_timeout(uint8_t *buf, size_t buflen,
						struct timespec *ts)
{
	return esdm_rpcc_get_random_bytes_full_timeout_int(buf, buflen, ts,
							   NULL);
}
