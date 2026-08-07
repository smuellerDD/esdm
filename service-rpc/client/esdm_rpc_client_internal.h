/*
 * Copyright (C) 2023 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_RPC_CLIENT_INTERNAL_H
#define ESDM_RPC_CLIENT_INTERNAL_H

#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"

#include <errno.h>
#include <stdatomic.h>
#include "mutex_w.h"
#include "queue.h"

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	esdm_rpcc_uninitialized,
	esdm_rpcc_in_initialization,
	esdm_rpcc_initialized,
	esdm_rpcc_in_termination,
};

struct esdm_rpc_client_connection {
	ProtobufCService service;
	char socketname[FILENAME_MAX];
	int fd;

	/*
	 * Caller can register function that is invoked to check whether call
	 * should be interrupted.
	 */
	esdm_rpcc_interrupt_func_t interrupt_func;
	void *interrupt_data;

	/*
	 * Both are robust mutexes, so a caller that is killed while owning the
	 * connection does not wedge it for the rest of the process lifetime.
	 *
	 * lock	   - held by esdm_client_invoke() across one request/response
	 *	     exchange. Taking it over from a died owner implies the
	 *	     socket may sit mid-message and has to be dropped.
	 * ref_cnt - held from esdm_rpcc_get_*_service() until the matching
	 *	     esdm_rpcc_put_*_service(), marking the connection as
	 *	     checked out. It guards no data, so taking it over from a
	 *	     died owner needs no recovery beyond the takeover itself.
	 */
	mutex_w_t lock;
	mutex_w_t ref_cnt;
	atomic_int state;

	/*
	 * The request/response and unpack scratch buffers are not stored per
	 * connection but per calling thread (see esdm_rpcc_reqbuf /
	 * esdm_rpcc_unpack_buf in esdm_rpc_client.c): they are only ever used
	 * during a single synchronous invoke held by the calling thread, so one
	 * buffer set per thread suffices instead of one per connection. This
	 * bounds the buffer memory by the number of threads issuing RPCs rather
	 * than by the size of the connection pool.
	 */

	/*
	 * Used to track successfull reads from esdm-server.
	 * esdm-server closes idle connections after ESDM_RPC_IDLE_TIMEOUT_USEC.
	 * Only update this, when data is received or on new connections.
	 * Otherwise, we may update on writes without answer and keep
	 * dead connections open for too long.
	 */
	struct timespec last_used;

	/*
	 * Outcome of the most recent esdm_client_invoke() on this connection:
	 * 0 on success, a negative errno when the request never made it to the
	 * server or no response came back.
	 *
	 * protobuf-c's invoke() returns void and only reports a result by
	 * calling the closure, which does not happen at all when the RPC fails
	 * at the transport level. Without this, callers can merely observe
	 * that their closure was not run and have to report a generic error
	 * for what may just as well be a refused connection or a broken pipe.
	 *
	 * A connection is owned exclusively by one caller from
	 * esdm_rpcc_get_*_service() to esdm_rpcc_put_*_service() (see the
	 * ref_cnt handling in esdm_rpcc_get_service()), so writing it in the
	 * invoke and reading it right afterwards needs no further
	 * serialization.
	 */
	int last_error;
};

/**
 * @brief Reason why the last RPC on this connection produced no response
 *
 * The RPC wrappers pre-set their closure result to -ETIMEDOUT and only learn
 * that something went wrong from the closure not having been invoked. This
 * turns that into the actual reason.
 *
 * -EAGAIN is deliberately not reported: that is how an interruption requested
 * through esdm_rpcc_interrupt_func_t surfaces - most notably the deadline of
 * esdm_rpcc_get_random_bytes_full_timeout() - for which the callers' own
 * -ETIMEDOUT placeholder is the right answer.
 *
 * @return negative errno describing the failure, 0 if the request reached the
 *	   server (or was interrupted on request of the caller)
 */
static inline int
esdm_rpcc_last_error(const esdm_rpc_client_connection_t *rpc_conn)
{
	int ret = rpc_conn->last_error;

	return (ret < 0 && ret != -EAGAIN) ? ret : 0;
}

/* Sleep time for poll operations */
static const struct timespec esdm_client_poll_ts = { .tv_sec = 1,
						     .tv_nsec = 0 };

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_INTERNAL_H */
