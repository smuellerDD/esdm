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

#include "config.h"
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

#ifdef ESDM_FUZZING
/**
 * @brief Hand one buffer to the client as if the server had answered with it
 * @param [in] message_desc Message type the client expects in the response
 * @param [in] data Bytes as they would have arrived from the server
 * @param [in] len Number of those bytes
 * @param [in] closure Invoked with the decoded message, as in a real call
 * @param [in] closure_data Opaque pointer handed to @p closure
 * @return 0 on success, < 0 on error - a malformed response is rejected, which
 * 	is the expected outcome
 */
int esdm_rpcc_fuzz_response(const ProtobufCMessageDescriptor *message_desc,
			    const uint8_t *data, size_t len,
			    ProtobufCClosure closure, void *closure_data);
#endif /* ESDM_FUZZING */

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
	 * Both are robust mutexes, so a caller killed while owning the
	 * connection does not wedge it for the process' lifetime.
	 *
	 * lock	   - held by esdm_client_invoke() across one request/response
	 *	     exchange. Taken over from a died owner, the socket may sit
	 *	     mid-message and has to be dropped.
	 * ref_cnt - held between get and put, marking the connection checked
	 *	     out. It guards no data, so a takeover needs no recovery.
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
	 * Outcome of the most recent esdm_client_invoke() on this connection: 0
	 * on success, a negative errno when the request never reached the server
	 * or no response came back. protobuf-c's invoke() returns void and only
	 * reports through the closure, which is not called at all on a transport
	 * failure - without this, callers can merely observe that and report a
	 * generic error. A connection is owned exclusively by one caller between
	 * get and put, so no further serialization is needed.
	 */
	int last_error;
};

/**
 * @brief Reason why the last RPC on this connection produced no response
 *
 * The RPC wrappers pre-set their closure result to -ETIMEDOUT and only learn
 * that something went wrong from the closure not being invoked; this turns that
 * into the actual reason. -EAGAIN is deliberately not reported: it is how an
 * interruption requested through esdm_rpcc_interrupt_func_t surfaces, for which
 * the callers' own -ETIMEDOUT placeholder is the right answer.
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
