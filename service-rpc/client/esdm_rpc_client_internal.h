/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "atomic.h"
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

	mutex_w_t lock;
	mutex_w_t ref_cnt;
	atomic_t state;

	/*
	 * Used to track successfull reads from esdm-server.
	 * esdm-server closes idle connections after ESDM_RPC_IDLE_TIMEOUT_USEC.
	 * Only update this, when data is received or on new connections.
	 * Otherwise, we may update on writes without answer and keep
	 * dead connections open for too long.
	 */
	struct timespec last_used;
};

/* Sleep time for poll operations */
static const struct timespec esdm_client_poll_ts = { .tv_sec = 1,
						     .tv_nsec = 0 };

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_INTERNAL_H */
