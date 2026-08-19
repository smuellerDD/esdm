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

#ifndef ESDM_RPC_SERVER_H
#define ESDM_RPC_SERVER_H

#include <protobuf-c/protobuf-c.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check whether Unix Domain Socket client is privileged (UID 0)
 *
 * This call uses getsockupt(SO_PEERCRED) to obtain the remote caller's
 * UID.
 *
 * NOTE: For Protobuf-C-RPC, a connection is left open. Thus, the CUSE
 *	 daemon's drop of privileges may not be caught by this check. Therefore
 *	 the CUSE daemons are considered trusted to implement another check
 *	 whether its callers is privileged.
 */
bool esdm_rpc_client_is_privileged(void *closure_data);

int esdm_rpc_server_init(const char *username, const char *groupname);
void esdm_rpc_server_fini(void);

/**
 * @brief Remove a left-over Unix domain socket of a previous server instance
 *
 * The socket is only removed when nothing is listening on it, probed by
 * connecting. Deliberately conservative: only a refused connection proves the
 * socket is dead, and the file is re-validated right before the removal so a
 * symlink or a replaced inode cannot be unlinked instead.
 *
 * @param [in] path Path of the socket to examine
 * @param [in] socktype Socket type used for the probe (SOCK_SEQPACKET,
 *			SOCK_STREAM, ...) - it must match the type the socket
 *			was created with
 */
void esdm_server_remove_stale_socket(const char *path, int socktype);

/**
 * @brief Remove the server IPC resources: both RPC Unix domain sockets, the
 *	  status SHM segment and its semaphores.
 *
 * Honors esdm_config_ipc_cleanup() and skips the socket removal when the
 * sockets are managed by systemd (socket activation). The removal of the
 * root-owned objects requires privileges the daemon no longer has after its
 * permanent privilege drop - the esdm-server therefore invokes this from its
 * privileged PID namespace supervisor once the daemon terminated.
 */
void esdm_rpc_server_cleanup(void);

/**
 * @brief Shutdown trigger for normal (non-signal) context
 *
 * Sets the exit flag and wakes waiting threads via a condvar broadcast. The
 * broadcast is NOT async-signal-safe, so do not call this from a signal
 * handler; use esdm_rpc_server_signal_exit_safe() there instead. Does NOT join
 * threads or free memory; the caller must invoke esdm_rpc_server_fini().
 */
void esdm_rpc_server_signal_exit(void);

/**
 * @brief Async-signal-safe shutdown trigger
 *
 * Only sets the exit flag (an atomic store + barrier), which is safe from a
 * signal handler. Blocked waiters notice the flag via the bounded re-poll in
 * thread_wait_event(), so no condvar broadcast is needed here.
 */
void esdm_rpc_server_signal_exit_safe(void);

#ifdef ESDM_FUZZING
/**
 * @brief Hand one buffer to the server as if it had just been read off a client
 * 	connection
 * @param [in] service The RPC service the request is directed at
 * @param [in] privileged Is this the privileged interface?
 * @param [in] data Bytes as they would have arrived from the client
 * @param [in] len Number of those bytes, capped at what a read can deliver
 * @param [in] out_fd Descriptor the response is written to
 * @return 0 on success, < 0 on error - the request was rejected, which for a
 * 	malformed request is the expected outcome
 */
int esdm_rpcs_fuzz_request(ProtobufCService *service, bool privileged,
			   const uint8_t *data, size_t len, int out_fd);

/**
 * @brief Serve one RPC interface on @p socket_path until the server is stopped
 * @param [in] socket_path Unix domain socket to bind and listen on
 * @param [in] service The RPC service the requests are directed at
 * @param [in] privileged Is this the privileged interface?
 * @return 0 when the server was asked to exit, < 0 on error
 */
int esdm_rpcs_fuzz_serve(const char *socket_path, ProtobufCService *service,
			 bool privileged);
#endif /* ESDM_FUZZING */

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_SERVER_H */
