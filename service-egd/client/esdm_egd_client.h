/*
 * Client for the EGD (Entropy Gathering Daemon) interface of the ESDM
 *
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

#ifndef ESDM_EGD_CLIENT_H
#define ESDM_EGD_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Client of the ESDM's EGD interface
 *
 * A client owns exactly one connection to the EGD socket. The protocol carries
 * no request identifiers - responses are matched to requests by their order on
 * the stream alone - so all operations of one client are serialized and one
 * request is in flight at a time; a caller wanting concurrency uses several
 * clients. The lock behind that is robust, so a thread killed mid operation
 * hands the client on rather than wedging it for the process' lifetime.
 *
 * All operations are thread safe and reconnect on their own:
 *
 *  - The connection is established by esdm_egd_client_alloc() and released by
 *    esdm_egd_client_free(). A client whose initial connect failed stays usable
 *    and connects on first use.
 *
 *  - A transfer failing halfway leaves the peer's parser at an unknown offset,
 *    so the connection is dropped and the operation retried once on a fresh
 *    one. A daemon restart between two requests is thus invisible.
 *
 *  - A descriptor inherited across fork() refers to the parent's connection,
 *    which two processes interleaving commands would desynchronize. A fork
 *    handler closes every inherited connection in the child; should the fork
 *    bypass it - a direct clone(2) - the client notices at its next use.
 *
 * Compared to the RPC client this needs nothing but a single Unix domain stream
 * socket, which makes it reachable from places the RPC interface is not, such
 * as a chroot. The price is a legacy protocol that can express neither
 * prediction resistance nor transfers above 255 bytes (split transparently).
 *
 * Syscall discipline
 * ------------------
 * Once connected, the operations stay within read(2), write(2), poll(2),
 * close(2), getpid(2), clock_gettime(2), nanosleep(2) and getsockopt(2) - the
 * set a seccomp confined process is typically still allowed, OpenSSH's pre-auth
 * sandbox being the reference case. send(2)/recv(2) are avoided as they are
 * sendto(2)/recvfrom(2), which that filter answers with SECCOMP_RET_KILL, so
 * MSG_NOSIGNAL is unavailable and a write is preceded by a poll instead.
 *
 * Connecting needs socket(2) and connect(2), which such a sandbox kills the
 * process for. A client serving a sandboxed process must therefore be connected
 * before the sandbox is entered - and a process that forks into one cannot be
 * served at all, since the fork forces a reconnect.
 */
struct esdm_egd_client;

/**
 * @brief Allocate a client and connect it
 *
 * The connection is established here, which is what a caller serving a
 * sandboxed process needs - connecting is exactly what such a process may no
 * longer do, see the syscall discipline above. Failing to connect is not an
 * allocation failure: the client is handed back usable and every operation
 * retries, so a consumer initialized before the ESDM is up keeps working once
 * the daemon arrives.
 *
 * @param [out] client Allocated client, to be released with
 *		       esdm_egd_client_free()
 * @param [in] socket_path Path of the EGD socket. NULL or the empty string
 *			   selects the path from the ESDM_EGD_SOCKET
 *			   environment variable, and failing that the socket
 *			   path this ESDM was built with.
 * @param [in] timeout_ms Bound in milliseconds on one step - the connection
 *			  setup, or one transfer. Every wait is a poll of its
 *			  own, so this covers the connect as well, which a
 *			  receive timeout cannot. 0 selects a default generous
 *			  enough for a blocking read to wait for a not yet
 *			  operational ESDM; large values are capped.
 *
 * @return 0 on success, < 0 when no client could be allocated - a failure to
 *	   connect is reported through the ESDM logger, not here
 */
int esdm_egd_client_alloc(struct esdm_egd_client **client,
			  const char *socket_path, unsigned int timeout_ms);

/**
 * @brief Close the connection and release the client
 *
 * @param [in] client Client to release, may be NULL
 */
void esdm_egd_client_free(struct esdm_egd_client *client);

/**
 * @brief Path of the EGD socket this client talks to
 *
 * @param [in] client Client to query
 *
 * @return The path, owned by the client
 */
const char *esdm_egd_client_socket_path(const struct esdm_egd_client *client);

/**
 * @brief Obtain random data, waiting for the ESDM to become operational
 *
 * Requests larger than one protocol transfer are split transparently. On
 * failure @buf is cleansed, so a partial transfer can never be mistaken for a
 * complete one.
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer to fill
 * @param [in] buflen Number of bytes to obtain
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_random(struct esdm_egd_client *client, uint8_t *buf,
			       size_t buflen);

/**
 * @brief Obtain random data without waiting
 *
 * The ESDM answers with as much data as it can deliver right away, which is
 * nothing at all while it is not operational yet. Use this only where a short
 * answer is acceptable - a seed consumer wants esdm_egd_client_get_random().
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer to fill
 * @param [in] buflen Number of bytes to ask for, at most
 *		      ESDM_EGD_MAX_TRANSFER
 * @param [out] generated Number of bytes actually delivered
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_random_nonblock(struct esdm_egd_client *client,
					uint8_t *buf, size_t buflen,
					size_t *generated);

/**
 * @brief Query the amount of entropy the ESDM currently holds
 *
 * @param [in] client Client to use
 * @param [out] entropy_bits Available entropy in bits
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_entropy_count(struct esdm_egd_client *client,
				  uint32_t *entropy_bits);

/**
 * @brief Insert data into the ESDM's auxiliary pool
 *
 * The protocol allows attaching an entropy claim to the data, which the ESDM
 * only honors for a privileged (UID 0) caller. An unprivileged caller passing
 * a non-zero @entropy_bits is not an error - the claim is simply dropped.
 *
 * @param [in] client Client to use
 * @param [in] buf Data to insert, at most ESDM_EGD_MAX_TRANSFER bytes
 * @param [in] buflen Length of the data
 * @param [in] entropy_bits Claimed entropy of the data in bits
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_write_entropy(struct esdm_egd_client *client,
				  const uint8_t *buf, size_t buflen,
				  uint32_t entropy_bits);

/**
 * @brief Query the PID of the daemon serving the socket
 *
 * @param [in] client Client to use
 * @param [out] pid PID reported by the peer
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_pid(struct esdm_egd_client *client, pid_t *pid);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_EGD_CLIENT_H */
