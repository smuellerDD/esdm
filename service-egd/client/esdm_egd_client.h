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
 * A client owns exactly one connection to the EGD socket. The EGD protocol
 * carries no request identifiers - responses are matched to requests purely by
 * their order on the stream - so all operations of one client are serialized
 * against each other, and one request is in flight at a time. A caller that
 * wants concurrency uses several clients.
 *
 * That serialization survives a caller that does not: the lock behind it is a
 * robust one, so a thread killed in the middle of an operation - while waiting
 * for an ESDM that is not operational yet, say - hands the client on to the
 * next caller instead of wedging it for the rest of the process' lifetime. The
 * connection it left at an unknown offset of the command stream is dropped,
 * exactly as for the failed transfer below.
 *
 * All operations are thread safe and reconnect on their own:
 *
 *  - The connection is established by esdm_egd_client_alloc() and released by
 *    esdm_egd_client_free(); it lives exactly as long as the client does. A
 *    client whose initial connect failed - because the ESDM is not up yet -
 *    stays usable and connects on first use.
 *
 *  - A transfer that fails halfway leaves the peer's parser at an unknown
 *    offset of the command stream, so the connection is dropped rather than
 *    reused and the operation is retried once on a freshly opened one. Hence
 *    the common case of the daemon having been restarted between two requests
 *    is invisible to the caller: the first transfer fails, the retry succeeds.
 *
 *  - A descriptor inherited across fork() refers to the same connection as the
 *    parent's, and two processes interleaving commands on it would
 *    desynchronize the stream. A fork handler therefore closes every inherited
 *    connection in the child right at the fork, which also releases the
 *    descriptor instead of pinning the connection open for the child's
 *    lifetime; the next operation there opens a connection of its own. Should
 *    the fork have bypassed the handler - a direct clone(2), say - the client
 *    still notices at its next use and reconnects then.
 *
 * Reasons to use this rather than the ESDM RPC client: the EGD interface needs
 * nothing but a single Unix domain stream socket - no protobuf, no shared
 * memory, no second socket - which makes it reachable from places the RPC
 * interface is not, such as a chroot that can be given exactly one socket. Its
 * downside is that the protocol is a legacy one which can neither express
 * prediction resistance nor transfer more than 255 bytes at a time (this
 * client splits larger requests transparently).
 *
 * Syscall discipline
 * ------------------
 * Once connected, the operations stay within read(2), write(2), poll(2),
 * close(2), getpid(2), clock_gettime(2), nanosleep(2) and getsockopt(2). That
 * is deliberate: it is the set a seccomp confined process is typically still
 * allowed, OpenSSH's pre-auth sandbox (sandbox-seccomp-filter.c) being the
 * reference case. Note in particular that send(2)/recv(2) are avoided - they
 * are sendto(2)/recvfrom(2), which that filter answers with
 * SECCOMP_RET_KILL - and that MSG_NOSIGNAL is therefore not available, so a
 * write is preceded by a poll that catches a vanished peer before it could
 * raise SIGPIPE.
 *
 * Establishing a connection is a different matter: it needs socket(2) and
 * connect(2), which such a sandbox does not permit and does not merely fail
 * but kills the process for. A client that has to serve a sandboxed process
 * must therefore be connected before the sandbox is entered - and a process
 * that forks into one cannot be served at all, since the fork forces a
 * reconnect (the parent's connection cannot be shared, see above).
 */
struct esdm_egd_client;

/**
 * @brief Allocate a client and connect it
 *
 * The connection is established here, which is what a caller that has to serve
 * a sandboxed process needs: see the note on the syscall discipline above -
 * connecting is exactly what such a process may no longer do.
 *
 * Failing to connect is not an allocation failure. The client is handed back
 * usable and every operation retries, so a consumer that is initialized before
 * the ESDM is up - an OpenSSL provider loaded during boot, say - keeps working
 * once the daemon arrives instead of having to be torn down and set up again.
 *
 * @param [out] client Allocated client, to be released with
 *		       esdm_egd_client_free()
 * @param [in] socket_path Path of the EGD socket. NULL or the empty string
 *			   selects the path from the ESDM_EGD_SOCKET
 *			   environment variable, and failing that the socket
 *			   path this ESDM was built with.
 * @param [in] timeout_ms Bound in milliseconds on how long the client waits
 *			  for the peer in one step - the connection setup, or
 *			  one transfer of a request or its response - before
 *			  treating it as failed. The socket is non-blocking
 *			  and every wait is a poll of its own, so this covers
 *			  the connect as well, which a receive timeout cannot.
 *			  0 selects a default generous enough for the blocking
 *			  read command to wait for an ESDM that is not
 *			  operational yet; unreasonably large values are
 *			  capped.
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
 * The protocol allows attaching an entropy claim to the data. The ESDM only
 * honors it for a privileged (UID 0) caller and inserts the data of everybody
 * else without any entropy credit, so an unprivileged caller passing a
 * non-zero @entropy_bits is not an error - the claim is simply dropped.
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
