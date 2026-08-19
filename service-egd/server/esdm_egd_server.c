/*
 * EGD (Entropy Gathering Daemon) protocol compatibility interface
 *
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "bitshift_be.h"
#include "build_bug_on.h"
#include "esdm.h"
#include "esdm_egd_protocol.h"
#include "esdm_egd_server.h"
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "helper.h"
#include "memset_secure.h"
#include "systemd_support.h"
#include "threading_support.h"

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                             \
	for ((var) = TAILQ_FIRST((head));                                      \
	     (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))
#endif

/*
 * Room for one maximum sized command plus the beginning of the next one, so a
 * client pipelining its requests does not have to be read byte-wise.
 */
#define ESDM_EGD_BUFSIZE (2 * ESDM_EGD_MAX_CMD_SIZE)

/*
 * Upper bound of concurrently served clients. EGD clients hold their connection
 * open for their entire lifetime, so this limits clients, not requests; beyond
 * it, connections stay queued in the listen backlog. Generous because such
 * consumers are typically idle long running daemons and nothing is preallocated
 * for them. Serving this many needs a RLIMIT_NOFILE above it; an accept failing
 * for want of a descriptor merely leaves the client queued.
 */
#define ESDM_EGD_MAX_CONNECTIONS 2048

/*
 * Connections that may wait to be accepted, matched to the number that may be
 * served: a backlog well below the limit above would turn a burst of clients
 * starting at once into connect failures long before that limit is reached.
 * The kernel silently caps this at net.core.somaxconn. A socket handed over by
 * systemd is already listening and unaffected - its depth is the Backlog= of
 * its .socket unit.
 */
#define ESDM_EGD_LISTEN_BACKLOG ESDM_EGD_MAX_CONNECTIONS

/* Number of events processed per epoll_wait call. */
#define ESDM_EGD_MAX_EVENTS 64

/*
 * Poll interval of the event loop while it is idle. It bounds how quickly the
 * worker notices a shutdown request, which is signaled by a plain atomic store
 * from a signal handler and therefore cannot wake the loop by itself.
 */
#define ESDM_EGD_IDLE_POLL_MS 250

/*
 * Poll interval while a blocking read request is deferred: it defines how
 * quickly such a request is answered once the ESDM turns operational.
 */
#define ESDM_EGD_DEFERRED_POLL_MS 50

/*
 * Time a response may stay undelivered before the connection is considered
 * stuck and torn down. Generous, because a client that does not read holds up
 * nothing but its own connection - the worker moved on the moment its socket
 * buffer was full. This only reclaims the slot of a peer that is not coming
 * back for its answer.
 */
#define ESDM_EGD_WRITE_TIMEOUT_MS 30000

struct esdm_egd_conn {
	int fd;

	/* Listener this connection arrived on - it selects the generator. */
	const struct esdm_egd_listener *listener;

	/* Credentials of the peer, obtained once when the client connected. */
	uid_t peer_uid;

	/* Events this connection is currently watched for, see
	 * esdm_egd_conn_arm(). */
	uint32_t armed;

	/* Command bytes received but not yet processed. */
	uint8_t in[ESDM_EGD_BUFSIZE];
	size_t in_len;

	/*
	 * The response of the command in flight, and how much of it the client
	 * has taken. Only ever one: the next command is processed once this is
	 * empty, so a client asking faster than it reads is backed up in its own
	 * socket rather than buffered for. Sized for the largest single response
	 * - a non-blocking read: its length byte and the data.
	 */
	uint8_t out[1 + ESDM_EGD_MAX_TRANSFER];
	size_t out_len;
	size_t out_off;

	/* When the pending response was produced, for the stall timeout. */
	uint64_t out_since;

	/*
	 * Number of bytes owed to the client for a blocking read request that
	 * could not be served yet because the ESDM is not operational. Zero
	 * when no request is deferred. While a request is deferred, no further
	 * command of this connection is processed - the protocol has no
	 * request IDs, so responses must retain their order.
	 */
	uint8_t deferred;

	/*
	 * Bytes of the deferred answer collected so far, see
	 * esdm_egd_cmd_read_block().
	 */
	uint8_t answer[ESDM_EGD_MAX_TRANSFER];
	uint8_t answer_len;

	TAILQ_ENTRY(esdm_egd_conn) tailq;
};
TAILQ_HEAD(esdm_egd_conn_list, esdm_egd_conn);

/*
 * One served socket. The interface exists twice, once for the ordinary fully
 * seeded generator and once for the prediction resistance one: the EGD protocol
 * has no notion of prediction resistance, so which generator answers is a
 * property of the socket a client connects to, not of its request.
 */
struct esdm_egd_listener {
	/* Name under which systemd hands this socket over. */
	const char *systemd_name;

	/*
	 * Socket path requested on the command line. Empty when this socket
	 * was not requested that way - it may still be activated by systemd,
	 * in which case the path lives in the .socket unit and is never known
	 * here.
	 */
	char socket_path[108];

	int listening_fd;

	/*
	 * Was the listening socket handed over by systemd? Its lifecycle is
	 * systemd's business then, and its path is unknown here.
	 */
	bool systemd_socket;

	/* Serve from esdm_get_random_bytes_pr() rather than _full()? */
	bool prediction_resistance;
};

static struct esdm_egd_listener esdm_egd_listeners[] = {
	{
		.systemd_name = "ESDM_EGD_SOCKET",
		.listening_fd = -1,
		.prediction_resistance = false,
	},
	{
		.systemd_name = "ESDM_EGD_PR_SOCKET",
		.listening_fd = -1,
		.prediction_resistance = true,
	},
};

#define ESDM_EGD_LISTENER_REGULAR (&esdm_egd_listeners[0])
#define ESDM_EGD_LISTENER_PR (&esdm_egd_listeners[1])

#define for_each_esdm_egd_listener(listener)                                   \
	for (listener = &esdm_egd_listeners[0];                                \
	     listener < &esdm_egd_listeners[ARRAY_SIZE(esdm_egd_listeners)];   \
	     listener++)

static atomic_int esdm_egd_exit = 0;
static atomic_bool esdm_egd_worker_running = false;

static int esdm_egd_listener_enable(struct esdm_egd_listener *listener,
				    const char *socket_path)
{
	struct sockaddr_un addr;

	if (!socket_path || !*socket_path)
		return -EINVAL;

	/*
	 * The path has to fit into sockaddr_un including its terminating NUL -
	 * the local buffer is sized identically, so one check covers both.
	 */
	BUILD_BUG_ON(sizeof(listener->socket_path) != sizeof(addr.sun_path));
	if (strlen(socket_path) >= sizeof(addr.sun_path)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD socket path is too long (max %zu characters)\n",
			    sizeof(addr.sun_path) - 1);
		return -ENAMETOOLONG;
	}

	snprintf(listener->socket_path, sizeof(listener->socket_path), "%s",
		 socket_path);

	return 0;
}

int esdm_egd_server_enable(const char *socket_path)
{
	return esdm_egd_listener_enable(ESDM_EGD_LISTENER_REGULAR, socket_path);
}

int esdm_egd_server_enable_pr(const char *socket_path)
{
	return esdm_egd_listener_enable(ESDM_EGD_LISTENER_PR, socket_path);
}

static bool esdm_egd_listener_enabled(const struct esdm_egd_listener *listener)
{
	return (listener->socket_path[0] != '\0');
}

/* Did any of the sockets actually come up? */
static bool esdm_egd_server_active(void)
{
	const struct esdm_egd_listener *listener;

	for_each_esdm_egd_listener (listener) {
		if (listener->listening_fd >= 0)
			return true;
	}

	return false;
}

bool esdm_egd_server_enabled(void)
{
	const struct esdm_egd_listener *listener;

	for_each_esdm_egd_listener (listener) {
		if (esdm_egd_listener_enabled(listener))
			return true;
	}

	return false;
}

/*
 * Use the EGD listening socket handed over by systemd socket activation.
 *
 * @return 0 when the socket was taken over, -ENOENT when systemd did not hand
 *	   one over (the caller binds it itself then), < 0 on all other errors
 */
static int esdm_egd_server_socket_systemd(struct esdm_egd_listener *listener)
{
#ifdef ESDM_SYSTEMD_SUPPORT
	socklen_t length;
	int fd, type;

	if (systemd_listen_fds() <= 0)
		return -ENOENT;

	fd = systemd_listen_fd_for_name(listener->systemd_name);
	if (fd < 0)
		return -ENOENT;

	/*
	 * The EGD protocol is a stream protocol, so the .socket unit has to use
	 * ListenStream=. Refuse anything else instead of misinterpreting the
	 * message boundaries of another socket type.
	 */
	length = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) < 0) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SERVER,
			"EGD server: cannot determine the type of the systemd provided socket: %s\n",
			strerror(errno));
		close(fd);
		return -errno;
	}

	if (type != SOCK_STREAM) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SERVER,
			"EGD server: the systemd provided socket is not a stream socket - use ListenStream= in the .socket unit\n");
		close(fd);
		return -EPROTOTYPE;
	}

	if (set_fd_nonblocking(fd) < 0) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SERVER,
			"EGD server: the systemd provided socket cannot be set non-blocking\n");
		close(fd);
		return -EINVAL;
	}

	listener->listening_fd = fd;
	listener->systemd_socket = true;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "EGD server: using the systemd provided socket %s (FD %d)\n",
		    listener->systemd_name, fd);

	return 0;
#else
	(void)listener;
	return -ENOENT;
#endif
}

static int esdm_egd_listener_socket_init(struct esdm_egd_listener *listener)
{
	struct sockaddr_un addr;
	int errsv, fd, ret;

	/*
	 * Socket activation enables the interface on its own: an administrator
	 * who starts esdm-server-egd.socket wants the EGD interface, and the
	 * socket unit carries its path and access mode. --egd_socket is the
	 * alternative for setups without systemd.
	 */
	ret = esdm_egd_server_socket_systemd(listener);
	if (!ret)
		return 0;
	if (ret != -ENOENT)
		return ret;

	if (!esdm_egd_listener_enabled(listener))
		return 0;

	/*
	 * LISTEN_FDS may be set without any of the descriptors being ours - an
	 * environment inherited from an unrelated socket activated context.
	 * Binding the requested socket ourselves is then the right move, just
	 * as the RPC interfaces do it.
	 */
	esdm_server_remove_stale_socket(listener->socket_path, SOCK_STREAM);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 listener->socket_path);

	/*
	 * EGD is a stream protocol: its clients delimit the messages by the
	 * length information the protocol carries, not by datagram boundaries.
	 */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot create socket: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot bind to socket %s: %s\n",
			    listener->socket_path, strerror(errsv));
		close(fd);
		return -errsv;
	}

	/*
	 * EGD clients are ordinary applications, so the socket is available to
	 * everybody - like the unprivileged RPC socket, and everything reachable
	 * through it is equally unprivileged (data from unprivileged callers is
	 * inserted without entropy credit, see esdm_egd_cmd_write_entropy()).
	 * A socket handed over by systemd never reaches this point: its mode
	 * comes from the SocketMode= of its .socket unit.
	 */
	if (chmod(listener->socket_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
						  S_IROTH | S_IWOTH) < 0) {
		errsv = errno;
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SERVER,
			"EGD server: cannot set permissions of socket %s: %s\n",
			listener->socket_path, strerror(errsv));
		close(fd);
		return -errsv;
	}

	if (listen(fd, ESDM_EGD_LISTEN_BACKLOG) < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot listen on socket %s: %s\n",
			    listener->socket_path, strerror(errsv));
		close(fd);
		return -errsv;
	}

	listener->listening_fd = fd;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "EGD server: listening on %s\n", listener->socket_path);

	return 0;
}

int esdm_egd_server_socket_init(void)
{
	struct esdm_egd_listener *listener;
	int ret;

	for_each_esdm_egd_listener (listener) {
		ret = esdm_egd_listener_socket_init(listener);
		if (ret)
			return ret;
	}

	return 0;
}

/* Milliseconds on the monotonic clock. */
static uint64_t esdm_egd_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Is a response waiting to be accepted by the client? */
static bool esdm_egd_out_pending(const struct esdm_egd_conn *conn)
{
	return (conn->out_off < conn->out_len);
}

/*
 * Push out what is left of the response.
 *
 * A socket that cannot take it all is not waited for: the rest stays in the
 * connection, the event loop arms EPOLLOUT and it goes out once the client has
 * made room. Waiting here would hand every other client's latency to whichever
 * one is slowest to read.
 *
 * @return 0 when the connection remains usable, whether or not everything went
 *	   out, < 0 when it has to be closed
 */
static int esdm_egd_flush(struct esdm_egd_conn *conn)
{
	while (esdm_egd_out_pending(conn)) {
		/*
		 * MSG_NOSIGNAL: a client closing its end between asking and
		 * being answered is an everyday event and must come back as an
		 * EPIPE for this connection, not a SIGPIPE for the whole daemon
		 * - the ESDM is a library as much as a daemon, and the host
		 * process owns that signal's disposition. The client library
		 * deliberately does not use this, as the sendto(2) it compiles
		 * to is killed by OpenSSH's pre-authentication sandbox.
		 */
		ssize_t ret = send(conn->fd, conn->out + conn->out_off,
				   conn->out_len - conn->out_off,
				   MSG_NOSIGNAL);

		if (ret > 0) {
			conn->out_off += (size_t)ret;
			continue;
		}

		if (ret < 0 && errno == EINTR)
			continue;

		/* The client has not made room yet - EPOLLOUT tells us when. */
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 0;

		return ret < 0 ? -errno : -EIO;
	}

	/* Delivered - and the buffer is free for the next response. */
	memset_secure(conn->out, 0, conn->out_len);
	conn->out_len = 0;
	conn->out_off = 0;

	return 0;
}

/*
 * Hand a complete response to the client.
 *
 * At most one response is outstanding per connection - a command is only
 * processed once its predecessor's response is gone - which bounds the buffer
 * below to the largest single response the protocol can express.
 *
 * @return 0 when the connection remains usable - the response may still be on
 *	   its way out then - < 0 when it has to be closed
 */
static int esdm_egd_write(struct esdm_egd_conn *conn, const uint8_t *buf,
			  size_t len)
{
	if (esdm_egd_out_pending(conn) || len > sizeof(conn->out)) {
		/*
		 * Both are broken invariants rather than anything a client can
		 * provoke, and continuing would put bytes on the wire that no
		 * request asked for.
		 */
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: response of %zu bytes cannot be queued on FD %d\n",
			    len, conn->fd);
		return -EOVERFLOW;
	}

	memcpy(conn->out, buf, len);
	conn->out_len = len;
	conn->out_off = 0;
	conn->out_since = esdm_egd_now_ms();

	return esdm_egd_flush(conn);
}

/*
 * Fill @buf with data from the generator this connection's socket selects.
 *
 * Exactly one non-blocking generation is attempted. A request it does not cover
 * goes back to the event loop as a deferred request (see
 * esdm_egd_cmd_read_block()) rather than being retried here, which would tie the
 * worker - it serves every client of both sockets - to a single request for as
 * long as the entropy sources need.
 *
 * @generated reports how much was produced, which matters for the prediction
 * resistance generator: it hands out no more than was just delivered, so a
 * short answer is normal, and discarding it to start over would waste entropy
 * and never converge on a large request.
 *
 * @return 0 when @len bytes were produced, -EAGAIN when fewer were (the
 *	   caller decides whether to answer short or to come back for more),
 *	   < 0 on all other errors
 */
static int esdm_egd_get_random(const struct esdm_egd_conn *conn, uint8_t *buf,
			       size_t len, size_t *generated)
{
	bool pr = conn->listener->prediction_resistance;
	ssize_t ret;

	*generated = 0;

	if (pr)
		ret = esdm_get_random_bytes_pr_noblock(buf, len);
	else
		ret = esdm_get_random_bytes_full_noblock(buf, len);

	if (ret < 0)
		return (ret == -EAGAIN) ? -EAGAIN : (int)ret;

	/*
	 * Nothing available: for the prediction resistance generator that means
	 * the entropy sources have not delivered yet, for the ordinary one it
	 * should not happen at all.
	 */
	if (ret == 0)
		return pr ? -EAGAIN : -EFAULT;

	*generated = (size_t)ret;

	return (*generated < len) ? -EAGAIN : 0;
}

/* Command 0x00: report the currently available amount of entropy in bits. */
static int esdm_egd_cmd_entropy_count(struct esdm_egd_conn *conn)
{
	uint32_t ent = esdm_avail_entropy();
	uint8_t resp[4];

	/* The count is transferred in big endian byte order. */
	be32_to_ptr(resp, ent);

	return esdm_egd_write(conn, resp, sizeof(resp));
}

/*
 * Command 0x01: deliver up to the requested number of bytes without blocking.
 *
 * The response is prefixed with the number of delivered bytes, which allows
 * answering with zero bytes while the ESDM is not operational yet. Clients
 * treat that as "no entropy available right now" and fall back to the blocking
 * request.
 */
static int esdm_egd_cmd_read_nonblock(struct esdm_egd_conn *conn,
				      uint8_t requested)
{
	uint8_t resp[1 + ESDM_EGD_MAX_TRANSFER];
	int ret;

	resp[0] = requested;

	if (requested) {
		size_t generated = 0;

		ret = esdm_egd_get_random(conn, resp + 1, requested,
					  &generated);
		if (ret == -EAGAIN) {
			/* A short answer is what this command is for. */
			resp[0] = (uint8_t)generated;
		} else if (ret) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "EGD server: generation of %u bytes failed: %d\n",
				    requested, ret);
			resp[0] = 0;
		}
	}

	ret = esdm_egd_write(conn, resp, 1 + (size_t)resp[0]);

	memset_secure(resp, 0, sizeof(resp));

	return ret;
}

/*
 * Command 0x02: deliver exactly the requested number of bytes, waiting for the
 * ESDM to become operational if needed.
 *
 * @return 0 when the request was served, -EAGAIN when it has to be retried
 *	   later, < 0 on all other errors
 */
static int esdm_egd_cmd_read_block(struct esdm_egd_conn *conn,
				   uint8_t requested)
{
	size_t generated = 0;
	int ret;

	if (!requested)
		return 0;

	/*
	 * Collect into the connection rather than into a local buffer: a
	 * request is assembled over as many rounds of the event loop as the
	 * available entropy needs - most visibly on the prediction resistance
	 * socket, whose generator hands out no more than its entropy sources
	 * just delivered - and what came out so far must survive them.
	 */
	ret = esdm_egd_get_random(conn, conn->answer + conn->answer_len,
				  requested - conn->answer_len, &generated);
	conn->answer_len += (uint8_t)generated;

	if (ret == -EAGAIN)
		return -EAGAIN;
	if (ret)
		goto out;

	ret = esdm_egd_write(conn, conn->answer, requested);

out:
	memset_secure(conn->answer, 0, sizeof(conn->answer));
	conn->answer_len = 0;

	return ret;
}

/*
 * Command 0x03: insert caller provided data into the auxiliary pool.
 *
 * The protocol lets the caller claim an entropy content for the data. Honoring
 * that from an arbitrary local user would let any of them drive the ESDM's
 * entropy accounting, so the claim is only accepted from a privileged caller -
 * the same rule the RPC interface applies. Unprivileged data is still mixed
 * into the auxiliary pool, just without entropy credit.
 *
 * The command has no response.
 */
static int esdm_egd_cmd_write_entropy(struct esdm_egd_conn *conn,
				      uint32_t entropy_bits, const uint8_t *data,
				      uint8_t len)
{
	int ret;

	if (!len)
		return 0;

	if (conn->peer_uid != 0) {
		if (entropy_bits) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_SERVER,
				"EGD server: ignoring entropy claim of %u bits from unprivileged UID %u\n",
				entropy_bits, conn->peer_uid);
		}
		entropy_bits = 0;
	}

	/* The data cannot hold more entropy than it has bits. */
	if (entropy_bits > (uint32_t)len * 8)
		entropy_bits = (uint32_t)len * 8;

	ret = esdm_pool_insert_aux(data, len, entropy_bits);
	if (ret) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
			    "EGD server: insertion of %u bytes into the auxiliary pool failed: %d\n",
			    len, ret);
	}

	/*
	 * An insertion failure is not a protocol error - the command has no
	 * response in which it could be reported, and the connection stays
	 * usable.
	 */
	return 0;
}

/* Command 0x04: report the PID of the daemon serving the socket. */
static int esdm_egd_cmd_get_pid(struct esdm_egd_conn *conn)
{
	uint8_t resp[1 + 20];
	int len;

	len = snprintf((char *)resp + 1, sizeof(resp) - 1, "%d", (int)getpid());
	if (len < 0 || (size_t)len >= sizeof(resp))
		return -EFAULT;

	resp[0] = (uint8_t)len;

	return esdm_egd_write(conn, resp, 1 + (size_t)len);
}

/* Serve a deferred blocking read request, if there is one. */
static int esdm_egd_serve_deferred(struct esdm_egd_conn *conn)
{
	int ret;

	if (!conn->deferred)
		return 0;

	ret = esdm_egd_cmd_read_block(conn, conn->deferred);
	if (ret)
		return ret;

	conn->deferred = 0;

	return 0;
}

/*
 * Watch the connection for what it can currently make progress on.
 *
 * A response on its way out is waited for with EPOLLOUT and nothing else: the
 * command behind it is not processed until it is delivered.
 *
 * A connection with a deferred request is watched for neither, since nothing of
 * it is read (see esdm_egd_read()) and a level-triggered EPOLLIN would spin the
 * worker on a pipelined client's unread bytes for as long as the request waits.
 * EPOLLERR and EPOLLHUP are reported regardless, so an unwatched connection is
 * still torn down when its peer goes away.
 */
static void esdm_egd_conn_arm(int epfd, struct esdm_egd_conn *conn)
{
	struct epoll_event ev = { .data.ptr = conn };

	if (esdm_egd_out_pending(conn))
		ev.events = EPOLLOUT;
	else if (!conn->deferred)
		ev.events = EPOLLIN | EPOLLRDHUP;

	if (conn->armed == ev.events)
		return;

	if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			    "EGD server: cannot watch client FD %d for 0x%x: %s\n",
			    conn->fd, ev.events, strerror(errno));
		return;
	}

	conn->armed = ev.events;
}

/* Consume @len bytes from the head of the connection's input buffer. */
static void esdm_egd_consume(struct esdm_egd_conn *conn, size_t len)
{
	conn->in_len -= len;
	if (conn->in_len)
		memmove(conn->in, conn->in + len, conn->in_len);
}

/*
 * Get the connection as far as it can go right now: deliver what is left of the
 * response in flight, then process as many complete commands as the input
 * buffer holds.
 *
 * It stops at the first command whose response the client did not take right
 * away, which is what makes one response buffer enough: a client asking faster
 * than it reads is slowed down by its own socket, not buffered for.
 *
 * @return 0 when the connection remains usable, < 0 when it has to be closed
 */
static int esdm_egd_process(struct esdm_egd_conn *conn)
{
	int ret;

	/* The response of the previous command has to be out of the way. */
	ret = esdm_egd_flush(conn);
	if (ret)
		return ret;
	if (esdm_egd_out_pending(conn))
		return 0;

	/*
	 * A deferred request blocks the connection: its response must precede
	 * the responses of all commands received after it.
	 */
	ret = esdm_egd_serve_deferred(conn);
	if (ret)
		return (ret == -EAGAIN) ? 0 : ret;
	if (esdm_egd_out_pending(conn))
		return 0;

	while (conn->in_len) {
		size_t cmd_len;

		switch (conn->in[0]) {
		case ESDM_EGD_CMD_ENTROPY_COUNT:
		case ESDM_EGD_CMD_GET_PID:
			cmd_len = 1;
			break;
		case ESDM_EGD_CMD_READ_NONBLOCK:
		case ESDM_EGD_CMD_READ_BLOCK:
			cmd_len = 2;
			break;
		case ESDM_EGD_CMD_WRITE_ENTROPY:
			if (conn->in_len < 4)
				return 0;
			cmd_len = 4 + (size_t)conn->in[3];
			break;
		default:
			/*
			 * The protocol offers no way to report an error, and
			 * an unknown command byte means the stream is out of
			 * sync - the only sane reaction is to drop the client.
			 */
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
				    "EGD server: unknown command 0x%02x on FD %d\n",
				    conn->in[0], conn->fd);
			return -EPROTO;
		}

		/* Wait for the remainder of the command. */
		if (conn->in_len < cmd_len)
			return 0;

		switch (conn->in[0]) {
		case ESDM_EGD_CMD_ENTROPY_COUNT:
			ret = esdm_egd_cmd_entropy_count(conn);
			break;
		case ESDM_EGD_CMD_GET_PID:
			ret = esdm_egd_cmd_get_pid(conn);
			break;
		case ESDM_EGD_CMD_READ_NONBLOCK:
			ret = esdm_egd_cmd_read_nonblock(conn, conn->in[1]);
			break;
		case ESDM_EGD_CMD_READ_BLOCK:
			ret = esdm_egd_cmd_read_block(conn, conn->in[1]);
			if (ret == -EAGAIN) {
				/*
				 * Remember the request and answer it once the
				 * ESDM turned operational. The command is
				 * consumed here so it is not processed twice.
				 */
				conn->deferred = conn->in[1];
				esdm_egd_consume(conn, cmd_len);
				return 0;
			}
			break;
		case ESDM_EGD_CMD_WRITE_ENTROPY:
			/* Big endian entropy claim, see the protocol header. */
			ret = esdm_egd_cmd_write_entropy(
				conn, ptr_to_be16(conn->in + 1), conn->in + 4,
				conn->in[3]);
			break;
		default:
			/* Cannot happen - the switch above filtered it out. */
			ret = -EPROTO;
			break;
		}

		/* Do not leave client supplied entropy data in the buffer. */
		memset_secure(conn->in, 0, cmd_len);
		esdm_egd_consume(conn, cmd_len);

		if (ret)
			return ret;

		/*
		 * The response did not fit into the client's socket buffer. The
		 * command behind it has to wait for it to be delivered - its own
		 * response would otherwise be read as the answer to this one.
		 */
		if (esdm_egd_out_pending(conn))
			return 0;
	}

	return 0;
}

#ifdef ESDM_FUZZING
/* Documented with its declaration in esdm_egd_server.h */
int esdm_egd_fuzz_stream(bool prediction_resistance, int out_fd,
			 const uint8_t *data, size_t len)
{
	struct esdm_egd_conn conn;
	size_t pos = 0;
	int ret = 0;

	if (len && !data)
		return -EINVAL;

	memset(&conn, 0, sizeof(conn));
	conn.fd = out_fd;
	conn.listener = prediction_resistance ? ESDM_EGD_LISTENER_PR :
						ESDM_EGD_LISTENER_REGULAR;
	/*
	 * Who the client is decides whether its entropy claim is believed, so
	 * it is the credentials of this process - the same answer the accept
	 * path gets from the socket, and root only where the harness runs as
	 * root.
	 */
	conn.peer_uid = getuid();

	/*
	 * The input is a sequence of records, each a length byte followed by
	 * that many bytes, and each record is one read() as the connection
	 * would see it.
	 */
	while (pos < len) {
		size_t chunk = data[pos++];

		if (chunk > len - pos)
			chunk = len - pos;

		if (chunk > sizeof(conn.in) - conn.in_len)
			chunk = sizeof(conn.in) - conn.in_len;

		if (chunk) {
			memcpy(conn.in + conn.in_len, data + pos, chunk);
			conn.in_len += chunk;
			pos += chunk;
		}

		ret = esdm_egd_process(&conn);
		if (ret)
			break;
	}

	memset_secure(conn.in, 0, sizeof(conn.in));
	memset_secure(conn.answer, 0, sizeof(conn.answer));
	memset_secure(conn.out, 0, sizeof(conn.out));

	return ret;
}
#endif /* ESDM_FUZZING */

/*
 * Read from the connection and process what became complete.
 *
 * @return 0 when the connection remains usable, < 0 when it has to be closed
 */
static int esdm_egd_read(struct esdm_egd_conn *conn)
{
	while (1) {
		ssize_t received;
		int ret;

		/*
		 * While a request is deferred, a response is on its way out or
		 * the buffer is full, do not read further: the pending data
		 * stays in the socket buffer, which applies backpressure to the
		 * client instead of requiring unbounded buffering here.
		 */
		if (conn->deferred || esdm_egd_out_pending(conn) ||
		    conn->in_len >= sizeof(conn->in))
			return 0;

		/* recv() for symmetry with the send() of the response. */
		received = recv(conn->fd, conn->in + conn->in_len,
				sizeof(conn->in) - conn->in_len, 0);
		if (received == 0) {
			/* Orderly shutdown by the client. */
			return -EPIPE;
		}
		if (received < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -errno;
		}

		conn->in_len += (size_t)received;

		ret = esdm_egd_process(conn);
		if (ret)
			return ret;
	}
}

static void esdm_egd_release_conn(struct esdm_egd_conn *conn)
{
	if (!conn)
		return;

	if (conn->fd >= 0) {
		shutdown(conn->fd, SHUT_RDWR);
		close(conn->fd);
		conn->fd = -1;
	}

	memset_secure(conn->in, 0, sizeof(conn->in));
	memset_secure(conn->out, 0, sizeof(conn->out));
	memset_secure(conn->answer, 0, sizeof(conn->answer));
	free(conn);
}

/* Accept one client and register it with the event loop. */
static struct esdm_egd_conn *
esdm_egd_accept(int epfd, const struct esdm_egd_listener *listener)
{
	struct esdm_egd_conn *conn;
	struct ucred cred;
	socklen_t cred_len = sizeof(cred);
	struct epoll_event ev;
	int fd = accept4(listener->listening_fd, NULL, NULL,
			 SOCK_NONBLOCK | SOCK_CLOEXEC);

	if (fd < 0)
		return NULL;

	conn = calloc(1, sizeof(struct esdm_egd_conn));
	if (!conn) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot allocate client connection\n");
		close(fd);
		return NULL;
	}

	conn->fd = fd;
	conn->listener = listener;

	/*
	 * Latch the peer's UID now: it decides whether an entropy claim of a
	 * write request is honored. A client dropping its privileges later
	 * keeps the credentials it connected with, which is the same property
	 * the RPC interface has for its long-lived connections.
	 */
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot obtain peer credentials: %s\n",
			    strerror(errno));
		esdm_egd_release_conn(conn);
		return NULL;
	}
	conn->peer_uid = cred.uid;

	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.ptr = conn;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot add client FD %d to epoll: %s\n",
			    fd, strerror(errno));
		esdm_egd_release_conn(conn);
		return NULL;
	}
	conn->armed = ev.events;

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_SERVER,
		"EGD server: new %sconnection on FD %d from UID %u\n",
		listener->prediction_resistance ? "prediction resistant " : "",
		fd, conn->peer_uid);

	return conn;
}

/* Thread main serving the EGD socket. */
static int esdm_egd_handler(void __unused *args)
{
	struct esdm_egd_conn_list conn_list;
	struct esdm_egd_conn *conn, *tmp;
	struct esdm_egd_listener *listener;
	struct epoll_event events[ESDM_EGD_MAX_EVENTS];
	size_t num_connections = 0;
	size_t deferred_requests = 0;
	/*
	 * Did a deferred request get any data in the last round? As long as one
	 * makes progress the next round follows immediately: the prediction
	 * resistance generator delivers a large request in chunks, and waiting
	 * the poll interval between them would multiply its latency. Other
	 * clients are still served in between.
	 */
	bool deferred_progress = false;
	/*
	 * The listening FD is level-triggered, so it has to be disarmed while
	 * no further client may be accepted - otherwise epoll_wait would
	 * report it readable over and over and spin the worker.
	 */
	bool listen_armed = true;
	int epfd = -1;
	int ret = 0;

	thread_set_name(egd_server, 0);
	TAILQ_INIT(&conn_list);

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot create epoll: %s\n",
			    strerror(errno));
		goto out;
	}

	/*
	 * Both sockets are served by this one thread: a listener is identified
	 * by its own pointer in the epoll data, a connection by the pointer to
	 * its own structure, and the two can never collide.
	 */
	for_each_esdm_egd_listener (listener) {
		if (listener->listening_fd < 0)
			continue;

		if (epoll_ctl(epfd, EPOLL_CTL_ADD, listener->listening_fd,
			      &(struct epoll_event){
				      .events = EPOLLIN,
				      .data.ptr = listener,
			      }) < 0) {
			ret = -errno;
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SERVER,
				"EGD server: cannot add listening FD to epoll: %s\n",
				strerror(errno));
			goto out;
		}

		/*
		 * The path is only known for a socket bound by us - a socket
		 * handed over by systemd carries its path in the .socket unit.
		 */
		esdm_logger(LOGGER_STATUS, LOGGER_C_SERVER,
			    "EGD server: serving %s%s\n",
			    listener->prediction_resistance ?
				    "with prediction resistance on " :
				    "",
			    listener->systemd_socket ?
				    "the socket provided by systemd" :
				    listener->socket_path);
	}

	while (atomic_load(&esdm_egd_exit) == 0) {
		bool want_armed = (num_connections < ESDM_EGD_MAX_CONNECTIONS);
		int nfds, i;

		if (want_armed != listen_armed) {
			bool armed_all = true;

			for_each_esdm_egd_listener (listener) {
				struct epoll_event lev = {
					.events = want_armed ? EPOLLIN : 0,
					.data.ptr = listener,
				};

				if (listener->listening_fd < 0)
					continue;
				if (epoll_ctl(epfd, EPOLL_CTL_MOD,
					      listener->listening_fd, &lev))
					armed_all = false;
			}

			if (armed_all)
				listen_armed = want_armed;
		}

		/*
		 * A deferred request is not tied to any descriptor event - it
		 * completes once entropy is available again. Poll more often
		 * while one is outstanding, and not at all while one is being
		 * filled round by round; the other clients' events are still
		 * collected in between, so the worker stays shared.
		 */
		nfds = epoll_wait(epfd, events, ESDM_EGD_MAX_EVENTS,
				  deferred_progress ?
					  0 :
					  (deferred_requests ?
						   ESDM_EGD_DEFERRED_POLL_MS :
						   ESDM_EGD_IDLE_POLL_MS));
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "EGD server: epoll_wait failed: %s\n",
				    strerror(errno));
			goto out;
		}

		for (i = 0; i < nfds; i++) {
			/*
			 * Tell the two apart by the pointer itself: the
			 * listeners live in a static array of their own, so a
			 * connection can never be mistaken for one.
			 */
			if (events[i].data.ptr >= (void *)&esdm_egd_listeners[0] &&
			    events[i].data.ptr <
				    (void *)&esdm_egd_listeners[ARRAY_SIZE(
					    esdm_egd_listeners)]) {
				conn = esdm_egd_accept(epfd,
						       events[i].data.ptr);
				if (!conn)
					continue;

				TAILQ_INSERT_TAIL(&conn_list, conn, tailq);
				num_connections++;
				continue;
			}

			conn = events[i].data.ptr;

			if (events[i].events & (EPOLLERR | EPOLLHUP))
				ret = -EPIPE;
			else if (esdm_egd_out_pending(conn))
				/* Room was made - deliver the rest and go on. */
				ret = esdm_egd_process(conn);
			else
				ret = esdm_egd_read(conn);

			/*
			 * EPOLLRDHUP only signals that the client will not send
			 * any more data - it may still be waiting for what it
			 * asked for before, be that a response on its way out or
			 * a request that has yet to find its entropy. Close only
			 * once nothing is owed to it any more.
			 */
			if (!ret && (events[i].events & EPOLLRDHUP) &&
			    !conn->deferred && !esdm_egd_out_pending(conn))
				ret = -EPIPE;

			if (ret) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_SERVER,
					"EGD server: closing connection on FD %d\n",
					conn->fd);
				epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
				TAILQ_REMOVE(&conn_list, conn, tailq);
				esdm_egd_release_conn(conn);
				num_connections--;
				continue;
			}

			/* The step above may have changed what to watch for. */
			esdm_egd_conn_arm(epfd, conn);
		}

		ret = 0;

		/*
		 * Whatever is not waiting for an event of its own: a deferred
		 * request, which completes when entropy arrives, and a response
		 * whose client has not made room, retried here so a missed
		 * EPOLLOUT cannot strand it. The deferred requests are recounted
		 * on the way, as the loop above may have changed their number.
		 */
		deferred_requests = 0;
		deferred_progress = false;
		TAILQ_FOREACH_SAFE (conn, &conn_list, tailq, tmp) {
			uint8_t collected, deferred;
			uint64_t out_since = conn->out_since;
			bool stuck;

			if (!conn->deferred && !esdm_egd_out_pending(conn))
				continue;

			collected = conn->answer_len;
			deferred = conn->deferred;

			if (esdm_egd_process(conn)) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_SERVER,
					"EGD server: closing connection on FD %d\n",
					conn->fd);
				epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
				TAILQ_REMOVE(&conn_list, conn, tailq);
				esdm_egd_release_conn(conn);
				num_connections--;
				continue;
			}

			/*
			 * A response the client never took. It holds up nobody
			 * else, but the connection is of no use to anyone until
			 * it is gone - reclaim it.
			 */
			stuck = (esdm_egd_out_pending(conn) &&
				 conn->out_since == out_since &&
				 esdm_egd_now_ms() - conn->out_since >
					 ESDM_EGD_WRITE_TIMEOUT_MS);
			if (stuck) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_SERVER,
					"EGD server: client on FD %d is not reading its response\n",
					conn->fd);
				epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
				TAILQ_REMOVE(&conn_list, conn, tailq);
				esdm_egd_release_conn(conn);
				num_connections--;
				continue;
			}

			/*
			 * Only a request waiting for entropy sets the pace. A
			 * response waiting for its client is woken by EPOLLOUT,
			 * and hurrying for it would spin against a full socket.
			 * The answer is reset once sent, so a change of its
			 * length means this round produced something.
			 */
			if (deferred) {
				if (conn->answer_len != collected ||
				    conn->deferred != deferred)
					deferred_progress = true;

				if (conn->deferred)
					deferred_requests++;
			}

			esdm_egd_conn_arm(epfd, conn);
		}
	}

out:
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "EGD server: exiting worker thread\n");

	TAILQ_FOREACH_SAFE (conn, &conn_list, tailq, tmp) {
		TAILQ_REMOVE(&conn_list, conn, tailq);
		if (epfd >= 0)
			epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
		esdm_egd_release_conn(conn);
	}

	if (epfd >= 0)
		close(epfd);

	atomic_store(&esdm_egd_worker_running, false);

	return ret;
}

int esdm_egd_server_start(void)
{
	int ret;

	/*
	 * The interface is active exactly when esdm_egd_server_socket_init()
	 * obtained a listening socket - either from systemd or by binding the
	 * path requested on the command line. One worker serves both of them.
	 */
	if (!esdm_egd_server_active())
		return 0;

	atomic_store(&esdm_egd_worker_running, true);

	ret = thread_start(esdm_egd_handler, NULL, ESDM_THREAD_EGD_GROUP, NULL);
	if (ret) {
		atomic_store(&esdm_egd_worker_running, false);
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: starting worker thread failed\n");
	}

	return ret;
}

void esdm_egd_server_signal_exit_safe(void)
{
	atomic_store(&esdm_egd_exit, 1);
}

void esdm_egd_server_fini(void)
{
	struct esdm_egd_listener *listener;
	unsigned int i;

	if (!esdm_egd_server_active())
		return;

	esdm_egd_server_signal_exit_safe();

	/*
	 * Wait for the worker to leave its event loop before the ESDM is
	 * finalized - it must not be inside esdm_get_random_bytes_full_noblock
	 * or esdm_pool_insert_aux by then. It is a special thread and thus not
	 * covered by the RPC server's thread_wait_all(). The bound is generous
	 * against the poll interval, but shutdown must not hang either.
	 */
	for (i = 0; i < 100 && atomic_load(&esdm_egd_worker_running); i++) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };

		nanosleep(&ts, NULL);
	}

	for_each_esdm_egd_listener (listener) {
		if (listener->listening_fd < 0)
			continue;
		close(listener->listening_fd);
		listener->listening_fd = -1;
	}
}

void esdm_egd_server_cleanup(void)
{
	struct esdm_egd_listener *listener;

	for_each_esdm_egd_listener (listener) {
		if (!esdm_egd_listener_enabled(listener))
			continue;

		/*
		 * A systemd socket is created and removed by systemd -
		 * unlinking one it still listens on leaves its .socket unit
		 * bound to an unlinked inode. listener->systemd_socket alone
		 * does not answer this: the privileged PID namespace supervisor
		 * also runs here and forked before the sockets were set up, so
		 * fall back to the activation state latched before that fork.
		 * Conservative on purpose - at worst a self-bound socket is left
		 * behind, and the stale socket check removes it at the next
		 * start.
		 */
		if (listener->systemd_socket || systemd_listen_fds() > 0)
			continue;

		if (unlink(listener->socket_path) < 0) {
			if (errno != ENOENT) {
				esdm_logger(
					LOGGER_VERBOSE, LOGGER_C_SERVER,
					"EGD socket %s cannot be deleted: %s\n",
					listener->socket_path,
					strerror(errno));
			}
		} else {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
				    "EGD socket %s deleted\n",
				    listener->socket_path);
		}
	}
}
