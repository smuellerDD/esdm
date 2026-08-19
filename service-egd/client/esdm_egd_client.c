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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "bitshift_be.h"
#include "config.h"
#include "esdm_egd_client.h"
#include "esdm_egd_protocol.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "mutex_w.h"
#include "visibility.h"

/*
 * Attempts per operation: the initial one plus a single retry on a freshly
 * opened connection. A second retry would not add anything - if a brand new
 * connection cannot carry the request either, the peer is not merely gone
 * since the last one.
 */
#define ESDM_EGD_CLIENT_ATTEMPTS 2

/*
 * Default bound, in milliseconds, on how long the client waits for the peer in
 * one step - the connection setup, or one transfer. Generous, because the
 * blocking read waits for the ESDM to become operational, which right after
 * boot takes a moment: this is a backstop against a wedged daemon, not a
 * latency target.
 */
#define ESDM_EGD_CLIENT_DEFAULT_TIMEOUT_MS 30000

/*
 * How long to wait before retrying a connect that found the peer's listen
 * backlog full. There is nothing to poll for in that case - the connection was
 * never initiated - so this is a plain retry interval, kept short because a
 * full backlog clears as soon as the peer accepts.
 */
#define ESDM_EGD_CLIENT_BACKLOG_RETRY_MS 20

/*
 * Upper bound of the configurable timeout. poll(2) takes its timeout as an
 * int, so an unreasonable value has to be capped rather than overflowed into a
 * nonsensical - possibly negative, i.e. infinite - one.
 */
#define ESDM_EGD_CLIENT_MAX_TIMEOUT_MS 3600000

/* Environment variable overriding the compiled in socket path. */
#define ESDM_EGD_CLIENT_SOCKET_ENV "ESDM_EGD_SOCKET"

struct esdm_egd_client {
	char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	unsigned int timeout_ms;

	/*
	 * Serializes the command stream - see the header. Robust, because it is
	 * held across the whole request / response exchange, bounded by nothing
	 * but the client's timeout: a caller killed in that window - shot while
	 * waiting for an ESDM that is not operational yet - would leave a plain
	 * mutex locked for the rest of the process' lifetime. A robust mutex
	 * hands the lock to the next taker instead.
	 */
	mutex_w_t lock;

	int fd;
	/*
	 * Process that opened @fd. The fork handler below normally deals with
	 * an inherited connection, but it only runs for fork(3); this is the
	 * backstop for the ways around it - a direct clone(2), or a child of a
	 * process that was already forked before this library was loaded.
	 */
	pid_t owner_pid;

	/* Registry entry, see esdm_egd_client_atfork_child(). */
	TAILQ_ENTRY(esdm_egd_client) tailq;
};

/*
 * Every live client, so that the fork handler can reach them. The lock is only
 * ever held to walk or edit this list - never across I/O - which is what makes
 * it safe to take in the prepare handler: fork() is delayed by no more than a
 * list operation.
 */
static TAILQ_HEAD(esdm_egd_client_list, esdm_egd_client) esdm_egd_clients =
	TAILQ_HEAD_INITIALIZER(esdm_egd_clients);
/*
 * Statically initialized so it is a usable lock even before the one time
 * initialization below turns it into a robust one - and the fallback should
 * that ever fail.
 */
static DEFINE_MUTEX_W_UNLOCKED(esdm_egd_clients_lock);
static pthread_once_t esdm_egd_client_init_once = PTHREAD_ONCE_INIT;

/*
 * Take the registry lock.
 *
 * EOWNERDEAD reports that the previous owner died while holding it. The lock is
 * recovered by the wrapper and the list is used as found - a TAILQ operation is
 * not atomic, so an owner that died inside one may have left it inconsistent,
 * with no way to tell from here. Still better than the alternative, where every
 * later alloc and free waits forever for a lock nobody can release.
 */
static void esdm_egd_clients_lock_acquire(void)
{
	if (mutex_w_lock(&esdm_egd_clients_lock) == EOWNERDEAD) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"EGD client: the client registry was left behind by a died owner - continuing with it as found\n");
	}
}

/****************************
 * Connection handling
 ****************************/

/* Caller holds the lock. */
static void esdm_egd_client_disconnect_locked(struct esdm_egd_client *client)
{
	if (client->fd < 0)
		return;

	close(client->fd);
	client->fd = -1;
}

/****************************
 * fork handling
 ****************************/

/*
 * Hold the registry across the fork, so the child cannot inherit it mid-edit
 * and walk a half-linked list.
 */
static void esdm_egd_client_atfork_prepare(void)
{
	esdm_egd_clients_lock_acquire();
}

static void esdm_egd_client_atfork_parent(void)
{
	mutex_w_unlock(&esdm_egd_clients_lock);
}

/*
 * Recreate a lock in the fork child, see esdm_egd_client_atfork_child() for
 * why that is what has to happen to every lock reachable from there.
 */
static void esdm_egd_client_recreate_lock(mutex_w_t *lock)
{
	/*
	 * The destroy fails with EBUSY for a lock that is still held - which is
	 * precisely the state this cleans up after. Nothing can be done about
	 * that, and the initialization below replaces the lock either way.
	 */
	mutex_w_destroy(lock);

	if (mutex_w_init(lock, 0, 1)) {
		static const mutex_w_t lock_init = MUTEX_W_UNLOCKED;

		/*
		 * A fork handler has nowhere to report to, and leaving the lock
		 * behind as it was found would hang the child. A plain mutex is
		 * still a working lock - only the recovery from a died owner is
		 * lost with it.
		 */
		*lock = lock_init;
	}
}

/*
 * Give up every inherited connection right here in the child.
 *
 * A child's duplicated descriptors refer to the parent's connections, and two
 * processes issuing commands on one EGD stream would desynchronize it. Closing
 * at the fork rather than at the next use also releases them immediately.
 *
 * The locks are recreated rather than unlocked, robustness notwithstanding: it
 * only hands over a lock when a thread of *this* process dies, and a lock held
 * by a parent thread that does not exist here would hang the child forever.
 * That includes the registry lock the prepare handler took - a robust mutex
 * records its owner by thread ID and fork(2) gave this thread a new one, so to
 * the lock its owner no longer exists. The child is single threaded here, so
 * recreating is safe.
 *
 * pthread_mutex_destroy()/_init() are not formally async-signal-safe, but they
 * neither allocate nor lock in the implementations at hand, and a robust mutex
 * cannot be reset by assigning a static initializer over it.
 */
static void esdm_egd_client_atfork_child(void)
{
	struct esdm_egd_client *client;

	TAILQ_FOREACH (client, &esdm_egd_clients, tailq) {
		if (client->fd >= 0) {
			close(client->fd);
			client->fd = -1;
		}

		esdm_egd_client_recreate_lock(&client->lock);
	}

	esdm_egd_client_recreate_lock(&esdm_egd_clients_lock);
}

/* Process wide setup, run once from esdm_egd_client_alloc(). */
static void esdm_egd_client_init(void)
{
	/*
	 * Make the registry lock robust. It is only held for a list operation,
	 * but the prepare handler above holds it across the fork(2) itself, and
	 * a caller killed in that window would leave every later allocation and
	 * release waiting for a lock with no owner. A static initializer cannot
	 * express this, hence the one time initialization here.
	 */
	if (mutex_w_init(&esdm_egd_clients_lock, 0, 1)) {
		static const mutex_w_t lock_init = MUTEX_W_UNLOCKED;

		/*
		 * Restore the plain lock: a failed initialization may have left
		 * the mutex half set up, and the registry needs *a* lock.
		 */
		esdm_egd_clients_lock = lock_init;
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"EGD client: cannot create a robust registry lock - a caller dying while it is held then wedges the client registry\n");
	}

	if (pthread_atfork(esdm_egd_client_atfork_prepare,
			   esdm_egd_client_atfork_parent,
			   esdm_egd_client_atfork_child)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"EGD client: cannot install the fork handler - an inherited connection is then only dropped at its next use\n");
	}
}

/* Milliseconds on the monotonic clock. */
static uint64_t esdm_egd_client_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Milliseconds left until @deadline_ms, 0 once it passed. */
static int esdm_egd_client_remaining_ms(uint64_t deadline_ms)
{
	uint64_t now = esdm_egd_client_now_ms();
	uint64_t remaining;

	if (now >= deadline_ms)
		return 0;

	remaining = deadline_ms - now;

	return (remaining > INT_MAX) ? INT_MAX : (int)remaining;
}

/*
 * Wait for @events on @fd, bounded by @timeout_ms.
 *
 * @return 0 when the descriptor is ready, -ETIMEDOUT when the wait ran out,
 *	   negative errno otherwise. @revents, when given, reports what poll
 *	   found - an error condition is not turned into a failure here, as the
 *	   caller decides whether it matters.
 */
static int esdm_egd_client_wait(int fd, short events, int timeout_ms,
				short *revents)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = events,
	};
	int ret;

	do {
		ret = poll(&pfd, 1, timeout_ms);
	} while (ret < 0 && errno == EINTR);

	if (revents)
		*revents = pfd.revents;

	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIMEDOUT;

	return 0;
}

/*
 * Connect @fd, bounded by @timeout_ms.
 *
 * The socket is non-blocking, which is what makes the bound possible in the
 * first place: a blocking connect() to a Unix domain socket whose peer has a
 * full listen backlog waits for as long as it takes, with no way to limit it.
 */
static int esdm_egd_client_connect_fd(int fd, const struct sockaddr_un *addr,
				      unsigned int timeout_ms)
{
	uint64_t deadline = esdm_egd_client_now_ms() + (uint64_t)timeout_ms;

	while (1) {
		int remaining, ret;

		if (connect(fd, (const struct sockaddr *)addr,
			    sizeof(*addr)) == 0)
			return 0;

		if (errno == EINTR)
			continue;

		/*
		 * A Unix domain socket reports a full listen backlog this way
		 * instead of blocking. The connection was never initiated, so
		 * there is nothing to poll for - wait a moment and try again
		 * until the deadline.
		 */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			struct timespec retry = {
				.tv_sec = 0,
				.tv_nsec = ESDM_EGD_CLIENT_BACKLOG_RETRY_MS *
					   1000L * 1000L,
			};

			remaining = esdm_egd_client_remaining_ms(deadline);
			if (remaining <= 0)
				return -ETIMEDOUT;
			if (remaining < ESDM_EGD_CLIENT_BACKLOG_RETRY_MS)
				retry.tv_nsec = (long)remaining * 1000L * 1000L;

			nanosleep(&retry, NULL);
			continue;
		}

		/*
		 * Not what a Unix domain socket does, but the address family is
		 * not this function's business - handle the generic
		 * non-blocking connect completion as well.
		 */
		if (errno == EINPROGRESS || errno == EALREADY) {
			int err = 0;
			socklen_t errlen = sizeof(err);

			remaining = esdm_egd_client_remaining_ms(deadline);
			if (remaining <= 0)
				return -ETIMEDOUT;

			ret = esdm_egd_client_wait(fd, POLLOUT, remaining, NULL);
			if (ret)
				return ret;

			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err,
				       &errlen) < 0)
				return -errno;

			return err ? -err : 0;
		}

		return -errno;
	}
}

/* Caller holds the lock. */
static int esdm_egd_client_connect_locked(struct esdm_egd_client *client)
{
	struct sockaddr_un addr;
	int errsv, fd, ret;

	/*
	 * SOCK_NONBLOCK: every wait of this client is bounded by a poll of its
	 * own, starting with the connect below.
	 *
	 * SOCK_CLOEXEC: the connection belongs to this process - an exec'd
	 * child must not inherit a descriptor into the middle of our command
	 * stream.
	 */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 client->socket_path);

	ret = esdm_egd_client_connect_fd(fd, &addr, client->timeout_ms);
	if (ret) {
		errsv = -ret;
		close(fd);
		return -errsv;
	}

	client->fd = fd;
	client->owner_pid = getpid();

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "EGD client: connected to %s\n", client->socket_path);

	return 0;
}

/*
 * Is the descriptor still our connection? Caller holds the lock.
 *
 * Applications do close descriptor ranges they did not open - OpenSSH's
 * privilege separation runs closefrom() on its way into the pre-authentication
 * child. Landing after this client connected, that frees the descriptor number
 * for reuse, and reading "random" data out of whatever took its place would be
 * a silent and serious failure. getpeername(2) is permitted even inside
 * OpenSSH's pre-auth sandbox, so confirming costs one allowed syscall.
 */
static bool esdm_egd_client_fd_is_ours_locked(struct esdm_egd_client *client)
{
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);

	memset(&addr, 0, sizeof(addr));

	/* Gone, or not a socket any more. */
	if (getpeername(client->fd, (struct sockaddr *)&addr, &addrlen) < 0)
		return false;

	/* Some other socket took the number. */
	if (addr.sun_family != AF_UNIX || addrlen > sizeof(addr))
		return false;

	return strncmp(addr.sun_path, client->socket_path,
		       sizeof(addr.sun_path)) == 0;
}

/* Caller holds the lock. */
static int esdm_egd_client_ensure_connected_locked(struct esdm_egd_client *client)
{
	if (client->fd >= 0 && client->owner_pid == getpid() &&
	    esdm_egd_client_fd_is_ours_locked(client))
		return 0;

	/*
	 * Either never connected, inherited across a fork() - see the comment
	 * on owner_pid - or the descriptor is no longer ours.
	 */
	esdm_egd_client_disconnect_locked(client);

	return esdm_egd_client_connect_locked(client);
}

/****************************
 * Raw transfers
 ****************************/

/* Caller holds the lock. */
static int esdm_egd_client_write_all_locked(struct esdm_egd_client *client,
					    const uint8_t *buf, size_t len)
{
	int timeout_ms = (int)client->timeout_ms;
	size_t written = 0;

	while (written < len) {
		short revents = 0;
		ssize_t ret;
		int wret;

		/*
		 * Establish writability before writing rather than after an
		 * EAGAIN: poll reports the hangup of a peer that went away, so
		 * the write never happens and cannot raise a SIGPIPE that would
		 * kill the application this library is linked into. send(2)
		 * with MSG_NOSIGNAL is deliberately not used - it is sendto(2),
		 * which OpenSSH's pre-auth sandbox answers with
		 * SECCOMP_RET_KILL (see the header).
		 */
		wret = esdm_egd_client_wait(client->fd, POLLOUT, timeout_ms,
					    &revents);
		if (wret)
			return wret;
		if (revents & (POLLERR | POLLHUP | POLLNVAL))
			return -EPIPE;

		ret = write(client->fd, buf + written, len - written);

		if (ret > 0) {
			written += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			continue;

		return (ret < 0) ? -errno : -EIO;
	}

	return 0;
}

/* Caller holds the lock. */
static int esdm_egd_client_read_all_locked(struct esdm_egd_client *client,
					   uint8_t *buf, size_t len)
{
	int timeout_ms = (int)client->timeout_ms;
	size_t received = 0;

	while (received < len) {
		ssize_t ret = read(client->fd, buf + received, len - received);

		if (ret > 0) {
			received += (size_t)ret;
			continue;
		}
		/* The peer closed the connection mid-response. */
		if (ret == 0)
			return -EPIPE;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			int wret = esdm_egd_client_wait(client->fd, POLLIN,
							timeout_ms, NULL);

			if (wret)
				return wret;
			continue;
		}

		return -errno;
	}

	return 0;
}

/*
 * Run one operation, retrying it once on a fresh connection.
 *
 * @op is invoked with the lock held and a connection established; it performs
 * the whole request / response exchange and returns 0 or a negative errno.
 */
static int esdm_egd_client_invoke(struct esdm_egd_client *client,
				  int (*op)(struct esdm_egd_client *, void *),
				  void *arg)
{
	unsigned int attempt;
	int ret = -EIO;

	if (client == NULL)
		return -EINVAL;

	/*
	 * EOWNERDEAD means the lock was taken over from a caller that died mid
	 * exchange. The lock is consistent again, the connection is not: a half
	 * written command leaves the peer's parser at an unknown offset, and an
	 * unconsumed response would be handed to the next request. The
	 * descriptor is still valid, so nothing below would notice - drop it
	 * here and let the loop open a fresh one.
	 */
	if (mutex_w_lock(&client->lock) == EOWNERDEAD) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"EGD client: recovered the lock of %s from a died owner, dropping the connection\n",
			client->socket_path);
		esdm_egd_client_disconnect_locked(client);
	}

	for (attempt = 0; attempt < ESDM_EGD_CLIENT_ATTEMPTS; attempt++) {
		ret = esdm_egd_client_ensure_connected_locked(client);
		if (ret)
			continue;

		ret = op(client, arg);
		if (!ret)
			break;

		/*
		 * Where in the command stream the failure left the peer is
		 * unknowable from here - a half written command would make it
		 * misread the next one - so the connection is not reusable.
		 * Drop it; the next attempt opens a fresh one.
		 */
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"EGD client: transfer on %s failed (%s), dropping the connection\n",
			client->socket_path, strerror(-ret));
		esdm_egd_client_disconnect_locked(client);
	}

	mutex_w_unlock(&client->lock);

	return ret;
}

/****************************
 * Operations
 ****************************/

struct esdm_egd_random_op {
	uint8_t *buf;
	size_t buflen;
	size_t generated;
};

/* Blocking read, split into protocol sized transfers. */
static int esdm_egd_client_get_random_op(struct esdm_egd_client *client,
					 void *arg)
{
	struct esdm_egd_random_op *op = arg;
	size_t done = 0;

	while (done < op->buflen) {
		size_t remaining = op->buflen - done;
		uint8_t chunk = (remaining > ESDM_EGD_MAX_TRANSFER) ?
					ESDM_EGD_MAX_TRANSFER :
					(uint8_t)remaining;
		uint8_t request[2] = { ESDM_EGD_CMD_READ_BLOCK, chunk };
		int ret;

		ret = esdm_egd_client_write_all_locked(client, request,
						       sizeof(request));
		if (ret)
			return ret;

		ret = esdm_egd_client_read_all_locked(client, op->buf + done,
						      chunk);
		if (ret)
			return ret;

		done += chunk;
	}

	op->generated = done;

	return 0;
}

DSO_PUBLIC
int esdm_egd_client_get_random(struct esdm_egd_client *client, uint8_t *buf,
			       size_t buflen)
{
	struct esdm_egd_random_op op = {
		.buf = buf,
		.buflen = buflen,
		.generated = 0,
	};
	int ret;

	if (buf == NULL)
		return -EINVAL;
	if (buflen == 0)
		return 0;

	ret = esdm_egd_client_invoke(client, esdm_egd_client_get_random_op,
				     &op);
	if (ret) {
		/*
		 * A partial transfer must never be mistaken for a complete
		 * one - leave nothing behind that looks like random data.
		 */
		memset_secure(buf, 0, buflen);
	}

	return ret;
}

static int esdm_egd_client_get_random_nonblock_op(struct esdm_egd_client *client,
						  void *arg)
{
	struct esdm_egd_random_op *op = arg;
	uint8_t request[2] = { ESDM_EGD_CMD_READ_NONBLOCK,
			       (uint8_t)op->buflen };
	uint8_t delivered;
	int ret;

	ret = esdm_egd_client_write_all_locked(client, request,
					       sizeof(request));
	if (ret)
		return ret;

	ret = esdm_egd_client_read_all_locked(client, &delivered,
					      sizeof(delivered));
	if (ret)
		return ret;

	/*
	 * More data than asked for would mean the peer is not speaking this
	 * protocol - reading it would desynchronize the stream for good.
	 */
	if (delivered > op->buflen)
		return -EPROTO;

	if (delivered) {
		ret = esdm_egd_client_read_all_locked(client, op->buf,
						      delivered);
		if (ret)
			return ret;
	}

	op->generated = delivered;

	return 0;
}

DSO_PUBLIC
int esdm_egd_client_get_random_nonblock(struct esdm_egd_client *client,
					uint8_t *buf, size_t buflen,
					size_t *generated)
{
	struct esdm_egd_random_op op = {
		.buf = buf,
		.buflen = buflen,
		.generated = 0,
	};
	int ret;

	if (buf == NULL || generated == NULL)
		return -EINVAL;
	if (buflen > ESDM_EGD_MAX_TRANSFER)
		return -EINVAL;

	*generated = 0;
	if (buflen == 0)
		return 0;

	ret = esdm_egd_client_invoke(
		client, esdm_egd_client_get_random_nonblock_op, &op);
	if (ret) {
		memset_secure(buf, 0, buflen);
		return ret;
	}

	*generated = op.generated;

	return 0;
}

static int esdm_egd_client_entropy_count_op(struct esdm_egd_client *client,
					    void *arg)
{
	const uint8_t request = ESDM_EGD_CMD_ENTROPY_COUNT;
	uint32_t *entropy_bits = arg;
	uint8_t response[4];
	int ret;

	ret = esdm_egd_client_write_all_locked(client, &request,
					       sizeof(request));
	if (ret)
		return ret;

	ret = esdm_egd_client_read_all_locked(client, response,
					      sizeof(response));
	if (ret)
		return ret;

	/* The count is transferred in big endian byte order. */
	*entropy_bits = ptr_to_be32(response);

	return 0;
}

DSO_PUBLIC
int esdm_egd_client_entropy_count(struct esdm_egd_client *client,
				  uint32_t *entropy_bits)
{
	if (entropy_bits == NULL)
		return -EINVAL;

	return esdm_egd_client_invoke(client, esdm_egd_client_entropy_count_op,
				      entropy_bits);
}

struct esdm_egd_write_op {
	const uint8_t *buf;
	uint8_t buflen;
	uint32_t entropy_bits;
};

static int esdm_egd_client_write_entropy_op(struct esdm_egd_client *client,
					    void *arg)
{
	struct esdm_egd_write_op *op = arg;
	uint8_t header[4];
	int ret;

	header[0] = ESDM_EGD_CMD_WRITE_ENTROPY;
	/* The entropy claim is transferred in big endian byte order. */
	be16_to_ptr(header + 1, (uint16_t)op->entropy_bits);
	header[3] = op->buflen;

	ret = esdm_egd_client_write_all_locked(client, header, sizeof(header));
	if (ret)
		return ret;

	/* The command has no response. */
	return esdm_egd_client_write_all_locked(client, op->buf, op->buflen);
}

DSO_PUBLIC
int esdm_egd_client_write_entropy(struct esdm_egd_client *client,
				  const uint8_t *buf, size_t buflen,
				  uint32_t entropy_bits)
{
	struct esdm_egd_write_op op;

	if (buf == NULL)
		return -EINVAL;
	if (buflen == 0)
		return 0;
	if (buflen > ESDM_EGD_MAX_TRANSFER)
		return -EINVAL;

	/* The protocol carries the claim in two bytes. */
	if (entropy_bits > UINT16_MAX)
		entropy_bits = UINT16_MAX;

	op.buf = buf;
	op.buflen = (uint8_t)buflen;
	op.entropy_bits = entropy_bits;

	return esdm_egd_client_invoke(client, esdm_egd_client_write_entropy_op,
				      &op);
}

static int esdm_egd_client_get_pid_op(struct esdm_egd_client *client, void *arg)
{
	const uint8_t request = ESDM_EGD_CMD_GET_PID;
	pid_t *pid = arg;
	/* The PID arrives as a string, without a terminating NUL. */
	char response[UINT8_MAX + 1];
	uint8_t len;
	char *end;
	long value;
	int ret;

	ret = esdm_egd_client_write_all_locked(client, &request,
					       sizeof(request));
	if (ret)
		return ret;

	ret = esdm_egd_client_read_all_locked(client, &len, sizeof(len));
	if (ret)
		return ret;

	if (len == 0)
		return -EPROTO;

	ret = esdm_egd_client_read_all_locked(client, (uint8_t *)response, len);
	if (ret)
		return ret;
	response[len] = '\0';

	errno = 0;
	value = strtol(response, &end, 10);

	/*
	 * The length prefix covers the digits and nothing else, so a response
	 * carrying anything besides them - or no digit at all - is not this
	 * protocol and its number is not to be believed.
	 */
	if (errno || end == response || end != response + len)
		return -EPROTO;

	/*
	 * A PID does not have to fit into a pid_t just because it arrived as
	 * text: the peer decides how many digits it sends, and a number beyond
	 * the type truncates on the way in - to a value naming a different
	 * process as often as to a negative one, which is what a caller passing
	 * it to kill(2) turns into a whole process group.
	 */
	if (value <= 0 || (long)(pid_t)value != value)
		return -EPROTO;

	*pid = (pid_t)value;

	return 0;
}

DSO_PUBLIC
int esdm_egd_client_get_pid(struct esdm_egd_client *client, pid_t *pid)
{
	if (pid == NULL)
		return -EINVAL;

	return esdm_egd_client_invoke(client, esdm_egd_client_get_pid_op, pid);
}

/****************************
 * Lifecycle
 ****************************/

DSO_PUBLIC
int esdm_egd_client_alloc(struct esdm_egd_client **client,
			  const char *socket_path, unsigned int timeout_ms)
{
	struct esdm_egd_client *new_client;
	int ret;

	if (client == NULL)
		return -EINVAL;
	*client = NULL;

	if (socket_path == NULL || *socket_path == '\0')
		socket_path = secure_getenv(ESDM_EGD_CLIENT_SOCKET_ENV);
	if (socket_path == NULL || *socket_path == '\0')
		socket_path = ESDM_SERVER_EGD_SOCKET_PATH;

	new_client = calloc(1, sizeof(struct esdm_egd_client));
	if (new_client == NULL)
		return -ENOMEM;

	if (strlen(socket_path) >= sizeof(new_client->socket_path)) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"EGD client: the socket path is %zu characters long, at most %zu are possible\n",
			strlen(socket_path),
			sizeof(new_client->socket_path) - 1);
		free(new_client);
		return -ENAMETOOLONG;
	}
	snprintf(new_client->socket_path, sizeof(new_client->socket_path), "%s",
		 socket_path);

	new_client->timeout_ms = timeout_ms ?
					 timeout_ms :
					 ESDM_EGD_CLIENT_DEFAULT_TIMEOUT_MS;
	if (new_client->timeout_ms > ESDM_EGD_CLIENT_MAX_TIMEOUT_MS)
		new_client->timeout_ms = ESDM_EGD_CLIENT_MAX_TIMEOUT_MS;
	new_client->fd = -1;

	/*
	 * Robust, see the struct. This has to succeed before the client is
	 * published: one that is reachable through the registry, or handed to
	 * the caller, without a lock that serializes and can be destroyed again
	 * is worse than no client at all.
	 */
	ret = mutex_w_init(&new_client->lock, 0, 1);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "EGD client: cannot create the client lock (%s)\n",
			    strerror(-ret));
		free(new_client);
		return ret;
	}

	/*
	 * Publish the client before connecting: from here on the fork handler
	 * knows about it, so no window exists in which a fork could leave a
	 * connection behind in a child.
	 */
	pthread_once(&esdm_egd_client_init_once, esdm_egd_client_init);
	esdm_egd_clients_lock_acquire();
	TAILQ_INSERT_TAIL(&esdm_egd_clients, new_client, tailq);
	mutex_w_unlock(&esdm_egd_clients_lock);

	/*
	 * Connect right away: a consumer serving a process that later confines
	 * itself must hold its connection by then, since opening one is exactly
	 * what such a process can no longer do (see the header). A failure is
	 * not fatal - the operations reconnect, so a consumer set up before the
	 * ESDM is running keeps working once it arrives.
	 */
	ret = esdm_egd_client_connect_locked(new_client);
	if (ret) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"EGD client: cannot connect to %s yet (%s) - retrying on first use\n",
			new_client->socket_path, strerror(-ret));
	}

	*client = new_client;

	return 0;
}

DSO_PUBLIC
void esdm_egd_client_free(struct esdm_egd_client *client)
{
	if (client == NULL)
		return;

	esdm_egd_clients_lock_acquire();
	TAILQ_REMOVE(&esdm_egd_clients, client, tailq);
	mutex_w_unlock(&esdm_egd_clients_lock);

	/*
	 * No client lock: the caller guarantees nobody uses the client any more,
	 * which it must, as the lock itself goes away here. Destroying it fails
	 * with EBUSY when a died owner left it held and nobody recovered it
	 * since. Nothing can be done about that and nothing leaks - the memory
	 * the mutex lives in is released right below.
	 */
	esdm_egd_client_disconnect_locked(client);
	mutex_w_destroy(&client->lock);
	free(client);
}

DSO_PUBLIC
const char *esdm_egd_client_socket_path(const struct esdm_egd_client *client)
{
	return client ? client->socket_path : NULL;
}
