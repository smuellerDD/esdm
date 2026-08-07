/*
 * Test peer speaking the EGD wire protocol
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
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "egd_peer.h"
#include "esdm_egd_protocol.h"

/*
 * One connection per client, plus room for the ones a forked child of a test
 * opens - a handful is all any test needs.
 */
#define EGD_PEER_MAX_CONN 8

/* How long the accept loop waits before it looks at the stop flag again. */
#define EGD_PEER_POLL_MS 50

struct egd_peer {
	enum egd_peer_mode mode;
	int listen_fd;
	pthread_t accept_thread;
	atomic_int stop;

	pthread_mutex_t lock;
	unsigned int connections;
	unsigned int requests;
	unsigned int nconn;
	int conn_fds[EGD_PEER_MAX_CONN];
	pthread_t conn_threads[EGD_PEER_MAX_CONN];

	unsigned int writes;
	uint8_t write_buf[ESDM_EGD_MAX_TRANSFER];
	size_t write_len;
	uint32_t write_bits;

	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

struct egd_peer_conn {
	struct egd_peer *peer;
	int fd;
	/* Bytes delivered on this connection, the read answers count from it. */
	size_t sent;
};

/****************************
 * Blocking transfers
 ****************************/

static int peer_read_all(int fd, uint8_t *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = read(fd, buf + done, len - done);

		if (ret > 0) {
			done += (size_t)ret;
			continue;
		}
		if (ret == 0)
			return -EPIPE;
		if (errno == EINTR)
			continue;

		return -errno;
	}

	return 0;
}

static int peer_write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = write(fd, buf + done, len - done);

		if (ret > 0) {
			done += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;

		return (ret < 0) ? -errno : -EIO;
	}

	return 0;
}

/****************************
 * The commands
 ****************************/

/* Deliver @len bytes of the connection's counter sequence. */
static int peer_send_data(struct egd_peer_conn *conn, size_t len)
{
	uint8_t buf[ESDM_EGD_MAX_TRANSFER];
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = egd_peer_data_byte(conn->sent + i);
	conn->sent += len;

	return peer_write_all(conn->fd, buf, len);
}

static int peer_cmd_entropy_count(struct egd_peer_conn *conn)
{
	uint8_t response[4] = {
		(uint8_t)(EGD_PEER_ENTROPY_BITS >> 24),
		(uint8_t)(EGD_PEER_ENTROPY_BITS >> 16),
		(uint8_t)(EGD_PEER_ENTROPY_BITS >> 8),
		(uint8_t)EGD_PEER_ENTROPY_BITS,
	};

	return peer_write_all(conn->fd, response, sizeof(response));
}

static int peer_cmd_read_nonblock(struct egd_peer_conn *conn)
{
	uint8_t requested, delivered;
	int ret;

	ret = peer_read_all(conn->fd, &requested, sizeof(requested));
	if (ret)
		return ret;

	switch (conn->peer->mode) {
	case EGD_PEER_SHORT:
		/* Half of it, and nothing at all for a single byte. */
		delivered = (uint8_t)(requested / 2);
		break;
	case EGD_PEER_OVERLONG:
		/*
		 * One byte more than was asked for. The client has to reject
		 * that on the length byte alone - reading the data would
		 * desynchronize the stream for good.
		 */
		if (requested == ESDM_EGD_MAX_TRANSFER)
			return -EINVAL;
		delivered = (uint8_t)(requested + 1);
		break;
	case EGD_PEER_NORMAL:
	case EGD_PEER_SILENT:
	case EGD_PEER_HANGUP:
		delivered = requested;
		break;
	}

	ret = peer_write_all(conn->fd, &delivered, sizeof(delivered));
	if (ret)
		return ret;

	return peer_send_data(conn, delivered);
}

static int peer_cmd_read_block(struct egd_peer_conn *conn)
{
	uint8_t requested;
	int ret;

	ret = peer_read_all(conn->fd, &requested, sizeof(requested));
	if (ret)
		return ret;

	/* The blocking command is answered in full, whatever it takes. */
	return peer_send_data(conn, requested);
}

static int peer_cmd_write_entropy(struct egd_peer_conn *conn)
{
	struct egd_peer *peer = conn->peer;
	uint8_t header[3];
	uint8_t buf[ESDM_EGD_MAX_TRANSFER];
	int ret;

	/* Two big endian entropy bytes and the length. */
	ret = peer_read_all(conn->fd, header, sizeof(header));
	if (ret)
		return ret;

	ret = peer_read_all(conn->fd, buf, header[2]);
	if (ret)
		return ret;

	pthread_mutex_lock(&peer->lock);
	peer->write_bits = ((uint32_t)header[0] << 8) | (uint32_t)header[1];
	peer->write_len = header[2];
	memcpy(peer->write_buf, buf, header[2]);
	peer->writes++;
	pthread_mutex_unlock(&peer->lock);

	/* This command has no answer. */
	return 0;
}

static int peer_cmd_get_pid(struct egd_peer_conn *conn)
{
	char pid[32];
	uint8_t len;
	int ret;

	/* The PID goes out as a string, without a terminating NUL. */
	ret = snprintf(pid, sizeof(pid), "%d", EGD_PEER_PID);
	if (ret <= 0)
		return -EFAULT;
	len = (uint8_t)ret;

	ret = peer_write_all(conn->fd, &len, sizeof(len));
	if (ret)
		return ret;

	return peer_write_all(conn->fd, (const uint8_t *)pid, len);
}

/****************************
 * Connection and accept loop
 ****************************/

static void *peer_conn_thread(void *arg)
{
	struct egd_peer_conn *conn = arg;
	struct egd_peer *peer = conn->peer;
	struct timespec nowait = { 0, 0 };
	sigset_t sigpipe;

	/*
	 * A client that gives up on an answer - which several of the tests make
	 * it do, the overlong one on the very byte before the data - closes its
	 * end while this thread is in the middle of writing the response, and
	 * an unhandled SIGPIPE would take the whole test process down with it.
	 * The peer writes plainly rather than with MSG_NOSIGNAL, as this has to
	 * stay reachable from where sendto(2) is not.
	 *
	 * Blocked here rather than ignored process wide on purpose: the client
	 * library promises to never let a vanished peer raise SIGPIPE (it polls
	 * for writability instead of using MSG_NOSIGNAL, see its header), and
	 * ignoring the signal for the whole process would take that promise out
	 * of the test. A blocked SIGPIPE only makes the write of this thread
	 * report EPIPE; every other thread keeps the default disposition, so a
	 * client that broke that promise still kills the test.
	 */
	sigemptyset(&sigpipe);
	sigaddset(&sigpipe, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sigpipe, NULL);

	while (!atomic_load(&peer->stop)) {
		uint8_t cmd;
		int ret;

		/*
		 * A silent peer reads nothing at all: the client's request fits
		 * into the socket buffer, so it gets as far as waiting for an
		 * answer that never comes - which is the point of this mode.
		 */
		if (peer->mode == EGD_PEER_SILENT) {
			struct pollfd pfd = { .fd = conn->fd, .events = 0 };

			poll(&pfd, 1, EGD_PEER_POLL_MS);
			continue;
		}

		ret = peer_read_all(conn->fd, &cmd, sizeof(cmd));
		if (ret)
			break;

		/*
		 * Counted on receipt, before the answer goes out. Counting a
		 * served request instead would race with the client it was
		 * served to: the client returns as soon as it has read the
		 * answer, so it can be back - and looking at this counter -
		 * while the thread that wrote that very answer has not got
		 * round to incrementing it yet.
		 */
		pthread_mutex_lock(&peer->lock);
		peer->requests++;
		pthread_mutex_unlock(&peer->lock);

		switch (cmd) {
		case ESDM_EGD_CMD_ENTROPY_COUNT:
			ret = peer_cmd_entropy_count(conn);
			break;
		case ESDM_EGD_CMD_READ_NONBLOCK:
			ret = peer_cmd_read_nonblock(conn);
			break;
		case ESDM_EGD_CMD_READ_BLOCK:
			ret = peer_cmd_read_block(conn);
			break;
		case ESDM_EGD_CMD_WRITE_ENTROPY:
			ret = peer_cmd_write_entropy(conn);
			break;
		case ESDM_EGD_CMD_GET_PID:
			ret = peer_cmd_get_pid(conn);
			break;
		default:
			printf("EGD peer: unknown command 0x%02x\n", cmd);
			ret = -EPROTO;
			break;
		}

		if (ret)
			break;
	}

	/*
	 * Blocking the signal keeps the write from being fatal, it does not make
	 * the signal go away: a SIGPIPE raised above is still pending on this
	 * thread, and leaving the thread is not enough to be rid of it. Whoever
	 * unblocks SIGPIPE in this thread first gets it delivered, and the exit
	 * path does exactly that - the sanitizer runtime's thread specific data
	 * destructor takes the mask apart on the way out, so an ASan build dies
	 * of the pending signal in __nptl_deallocate_tsd(), long after the write
	 * that raised it. That is the very death the block above exists to
	 * prevent, only moved to where nothing points at the cause any more.
	 *
	 * So take the signal off the thread here, while it is still blocked and
	 * this is the only thread that could receive it. Nothing is pending in
	 * the common case, where the zero timeout returns right away.
	 */
	while (sigtimedwait(&sigpipe, NULL, &nowait) < 0 && errno == EINTR)
		;

	free(conn);

	return NULL;
}

static void *peer_accept_thread(void *arg)
{
	struct egd_peer *peer = arg;

	while (!atomic_load(&peer->stop)) {
		struct pollfd pfd = {
			.fd = peer->listen_fd,
			.events = POLLIN,
		};
		struct egd_peer_conn *conn;
		unsigned int connections;
		int fd;

		if (poll(&pfd, 1, EGD_PEER_POLL_MS) <= 0)
			continue;

		fd = accept(peer->listen_fd, NULL, NULL);
		if (fd < 0)
			continue;

		pthread_mutex_lock(&peer->lock);
		peer->connections++;
		connections = peer->connections;
		pthread_mutex_unlock(&peer->lock);

		/* A daemon that went away between two requests. */
		if (peer->mode == EGD_PEER_HANGUP && connections == 1) {
			close(fd);
			continue;
		}

		conn = calloc(1, sizeof(*conn));
		if (conn == NULL || peer->nconn >= EGD_PEER_MAX_CONN) {
			printf("EGD peer: cannot serve the connection\n");
			free(conn);
			close(fd);
			continue;
		}
		conn->peer = peer;
		conn->fd = fd;

		/*
		 * Only the accept thread touches these two, and stopping joins
		 * it before it looks at them.
		 */
		peer->conn_fds[peer->nconn] = fd;
		if (pthread_create(&peer->conn_threads[peer->nconn], NULL,
				   peer_conn_thread, conn)) {
			printf("EGD peer: cannot create the connection thread\n");
			free(conn);
			close(fd);
			continue;
		}
		peer->nconn++;
	}

	return NULL;
}

/****************************
 * Lifecycle
 ****************************/

int egd_peer_start(struct egd_peer **peer, const char *path,
		   enum egd_peer_mode mode)
{
	struct egd_peer *new_peer;
	struct sockaddr_un addr;
	int ret;

	if (peer == NULL || path == NULL)
		return -EINVAL;
	*peer = NULL;

	new_peer = calloc(1, sizeof(struct egd_peer));
	if (new_peer == NULL)
		return -ENOMEM;

	new_peer->mode = mode;
	new_peer->listen_fd = -1;
	atomic_init(&new_peer->stop, 0);
	pthread_mutex_init(&new_peer->lock, NULL);

	if (strlen(path) >= sizeof(new_peer->path)) {
		free(new_peer);
		return -ENAMETOOLONG;
	}
	snprintf(new_peer->path, sizeof(new_peer->path), "%s", path);

	new_peer->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (new_peer->listen_fd < 0) {
		ret = -errno;
		goto err;
	}

	/* A leftover of a previous run would make the bind fail. */
	unlink(path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	if (bind(new_peer->listen_fd, (struct sockaddr *)&addr,
		 sizeof(addr)) < 0) {
		ret = -errno;
		goto err;
	}

	if (listen(new_peer->listen_fd, EGD_PEER_MAX_CONN) < 0) {
		ret = -errno;
		goto err;
	}

	if (pthread_create(&new_peer->accept_thread, NULL, peer_accept_thread,
			   new_peer)) {
		ret = -EFAULT;
		goto err;
	}

	*peer = new_peer;

	return 0;

err:
	if (new_peer->listen_fd >= 0)
		close(new_peer->listen_fd);
	pthread_mutex_destroy(&new_peer->lock);
	free(new_peer);

	return ret;
}

void egd_peer_stop(struct egd_peer *peer)
{
	unsigned int i;

	if (peer == NULL)
		return;

	atomic_store(&peer->stop, 1);
	pthread_join(peer->accept_thread, NULL);

	/*
	 * Shut the connections down before joining: a connection thread sits in
	 * a blocking read, which only returns once the other end is gone.
	 */
	for (i = 0; i < peer->nconn; i++)
		shutdown(peer->conn_fds[i], SHUT_RDWR);
	for (i = 0; i < peer->nconn; i++) {
		pthread_join(peer->conn_threads[i], NULL);
		close(peer->conn_fds[i]);
	}

	close(peer->listen_fd);
	unlink(peer->path);
	pthread_mutex_destroy(&peer->lock);
	free(peer);
}

unsigned int egd_peer_connections(struct egd_peer *peer)
{
	unsigned int connections;

	pthread_mutex_lock(&peer->lock);
	connections = peer->connections;
	pthread_mutex_unlock(&peer->lock);

	return connections;
}

unsigned int egd_peer_requests(struct egd_peer *peer)
{
	unsigned int requests;

	pthread_mutex_lock(&peer->lock);
	requests = peer->requests;
	pthread_mutex_unlock(&peer->lock);

	return requests;
}

unsigned int egd_peer_last_write(struct egd_peer *peer, uint8_t *buf,
				 size_t buflen, size_t *len,
				 uint32_t *entropy_bits)
{
	unsigned int writes;

	pthread_mutex_lock(&peer->lock);
	writes = peer->writes;
	if (len)
		*len = peer->write_len;
	if (entropy_bits)
		*entropy_bits = peer->write_bits;
	if (buf)
		memcpy(buf, peer->write_buf,
		       (buflen < peer->write_len) ? buflen : peer->write_len);
	pthread_mutex_unlock(&peer->lock);

	return writes;
}
