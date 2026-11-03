/*
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

/*
 * The provider server: one thread polling the listening socket and its
 * clients, serving one request at a time - all the callbacks allow, and all
 * the ESDM needs, sending one request at a time.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm_es_ext.h"
#include "esdm_es_ext_json.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"
#include "visibility.h"

struct esdm_es_ext_server {
	const struct esdm_es_ext_plugin *plugin;
	void *ctx;
	bool initialized;

	/* What INFO declares: the name, empty for none, and the rates */
	char name[ESDM_ES_EXT_NAME_MAX + 1];
	uint32_t rate;
	uint32_t plugin_rate;

	/* For STATUS: self test verdict - 1 none yet - and monotonic ns */
	uint64_t requests;
	int selftest;
	uint64_t started;

	int listen_fd;
	int stop_pipe[2];
	int clients[ESDM_ES_EXT_MAX_CLIENTS];
	/* Accepted or last active, monotonic ns */
	uint64_t client_active[ESDM_ES_EXT_MAX_CLIENTS];
	bool client_root[ESDM_ES_EXT_MAX_CLIENTS];

	uid_t allowed_uids[ESDM_ES_EXT_MAX_CLIENT_UIDS];
	unsigned int allowed_uids_num;

	/*
	 * The socket file created, so that only that one is removed - by its
	 * name in its directory, opened once: what is checked and unlinked
	 * cannot be moved to another directory in between. The bind takes the
	 * path, so that it shows; one bound elsewhere is not removed.
	 */
	int dir_fd;
	char *file;
	dev_t dev;
	ino_t ino;
};

static void esdm_es_ext_server_close(struct esdm_es_ext_server *server,
				     unsigned int i)
{
	if (server->clients[i] >= 0)
		close(server->clients[i]);
	server->clients[i] = -1;
}

/* With uids allowed, only those and root - *@root tells which */
static bool esdm_es_ext_server_allowed(struct esdm_es_ext_server *server,
				       int fd, bool *root)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);
	bool known = !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);
	unsigned int i;

	*root = known && cred.uid == 0;
	if (!server->allowed_uids_num || *root)
		return true;
	for (i = 0; known && i < server->allowed_uids_num; i++) {
		if (cred.uid == server->allowed_uids[i])
			return true;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "External ES provider: client refused\n");
	return false;
}

/*
 * Make room for a new client by disconnecting @a rather than @b? A client of
 * root goes after one that is not, else the one idle the longer goes first.
 */
static bool esdm_es_ext_server_evict_first(struct esdm_es_ext_server *server,
					   unsigned int a, unsigned int b)
{
	if (server->client_root[a] != server->client_root[b])
		return !server->client_root[a];
	return server->client_active[a] < server->client_active[b];
}

/* Take one pending connection: false once there is none */
static bool esdm_es_ext_server_accept_one(struct esdm_es_ext_server *server)
{
	unsigned int i, slot = ESDM_ES_EXT_MAX_CLIENTS;
	bool root;
	int fd;

	fd = accept4(server->listen_fd, NULL, NULL,
		     SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0) {
		/* The connection stays pending: pace the retries */
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
		    errno == ENOMEM)
			nanosleep(&(struct timespec){ .tv_nsec = 100000000 },
				  NULL);
		return false;
	}

	if (!esdm_es_ext_server_allowed(server, fd, &root)) {
		close(fd);
		return true;
	}

	/* A free slot, else one to evict - never one of root for a non-root */
	for (i = 0; i < ESDM_ES_EXT_MAX_CLIENTS; i++) {
		if (server->clients[i] < 0) {
			slot = i;
			break;
		}
		if (server->client_root[i] && !root)
			continue;
		if (slot == ESDM_ES_EXT_MAX_CLIENTS ||
		    esdm_es_ext_server_evict_first(server, i, slot))
			slot = i;
	}

	/* Debug only: an allowed client can make these as often as it likes */
	if (slot == ESDM_ES_EXT_MAX_CLIENTS) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "External ES provider: too many clients\n");
		close(fd);
		return true;
	}
	if (server->clients[slot] >= 0)
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"External ES provider: too many clients, the one idle the longest disconnected\n");

	esdm_es_ext_server_close(server, slot);
	server->clients[slot] = fd;
	server->client_active[slot] = esdm_monotonic_now_ns();
	server->client_root[slot] = root;
	return true;
}

/*
 * Take the pending connections, up to the backlog: refused ones, possibly of
 * any local user, are closed at once instead of filling it.
 */
static void esdm_es_ext_server_accept(struct esdm_es_ext_server *server)
{
	unsigned int i;

	for (i = 0; i < ESDM_ES_EXT_MAX_CLIENTS; i++) {
		if (!esdm_es_ext_server_accept_one(server))
			break;
	}
}

/* The self test verdict: 1 for none yet, 0 or a negative errno */
static const char *esdm_es_ext_server_selftest_name(int selftest)
{
	if (selftest > 0)
		return "none";
	return selftest ? "failed" : "passed";
}

/* The status of the source, NULL for none or one that is no valid status */
static struct json_object *
esdm_es_ext_server_plugin_status(struct esdm_es_ext_server *server)
{
	char text[ESDM_ES_EXT_STATUS_MAX + 1] = { 0 };

	if (!server->plugin->status_json ||
	    esdm_es_ext_errno(server->plugin->status_json(server->ctx, text,
							  sizeof(text))))
		return NULL;

	return esdm_es_ext_json_object(text, strnlen(text, sizeof(text)),
				       ESDM_ES_EXT_STATUS_MAX,
				       ESDM_ES_EXT_STATUS_MAX_DEPTH);
}

static uint32_t esdm_es_ext_server_rate(const struct esdm_es_ext_server *server)
{
	return server->rate != ESDM_ES_EXT_PROTO_RATE_NONE ?
		       server->rate :
		       server->plugin_rate;
}

/*
 * Answer STATUS for at most @length bytes into @data: the fields of the
 * server and the status of the source, which is left out (null) if both do
 * not fit - half a JSON object is none.
 */
static int esdm_es_ext_server_status(struct esdm_es_ext_server *server,
				     uint8_t *data, uint32_t length,
				     uint32_t *datalen)
{
	struct json_object *root = json_object_new_object();
	struct json_object *obj = json_object_new_object();
	uint32_t rate = esdm_es_ext_server_rate(server);
	unsigned int i, clients = 0;
	const char *text;
	size_t len;
	int ret = -EMSGSIZE;

	if (!root || !obj) {
		json_object_put(root);
		json_object_put(obj);
		return -ENOMEM;
	}

	for (i = 0; i < ESDM_ES_EXT_MAX_CLIENTS; i++)
		clients += server->clients[i] >= 0;

	json_object_object_add(obj, "version", json_object_new_string(VERSION));
	json_object_object_add(obj, "plugin_api",
			       json_object_new_int64(server->plugin->version));
	json_object_object_add(
		obj, "name",
		server->name[0] ? json_object_new_string(server->name) : NULL);
	json_object_object_add(obj, "entropy_rate",
			       rate != ESDM_ES_EXT_PROTO_RATE_NONE ?
				       json_object_new_int64(rate) :
				       NULL);
	json_object_object_add(obj, "clients", json_object_new_int64(clients));
	json_object_object_add(obj, "client_slots",
			       json_object_new_int64(ESDM_ES_EXT_MAX_CLIENTS));
	json_object_object_add(
		obj, "requests",
		json_object_new_int64((int64_t)server->requests));
	json_object_object_add(
		obj, "selftest",
		json_object_new_string(
			esdm_es_ext_server_selftest_name(server->selftest)));
	json_object_object_add(
		obj, "uptime_seconds",
		json_object_new_int64(
			(int64_t)((esdm_monotonic_now_ns() - server->started) /
				  1000000000ULL)));
	json_object_object_add(root, "server", obj);
	json_object_object_add(root, "plugin",
			       esdm_es_ext_server_plugin_status(server));

	for (i = 0; i < 2 && ret; i++) {
		text = json_object_to_json_string_ext(
			root, JSON_C_TO_STRING_PLAIN |
				      JSON_C_TO_STRING_NOSLASHESCAPE);
		len = text ? strlen(text) : SIZE_MAX;
		if (len <= length) {
			memcpy(data, text, len);
			*datalen = (uint32_t)len;
			ret = 0;
		}
		json_object_object_add(root, "plugin", NULL);
	}

	json_object_put(root);
	return ret;
}

/*
 * Ask the source for @buflen bytes. Its claim must not exceed the data: a
 * source that cannot count its bits is not believed on them either.
 */
static int esdm_es_ext_server_get(struct esdm_es_ext_server *server,
				  uint8_t *buf, uint32_t buflen,
				  uint32_t *entropy_bits)
{
	int ret;

	/* A source writing less than asked hands out zeros, not the stack */
	memset(buf, 0, buflen);
	ret = server->plugin->get_entropy(server->ctx, buf, buflen,
					  entropy_bits);

	if (!ret && *entropy_bits > buflen * 8)
		ret = -EINVAL;
	return esdm_es_ext_errno(ret);
}

/* Serve the request of client @i, disconnecting it on an error */
static void esdm_es_ext_server_serve(struct esdm_es_ext_server *server,
				     unsigned int i)
{
	/* One byte more than a request, to tell a longer message */
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_MAX + 1];
	uint8_t msg[ESDM_ES_EXT_PROTO_MSG_MAX];
	struct esdm_es_ext_proto_rsp rsp = { 0 };
	uint32_t length, datalen = 0;
	uint16_t type;
	size_t msglen;
	ssize_t n;
	bool ret = false;

	server->client_active[i] = esdm_monotonic_now_ns();

	/* MSG_TRUNC: the size of a longer message, which is no request */
	n = recv(server->clients[i], req, sizeof(req),
		 MSG_DONTWAIT | MSG_TRUNC);
	if (n < 0 &&
	    (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		return;
	if (n <= 0 || (size_t)n > ESDM_ES_EXT_PROTO_REQ_MAX ||
	    esdm_es_ext_proto_req_unpack(req, (size_t)n, &type, &length)) {
		/* Debug only: an allowed client can send these in a loop */
		if (n > 0)
			esdm_logger(
				LOGGER_DEBUG, LOGGER_C_ANY,
				"External ES provider: invalid request, client disconnected\n");
		goto out;
	}

	rsp.type = type;
	switch (type) {
	case ESDM_ES_EXT_PROTO_GET_ENTROPY:
		rsp.datalen = length;
		rsp.status = esdm_es_ext_server_get(server, rsp.data, length,
						    &rsp.entropy_bits);
		break;
	case ESDM_ES_EXT_PROTO_STATUS:
		rsp.status = esdm_es_ext_server_status(server, rsp.data, length,
						       &datalen);
		rsp.datalen = datalen;
		break;
	case ESDM_ES_EXT_PROTO_INFO:
		rsp.rate = esdm_es_ext_server_rate(server);
		rsp.namelen = strlen(server->name);
		memcpy(rsp.name, server->name, rsp.namelen);
		break;
	case ESDM_ES_EXT_PROTO_SELFTEST:
		/* Without a test the verdict stays none, the answer is 0 */
		if (server->plugin->selftest) {
			rsp.status = esdm_es_ext_errno(
				server->plugin->selftest(server->ctx));
			server->selftest = rsp.status;
		}
		break;
	}

	/* The client reads one answer per request: it fits its queue */
	msglen = esdm_es_ext_proto_rsp_pack(msg, sizeof(msg), &rsp);
	ret = msglen && send(server->clients[i], msg, msglen,
			     MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)msglen;
	server->requests += ret;

out:
	memset_secure(&rsp, 0, sizeof(rsp));
	memset_secure(msg, 0, sizeof(msg));
	if (!ret)
		esdm_es_ext_server_close(server, i);
}

struct esdm_es_ext_server_bind {
	int fd;
	const struct sockaddr_un *addr;
	int ret;
	int unshare_errno;
};

/*
 * A thread of its own with its own umask: the umask is process wide, and
 * clearing it around the bind(2) would expose the files other threads create.
 */
static void *esdm_es_ext_server_bind_thread(void *arg)
{
	struct esdm_es_ext_server_bind *b = arg;

	if (unshare(CLONE_FS) == 0)
		umask(0);
	else
		b->unshare_errno = errno;

	b->ret = bind(b->fd, (const struct sockaddr *)b->addr,
		      sizeof(*b->addr)) < 0 ?
			 -errno :
			 0;
	return NULL;
}

/*
 * Create the socket file with @mode from the start: Linux takes it from the
 * socket inode, masked with the umask. A chmod(2) of the path afterwards, as
 * root, would follow a symlink swapped in meanwhile.
 */
static int esdm_es_ext_server_bind(int fd, const struct sockaddr_un *addr,
				   mode_t mode)
{
	struct esdm_es_ext_server_bind b = { .fd = fd, .addr = addr };
	pthread_t thread;
	int ret;

	if (fchmod(fd, mode & 0777) < 0)
		return -errno;

	ret = -pthread_create(&thread, NULL, esdm_es_ext_server_bind_thread,
			      &b);
	if (ret)
		return ret;
	pthread_join(thread, NULL);

	if (b.unshare_errno)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"Cannot clear the umask for socket %s (%s) - its mode may be narrower than %04o\n",
			addr->sun_path, strerror(b.unshare_errno),
			(unsigned int)(mode & 0777));

	return b.ret;
}

/*
 * Is the socket at @addr left behind? Only a refused connection proves that
 * nothing listens: a full backlog, for one, is a provider still serving.
 */
static bool esdm_es_ext_server_stale(const struct sockaddr_un *addr)
{
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
			0);
	bool stale;

	if (fd < 0)
		return false;
	stale = connect(fd, (const struct sockaddr *)addr, sizeof(*addr)) < 0 &&
		errno == ECONNREFUSED;
	close(fd);
	return stale;
}

/* Open the directory of @path and take the name of the file in it */
static int esdm_es_ext_server_dir(struct esdm_es_ext_server *server,
				  const char *path)
{
	const char *slash = strrchr(path, '/');
	char *dir;
	int ret = 0;

	if (!slash)
		dir = strdup(".");
	else if (slash == path)
		dir = strdup("/");
	else
		dir = strndup(path, (size_t)(slash - path));
	server->file = strdup(slash ? slash + 1 : path);
	if (!dir || !server->file) {
		ret = -ENOMEM;
		goto out;
	}

	server->dir_fd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (server->dir_fd < 0)
		ret = -errno;

out:
	free(dir);
	return ret;
}

/* Take the name of the source for INFO, if it is a valid one */
static void esdm_es_ext_server_plugin_name(struct esdm_es_ext_server *server)
{
	const char *name = esdm_es_ext_name_or_null(server->plugin->name);

	snprintf(server->name, sizeof(server->name), "%s", name ? name : "");
	if (!name && server->plugin->name)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: the name of the source is invalid, INFO declares none\n");
}

DSO_PUBLIC
int esdm_es_ext_server_alloc(const struct esdm_es_ext_plugin *plugin,
			     const char *socket_path, mode_t mode,
			     struct esdm_es_ext_server **server)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct esdm_es_ext_server *s;
	struct stat sb;
	unsigned int i;
	int ret;

	if (!server || !socket_path)
		return -EINVAL;
	*server = NULL;

	if (!plugin || plugin->version < 1 ||
	    plugin->version > ESDM_ES_EXT_PLUGIN_VERSION ||
	    !plugin->get_entropy)
		return -EPROTO;

	if (!socket_path[0])
		return -EINVAL;
	if (strlen(socket_path) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;
	strcpy(addr.sun_path, socket_path);

	s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;
	s->plugin = plugin;
	s->rate = s->plugin_rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	s->selftest = 1;
	s->started = esdm_monotonic_now_ns();
	s->listen_fd = s->stop_pipe[0] = s->stop_pipe[1] = s->dir_fd = -1;
	for (i = 0; i < ESDM_ES_EXT_MAX_CLIENTS; i++)
		s->clients[i] = -1;

	ret = esdm_es_ext_server_dir(s, socket_path);
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"External ES provider: cannot open the directory of %s: %s\n",
			socket_path, strerror(-ret));
		goto err;
	}

	if (pipe2(s->stop_pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
		ret = -errno;
		goto err;
	}

	/* A socket left behind by an earlier instance, and nothing else */
	if (!fstatat(s->dir_fd, s->file, &sb, AT_SYMLINK_NOFOLLOW)) {
		if (!S_ISSOCK(sb.st_mode)) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: %s exists and is no socket\n",
				socket_path);
			ret = -EEXIST;
			goto err;
		}
		if (!esdm_es_ext_server_stale(&addr)) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: another provider serves on %s\n",
				socket_path);
			ret = -EADDRINUSE;
			goto err;
		}
		unlinkat(s->dir_fd, s->file, 0);
	}

	/* Non-blocking: the backlog is taken until accept4(2) finds none */
	s->listen_fd = socket(AF_UNIX,
			      SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (s->listen_fd < 0) {
		ret = -errno;
		goto err;
	}

	ret = esdm_es_ext_server_bind(s->listen_fd, &addr, mode);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "External ES provider: cannot bind to %s: %s\n",
			    socket_path, strerror(-ret));
		goto err;
	}

	if (!fstatat(s->dir_fd, s->file, &sb, AT_SYMLINK_NOFOLLOW)) {
		s->dev = sb.st_dev;
		s->ino = sb.st_ino;
	}

	if (listen(s->listen_fd, ESDM_ES_EXT_MAX_CLIENTS) < 0) {
		ret = -errno;
		goto err;
	}

	if (plugin->init) {
		ret = esdm_es_ext_errno(plugin->init(&s->ctx));
		if (ret) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: initialization of the source failed: %s\n",
				strerror(-ret));
			goto err;
		}
	}
	s->initialized = true;

	/* After its init, which may find out what it is and what it has */
	esdm_es_ext_server_plugin_name(s);
	if (plugin->entropy_rate) {
		/* None stays none: capping it would credit what is unrated */
		s->plugin_rate =
			esdm_es_ext_rate_cap(plugin->entropy_rate(s->ctx));
		if (s->plugin_rate != ESDM_ES_EXT_PROTO_RATE_NONE)
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_ANY,
				"External ES provider: the source declares an entropy rate of %u bits per 256 bits\n",
				s->plugin_rate);
	}

	*server = s;
	return 0;

err:
	esdm_es_ext_server_free(s);
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_server_allow_uid(struct esdm_es_ext_server *server, uid_t uid)
{
	unsigned int i;

	if (!server || uid == (uid_t)-1)
		return -EINVAL;

	for (i = 0; i < server->allowed_uids_num; i++) {
		if (server->allowed_uids[i] == uid)
			return 0;
	}
	if (server->allowed_uids_num >= ESDM_ES_EXT_MAX_CLIENT_UIDS)
		return -ENOSPC;

	server->allowed_uids[server->allowed_uids_num++] = uid;
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_set_name(struct esdm_es_ext_server *server,
				const char *name)
{
	if (!server || (name && !esdm_es_ext_name_or_null(name)))
		return -EINVAL;

	if (name)
		snprintf(server->name, sizeof(server->name), "%s", name);
	else
		esdm_es_ext_server_plugin_name(server);
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_set_entropy_rate(struct esdm_es_ext_server *server,
					uint32_t rate)
{
	if (!server || (rate > ESDM_ES_EXT_ENTROPY_RATE_MAX &&
			rate != ESDM_ES_EXT_PROTO_RATE_NONE))
		return -EINVAL;

	server->rate = rate;
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_run(struct esdm_es_ext_server *server)
{
	struct pollfd pfd[ESDM_ES_EXT_MAX_CLIENTS + 2];
	unsigned int i;
	char c;

	if (!server)
		return -EINVAL;

	pfd[0] =
		(struct pollfd){ .fd = server->stop_pipe[0], .events = POLLIN };
	pfd[1] = (struct pollfd){ .fd = server->listen_fd, .events = POLLIN };
	for (;;) {
		for (i = 0; i < ESDM_ES_EXT_MAX_CLIENTS; i++)
			pfd[i + 2] = (struct pollfd){ .fd = server->clients[i],
						      .events = POLLIN };

		if (poll(pfd, ESDM_ES_EXT_MAX_CLIENTS + 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		if (pfd[0].revents)
			break;

		for (i = 0; i < ESDM_ES_EXT_MAX_CLIENTS; i++) {
			if (server->clients[i] < 0 || !pfd[i + 2].revents)
				continue;
			if (pfd[i + 2].revents & POLLIN)
				esdm_es_ext_server_serve(server, i);
			else
				esdm_es_ext_server_close(server, i);
		}

		/* After the clients, so a new one is not served in this round */
		if (pfd[1].revents & POLLIN)
			esdm_es_ext_server_accept(server);
	}

	/* Drain the stop request, so that the server can be run again */
	while (read(server->stop_pipe[0], &c, 1) == 1)
		;

	return 0;
}

DSO_PUBLIC
void esdm_es_ext_server_stop(struct esdm_es_ext_server *server)
{
	int errsv = errno;
	ssize_t __unused ret;

	if (!server)
		return;

	/* async-signal-safe: one write(2) to a non-blocking pipe */
	ret = write(server->stop_pipe[1], "", 1);
	errno = errsv;
}

DSO_PUBLIC
void esdm_es_ext_server_free(struct esdm_es_ext_server *server)
{
	struct stat sb;
	unsigned int i;

	if (!server)
		return;

	for (i = 0; i < ESDM_ES_EXT_MAX_CLIENTS; i++)
		esdm_es_ext_server_close(server, i);

	if (server->listen_fd >= 0) {
		close(server->listen_fd);

		/* Only the socket created here, not one another instance made */
		if (server->dir_fd >= 0 &&
		    !fstatat(server->dir_fd, server->file, &sb,
			     AT_SYMLINK_NOFOLLOW) &&
		    sb.st_dev == server->dev && sb.st_ino == server->ino)
			unlinkat(server->dir_fd, server->file, 0);
	}

	if (server->initialized && server->plugin->fini)
		server->plugin->fini(server->ctx);

	if (server->stop_pipe[0] >= 0)
		close(server->stop_pipe[0]);
	if (server->stop_pipe[1] >= 0)
		close(server->stop_pipe[1]);

	if (server->dir_fd >= 0)
		close(server->dir_fd);
	free(server->file);
	free(server);
}
