/*
 * Copyright (C) 2025 Markus Theil <theil.markus@gmail.com>
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

#define _GNU_SOURCE 1
#include "systemd_support.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd)
{
	if (!fd || *fd < 0)
		return;

	close(*fd);
	*fd = -1;
}

int systemd_notify(const char *message)
{
	union sockaddr_union {
		struct sockaddr sa;
		struct sockaddr_un sun;
	} socket_addr = {
		.sun.sun_family = AF_UNIX,
	};
	size_t path_length, message_length;
	_cleanup_(closep) int fd = -1;
	const char *socket_path;

	/* Verify the argument first */
	if (!message)
		return -EINVAL;

	message_length = strlen(message);
	if (message_length == 0)
		return -EINVAL;

	/* If the variable is not set, the protocol is a noop */
	socket_path = getenv("NOTIFY_SOCKET");
	if (!socket_path)
		return 0; /* Not set? Nothing to do */

	/* Only AF_UNIX is supported, with path or abstract sockets */
	if (socket_path[0] != '/' && socket_path[0] != '@')
		return -EAFNOSUPPORT;

	path_length = strlen(socket_path);
	/* Ensure there is room for NUL byte */
	if (path_length >= sizeof(socket_addr.sun.sun_path))
		return -E2BIG;

	memcpy(socket_addr.sun.sun_path, socket_path, path_length);

	/* Support for abstract socket */
	if (socket_addr.sun.sun_path[0] == '@')
		socket_addr.sun.sun_path[0] = 0;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (connect(fd, &socket_addr.sa,
		    (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
				path_length)) != 0)
		return -errno;

	ssize_t written = write(fd, message, message_length);
	if (written != (ssize_t)message_length)
		return written < 0 ? -errno : -EPROTO;

	return 1; /* Notified! */
}

int systemd_notify_ready(void)
{
	return systemd_notify("READY=1");
}

int systemd_notify_stopping(void)
{
	return systemd_notify("STOPPING=1");
}

int systemd_notify_mainpid(pid_t pid)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "MAINPID=%d", pid);

	return systemd_notify(buf);
}

int systemd_notify_access(char *mode)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "NOTIFYACCESS=%s", mode);

	return systemd_notify(buf);
}

int systemd_notify_status(char *msg)
{
	char buf[4096];
	snprintf(buf, sizeof(buf), "STATUS=%s", msg);

	return systemd_notify(buf);
}

int systemd_listen_pid(void)
{
	const char *listen_pid = getenv("LISTEN_PID");

	if (!listen_pid)
		return -1;

	return atoi(listen_pid);
}

int systemd_listen_fds(void)
{
	const char *listen_fds = getenv("LISTEN_FDS");

	if (!listen_fds)
		return -1;

	return atoi(listen_fds);
}

static void freep(char **p)
{
	if (!p || *p == NULL)
		return;

	free(*p);
	*p = NULL;
}

int systemd_listen_fd_for_name(const char *name)
{
	const char *listen_fd_names = getenv("LISTEN_FDNAMES");
	_cleanup_(freep) char *fd_names_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	int fd_offset = 0;
	int num_listen_fds = systemd_listen_fds();

	/* no env set?*/
	if (!listen_fd_names)
		return -1;

	/* no fds to handle here? */
	if (num_listen_fds <= 0)
		return -1;

	fd_names_copy = calloc(1, strlen(listen_fd_names) + 1);
	fd_names_copy = strcpy(fd_names_copy, listen_fd_names);

	/* without tokens present, strtok_r returns the whole string */
	token = strtok_r(fd_names_copy, ":", &saveptr);
	while (token != NULL) {
		if (strcmp(name, token) == 0 && fd_offset < num_listen_fds)
			return SYSTEMD_LISTEN_FDS_START + fd_offset;

		token = strtok_r(NULL, ":", &saveptr);

		/* break early on invalid inputs */
		if (fd_offset >= num_listen_fds)
			break;

		fd_offset++;
	}

	return -1;
}
