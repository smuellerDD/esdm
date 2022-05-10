/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <semaphore.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "atomic.h"
#include "config.h"
#include "esdm_config.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "logger.h"
#include "privileges.h"
#include "protobuf-c-rpc/protobuf-c-rpc.h"
#include "ret_checkers.h"
#include "threading_support.h"

#ifdef ESDM_RPC_SERVER

static DECLARE_WAIT_QUEUE(esdm_rpc_thread_init_wait);
static ProtobufC_RPC_Server *esdm_rpc_thread_server[THREADING_MAX_THREADS + 1];
static ProtobufCRPCDispatch *esdm_rpc_thread_dispatch[THREADING_MAX_THREADS + 1];
static atomic_t esdm_rpc_thread_online = ATOMIC_INIT(0);

static pid_t server_pid = -1;

static atomic_t server_exit = ATOMIC_INIT(0);

static void *esdm_system_alloc(void *allocator_data, size_t size)
{
	(void)allocator_data;
	return malloc(size);
}

static void esdm_system_free(void *allocator_data, void *data)
{
	(void)allocator_data;
	free(data);
}

static ProtobufCAllocator esdm_rpc_allocator = {
	.alloc = &esdm_system_alloc,
	.free = &esdm_system_free,
	.allocator_data = NULL,
};

struct esdm_rpc_server_thread_args {
	uint32_t id;
};

/* Initialize one thread handling an unprivileged interface instance */
static int esdm_rpc_server_thread(void *args)
{
	ProtobufC_RPC_Server *server = NULL;
	ProtobufCRPCDispatch *dispatch = NULL;
	ProtobufCService *unpriv_service =
				(ProtobufCService *)&unpriv_access_service;
	struct esdm_rpc_server_thread_args *thread_args = args;
	uint32_t id;
	int ptr, ret = 0;
	char socketname[FILENAME_MAX];

	if (!args)
		return -EFAULT;
	id = thread_args->id;
	free(thread_args);

	thread_set_name(rpc_server, id);

	/* Name of the Unix domain sockets */
	if (id) {
		snprintf(socketname, sizeof(socketname), "%s%u.socket",
			 ESDM_RPC_UNPRIV_SOCKET, id);
	} else {
		snprintf(socketname, sizeof(socketname), "%s.socket",
			 ESDM_RPC_UNPRIV_SOCKET);
	}

	dispatch = protobuf_c_rpc_dispatch_new(&esdm_rpc_allocator);
	CKNULL_LOG(dispatch, -EFAULT, "Dispatcher for thread %u failed\n", id);

	server = protobuf_c_rpc_server_new(PROTOBUF_C_RPC_ADDRESS_LOCAL,
					   socketname, unpriv_service,
					   dispatch);
	CKNULL_LOG(server, -EFAULT, "Server for thread %u failed\n", id);

	/* Make unprivileged socket available for all users */
	if (chmod(socketname,
		  S_IRUSR | S_IWUSR |
		  S_IRGRP | S_IWGRP |
		  S_IROTH | S_IWOTH) == -1) {
		ret = -errno;

		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Failed to set permissions for Unix domain socket %s: %s\n",
		       socketname, strerror(errno));
		goto out;
	}

	ptr = atomic_inc(&esdm_rpc_thread_online);
	esdm_rpc_thread_dispatch[ptr] = dispatch;
	esdm_rpc_thread_server[ptr] = server;

	/* Wait for the mother to drop the privileges. */
	thread_wait_event(&esdm_rpc_thread_init_wait, getuid());
	logger(LOGGER_DEBUG, LOGGER_C_RPC,
	       "Unprivileged server thread for %s available\n", socketname);

	while (!atomic_read(&server_exit))
		protobuf_c_rpc_dispatch_run(dispatch);

	return 0;

out:
	if (server) {
		protobuf_c_rpc_server_destroy(server, 0);
		server = NULL;
	}
	if (dispatch) {
		protobuf_c_rpc_dispatch_free(dispatch);
		dispatch = NULL;
	}

	return ret;
}

static int esdm_rpc_unpriv_server_init_threads(void)
{
	struct esdm_rpc_server_thread_args *thread_args;
	uint32_t i, nodes = esdm_config_online_nodes();

	/* Create as many threads as we have defined nodes. */
	for (i = 0; i < nodes; i++) {
		thread_args = malloc(sizeof(*thread_args));
		if (!thread_args)
			continue;
		thread_args->id = i;
		if (thread_start(esdm_rpc_server_thread, thread_args, 0,
				 NULL)) {
			logger(LOGGER_ERR, LOGGER_C_RPC,
			       "Starting server thread %u failed\n", i);
		}
	}

	return 0;
}

static int esdm_rpc_server_interfaces_init(const char *username)
{
	ProtobufC_RPC_Server *server = NULL;
	ProtobufCRPCDispatch *dispatch = NULL;
	ProtobufCService *priv_service =
				(ProtobufCService *)&priv_access_service;
	char socketname[FILENAME_MAX];
	int ret;

	/* Create server handler for privileged interface in main thread */
	dispatch = protobuf_c_rpc_dispatch_new(&esdm_rpc_allocator);
	if (!dispatch) {
		logger(LOGGER_ERR, LOGGER_C_RPC,
			"Dispatcher for priv thread failed\n");
		return -EFAULT;
	}

	snprintf(socketname, sizeof(socketname), "%s.socket",
		 ESDM_RPC_PRIV_SOCKET);
	server = protobuf_c_rpc_server_new(PROTOBUF_C_RPC_ADDRESS_LOCAL,
					   socketname, priv_service,
					   dispatch);
	if (!server) {
		protobuf_c_rpc_dispatch_free(dispatch);
		ret = -EFAULT;
		goto out;
	}

	esdm_rpc_thread_dispatch[0] = dispatch;
	esdm_rpc_thread_server[0] = server;

	/* Make privileged socket available for root only */
	if (chmod(socketname, S_IRUSR | S_IWUSR) == -1) {
		int errsv = errno;

		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Failed to set permissions for Unix domain socket %s: %s\n",
		       ESDM_RPC_PRIV_SOCKET, strerror(errsv));
		ret = -errsv;
		goto out;
	}

	/* Spawn all threads handling the unprivileged interface */
	CKINT(esdm_rpc_unpriv_server_init_threads());

	/* Permanently drop all privileges */
	CKINT(drop_privileges_permanent(username ? username : "nobody"));

	/* Notify all unpriv handler threads that they can become active */
	thread_wake_all(&esdm_rpc_thread_init_wait);
	logger(LOGGER_DEBUG, LOGGER_C_RPC,
	       "Privileged server thread for %s available\n", socketname);

	/* Server handing privileged interface in current thread */
	while (!atomic_read(&server_exit))
		protobuf_c_rpc_dispatch_run(dispatch);

	return 0;

out:
	if (server) {
		protobuf_c_rpc_server_destroy(server, 0);
		server = NULL;
	}
	if (dispatch) {
		protobuf_c_rpc_dispatch_free(dispatch);
		dispatch = NULL;
	}

	return ret;
}

static void esdm_rpc_server_cleanup(void)
{
	struct stat statbuf;
	char socketname[FILENAME_MAX];
	int esdm_shmid;
	unsigned int i;
	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);

	/* Clean up all unprivileged Unix domain sockets */
	for (i = 0; i < esdm_config_online_nodes(); i++) {
		/* Name of the Unix domain sockets */
		if (i) {
			snprintf(socketname, sizeof(socketname), "%s%u.socket",
				 ESDM_RPC_UNPRIV_SOCKET, i);
		} else {
			snprintf(socketname, sizeof(socketname), "%s.socket",
				 ESDM_RPC_UNPRIV_SOCKET);
		}

		/* Does the path exist? */
		if (stat(socketname, &statbuf) == -1 && errno == ENOENT)
			break;

		if (unlink(socketname) < 0) {
			logger(LOGGER_ERR, LOGGER_C_SERVER,
			       "ESDM Unix domain socket %s cannot be deleted: %s\n",
			       socketname, strerror(errno));
		} else {
			logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			       "ESDM Unix domain socket %s deleted\n",
			       socketname);
		}
	}

	/* Clean up the privileged Unix domain socket */
	snprintf(socketname, sizeof(socketname), "%s.socket",
		 ESDM_RPC_PRIV_SOCKET);
	if (unlink(socketname) < 0) {
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "ESDM Unix domain socket %s cannot be deleted: %s\n",
		       socketname, strerror(errno));
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		       "ESDM Unix domain socket %s deleted\n", socketname);
	}

	/* Clean up the status shared memory segment */
	esdm_shmid = shmget(key, sizeof(struct esdm_shm_status),
			    S_IRUSR | S_IRGRP | S_IROTH);
	if (esdm_shmid < 0) {
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "ESDM shared memory segment attachment for deletion failed: %s\n",
		       strerror(errno));
	} else {
		if (shmctl(esdm_shmid, IPC_RMID, NULL) < 0) {
			logger(LOGGER_ERR, LOGGER_C_SERVER,
			       "ESDM shared memory segment cannot be deleted: %s\n",
			       strerror(errno));
		} else {
			logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			       "ESDM shared memory segment deleted\n");
		}
	}

	/* Clean up the status semaphore */
	if (sem_unlink(ESDM_SEM_NAME)) {
		logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		       "Cannot unlink semaphore: %s\n", strerror(errno));
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_SERVER, "ESDM semaphore deleted\n");
	}
}

static void esdm_rpc_server_cleanup_signals(void (*sighandler)(int))
{
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT, sighandler);
	signal(SIGTERM, sighandler);
}

static void esdm_rpc_server_cleanup_term(int sig)
{
	(void)sig;

	esdm_rpc_server_cleanup_signals(SIG_DFL);

	if (server_pid > 0)
		kill(server_pid, sig);
}

int esdm_rpc_server_init(const char *username)
{
	pid_t pid;
	int ret = 0;

	pid = fork();
	if (pid < 0) {
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "Cannot fork interface process\n");
		exit(1);
	} else if (pid == 0) {
		/* Fork the server process */
		esdm_rpc_server_interfaces_init(username);
	} else {
		/*
		 * This is the cleanup process. It simply waits for the server
		 * to exit to clean up its resources. This is needed because
		 * the server creates resources as root, but then permanently
		 * drops its privileges. This means it cannot clean up after
		 * itself. The cleanup process has no interfaces other than
		 * waiting for the termination of the server process but has
		 * full privileges to be able to clean up the server resources.
		 */

		/*
		 * In case the cleanup process received a signal, relay it to
		 * the server, but do not process the signal itself.
		 */
		server_pid = pid;
		esdm_rpc_server_cleanup_signals(esdm_rpc_server_cleanup_term);

		/* Now wait for the server to finish. */
		waitpid(pid, NULL, 0);
		server_pid = -1;

		esdm_rpc_server_cleanup_signals(SIG_DFL);

		/* Clean up all resources */
		esdm_rpc_server_cleanup();
	}

	return ret;
}

void esdm_rpc_server_fini(void)
{
	int i, threads = atomic_read(&esdm_rpc_thread_online);

	atomic_set(&server_exit, 1);
	thread_wake_all(&esdm_rpc_thread_init_wait);

	/*
	 * Unfortunately there seems to be no other way to stop the servers
	 * which are usually waiting in a poll(2) system call of
	 * protobuf_c_rpc_dispatch_run.
	 */
	thread_release(true, false);

	/* Free the resources */
	for (i = 0; i <= threads; i++) {
		if (esdm_rpc_thread_server[i])
			protobuf_c_rpc_server_destroy(esdm_rpc_thread_server[i],
						      0);
		if (esdm_rpc_thread_dispatch[i])
			protobuf_c_rpc_dispatch_free(
						esdm_rpc_thread_dispatch[i]);
	}
}

#else /* ESDM_RPC_SERVER */

int esdm_ipc_server_init(void)
{
	return 0;
}

void esdm_ipc_server_fini(void) { }

#endif /* ESDM_RPC_SERVER */
