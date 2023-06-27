/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "logger.h"
#include "linux_support.h"

int linux_isolate_namespace_prefork(void)
{
	// TODO: this currently prevents a successful test run
#if 0
	pid_t pid;
	int errsv;

	/*
	 * Unshare the PID namespace before first fork,
	 */
	if (unshare(CLONE_NEWPID) == -1) {
		errsv = errno;
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "Cannot create PID namespace: %s\n", strerror(errsv));
		return -errsv;
	}

	logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
	       "Successfully entered isolating PID namespace\n");

	pid = fork();
	if (pid < 0) {
		errsv = errno;
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "Cannot enter PID namespace: %s\n", strerror(errsv));
		return -errsv;
	} else if (pid > 0) {
		pthread_setname_np(pthread_self(), "ESDM PIDNS creat");

		/* Wait for the termination of the child */
		wait(NULL);
	}
#endif

	return 0;
}

int linux_isolate_namespace(void)
{
	/*
	 * Unshare from the following namespaces - the ESDM process cannot
	 * re-establish connection to those resources. Hence, the ESDM process
	 * is effectively jailed with respect to those resources.
	 *
	 * The ESDM server only needs shared IPC and Semaphores.
	 */
	if (unshare(CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWNET) == -1) {
		int errsv = errno;

		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "Cannot enter namespaces: %s\n", strerror(errsv));
		return -errsv;
	}

	logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
	       "Successfully entered isolating namespaces\n");

	return 0;
}
