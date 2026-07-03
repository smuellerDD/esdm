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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "linux_support.h"
#include "memset_secure.h"

/*
 * PID of the namespace init child the supervisor waits for. Written once
 * before the forwarding signal handlers are installed, read-only afterwards.
 */
static volatile pid_t linux_pidns_child;

static void linux_pidns_forward_signal(int sig)
{
	pid_t child = linux_pidns_child;

	if (child > 0)
		kill(child, sig);
}

int linux_isolate_namespace_prefork(void (*supervisor_exit_cb)(void))
{
	/*
	 * Signals the supervisor relays to the daemon: the termination signals
	 * handled by the server and CUSE frontends plus SIGUSR1/SIGUSR2 used
	 * by esdm-server-signal-helper for suspend/resume.
	 */
	static const int fwd_signals[] = { SIGHUP,  SIGINT,  SIGQUIT,
					   SIGTERM, SIGUSR1, SIGUSR2 };
	struct sigaction sa;
	unsigned int i;
	pid_t pid;
	int errsv, status;

	/*
	 * Unshare the PID namespace before the first fork and before any
	 * thread exists: the kernel rejects unshare(CLONE_NEWPID) in a
	 * multi-threaded process and rejects thread creation in a process
	 * whose PID namespace for children differs from its own. Hence this
	 * must run before thread_init() and only the child below may create
	 * threads afterwards.
	 */
	if (unshare(CLONE_NEWPID) == -1) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot create PID namespace: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "Successfully entered isolating PID namespace\n");

	pid = fork();
	if (pid < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot fork into PID namespace: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	if (pid == 0) {
		/*
		 * Child: PID 1 of the new namespace, continues as the actual
		 * daemon. Tie its lifetime to the supervisor so a SIGKILLed
		 * supervisor does not leak an unreachable daemon. Best
		 * effort only: the kernel clears the parent-death signal
		 * when the daemon later drops privileges.
		 */
		if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
			esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
				    "Cannot set parent-death signal: %s\n",
				    strerror(errno));
		return 0;
	}

	/*
	 * Parent: act as supervisor only and never return to the caller.
	 * External parties (systemd via PIDFile=, esdm-server-signal-helper,
	 * test harnesses) address the daemon by this PID, so relay the
	 * daemon control signals to the namespace init and mirror its exit
	 * status. A signal is only delivered to a PID namespace init from an
	 * ancestor namespace if the init installed a handler for it, which
	 * the daemon does for all signals forwarded here.
	 */
	linux_pidns_child = pid;

	/* Name must fit the 15 character kernel limit on thread names */
	pthread_setname_np(pthread_self(), "ESDM supervisor");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = linux_pidns_forward_signal;
	sigemptyset(&sa.sa_mask);
	/* SA_RESTART: resume the waitpid() below after forwarding */
	sa.sa_flags = SA_RESTART;
	for (i = 0; i < sizeof(fwd_signals) / sizeof(fwd_signals[0]); i++)
		sigaction(fwd_signals[i], &sa, NULL);

	for (;;) {
		if (waitpid(pid, &status, 0) >= 0)
			break;
		if (errno != EINTR) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "Cannot wait for PID namespace init: %s\n",
				    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * The daemon is gone - let the caller perform teardown work that
	 * needs the supervisor's retained privileges (e.g. removing
	 * root-owned IPC resources after the daemon dropped privileges).
	 */
	if (supervisor_exit_cb)
		supervisor_exit_cb();

	if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);

		/*
		 * Die by the same signal so the wait status observed by our
		 * own parent (e.g. systemd Restart=on-failure) matches the
		 * daemon's fate.
		 */
		signal(sig, SIG_DFL);
		raise(sig);
		/* Reached only if the signal did not terminate us */
		exit(128 + sig);
	}

	exit(WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE);
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

		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot enter namespaces: %s\n", strerror(errsv));
		return -errsv;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "Successfully entered isolating namespaces\n");

	return 0;
}

int linux_personalization_string(char **ptr, size_t *length)
{
	FILE *f = fopen("/sys/class/dmi/id/product_uuid", "r");
	char buf[128] = { 0 };
	int ret;

	assert(*ptr == NULL);
	assert(*length == 0);

	if (!f) {
		int errsv = errno;

		esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
			    "Unable to open product_uuid file: %s\n",
			    strerror(errsv));
		ret = -errsv;
		goto out;
	}

	if (!fgets(buf, sizeof(buf), f)) {
		int errsv = errno;

		esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
			    "Unable to read product_uuid file: %s\n",
			    strerror(errsv));
		ret = -errsv;
		goto out_close;
	}

	/* Remove trailing newline */
	for (char *p = buf; *p; p++) {
		if (*p == '\n')
			*p = '\0';
	}

	*length = strnlen(buf, 128 - 1);
	*ptr = strndup(buf, *length);
	if (!*ptr) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Unable to duplicate string: %s\n",
			    strerror(errsv));
		ret = -errsv;
		goto out_close;
	}

	ret = 0;

out_close:
	fclose(f);
out:
	memset_secure(buf, 0, sizeof(buf));
	return ret;
}
