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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#ifdef __GLIBC__
#include <malloc.h>
#endif

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_egd_server.h"
#include "esdm_rpc_server.h"
#include "esdm_logger.h"
#include "helper.h"
#include "linux_support.h"
#include "ret_checkers.h"
#include "systemd_support.h"
#include "threading_support.h"

/*
 * Per-thread stack size used in small-memory mode. The RPC worker threads only
 * execute shallow handler call chains, so 2 MiB is ample while drastically
 * cutting the address space reserved across the entire worker pool compared to
 * the (commonly 8 MiB) platform default.
 */
#define ESDM_SERVER_SMALL_MEM_STACKSIZE (2 * 1024 * 1024)

static unsigned int verbosity = 0;
static unsigned int foreground = 0;
/* "/run/esdm-rpc-server.pid" */
static char *pidfile = NULL;
static int pidfile_fd = -1;
static const char *username = NULL;
static const char *groupname = NULL;
static unsigned int memlock = 0;
static unsigned int small_memory = 0;
static unsigned int pid_namespace = 0;

/*******************************************************************
 * Forward Declarations
 *******************************************************************/
static void daemon_raise_sched_priority(void);

/*******************************************************************
 * General helper functions
 *******************************************************************/

/*
 * Room for what esdm_version() produces. A test mode build prefixes the line
 * with TESTMODE_STR, which is longer than the line itself - a buffer sized for
 * the production string silently truncates it, and what got cut off is the
 * version number the caller asked for.
 */
#define ESDM_SERVER_VERSION_BUFLEN 128

static void usage(void)
{
	char version[ESDM_SERVER_VERSION_BUFLEN];

	memset(version, 0, sizeof(version));
	esdm_version(version, sizeof(version));

	fprintf(stderr, "\nESDM RPC server\n\n");
	fprintf(stderr, "%s\n\n", version);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-h --help\tThis help information\n");
	fprintf(stderr, "\t   --version\tPrint version\n");
	fprintf(stderr,
		"\t-v --verbose\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr,
		"\t\t\tVerbose logging implies running in foreground\n");
	fprintf(stderr, "\t-p --pid\tWrite daemon PID to file\n");
	fprintf(stderr,
		"\t-u --username\tUnprivileged user name to switch to (default: \"nobody\")\n");
	fprintf(stderr,
		"\t-g --groupname\tSupplemental group name to switch to (default: none)\n");
	fprintf(stderr, "\t-f --foreground\tExecute in foreground\n");
	fprintf(stderr,
		"\t-i --force_irqes\tForce to enable IRQ ES where the ESDM\n");
	fprintf(stderr, "\t\t\t\tretries enabling it\n");
	fprintf(stderr,
		"\t-s --force_schedes\tForce to enable Sched ES where the ESDM\n");
	fprintf(stderr, "\t\t\t\tretries enabling it\n");
	fprintf(stderr,
		"\t   --jent_block_disable\tDisable Jitter RNG block collection\n");
	fprintf(stderr,
		"\t-S --syslog\tLog to syslog instead of stdout/stderr\n");
	fprintf(stderr,
		"\t-P --raise_sched_priority\tRaise scheduling priority/nice level\n");
	fprintf(stderr,
		"\t-m --memlock\tLock all memory from being swapped out and disable core dumps\n");
	fprintf(stderr,
		"\t-M --small_memory\tReduce memory consumption (1 MiB thread stacks, single DRNG node)\n");
	fprintf(stderr,
		"\t   --keep_ipc\tDo not remove the RPC sockets, status SHM segment and\n");
	fprintf(stderr,
		"\t\t\tsemaphores at shutdown (running CUSE clients survive a\n");
	fprintf(stderr, "\t\t\tserver restart)\n");
	fprintf(stderr,
		"\t   --pid_namespace\tFork the daemon into an isolating PID namespace;\n");
	fprintf(stderr,
		"\t\t\tthe starting process remains as supervisor\n");
	fprintf(stderr,
		"\t-e --egd_socket <PATH>\tAdditionally serve the EGD protocol on the\n");
	fprintf(stderr,
		"\t\t\tUnix domain socket PATH (disabled by default)\n");
	fprintf(stderr,
		"\t-E --egd_socket_pr <PATH>\tThe same, but serving the prediction\n");
	fprintf(stderr,
		"\t\t\tresistance generator - the EGD protocol cannot select it\n");
	fprintf(stderr, "\t\t\tper request, so it gets a socket of its own\n");
	exit(1);
}

static void parse_opts(int argc, char *argv[])
{
	int c = 0;
	char version[ESDM_SERVER_VERSION_BUFLEN];

	while (1) {
		int opt_index = 0;
		static struct option opts[] = {
			{ "verbose", 0, 0, 0 },
			{ "pid", 1, 0, 0 },
			{ "help", 0, 0, 0 },
			{ "version", 0, 0, 0 },
			{ "username", 0, 0, 0 },
			{ "foreground", 0, 0, 0 },
			{ "force_irqes", 0, 0, 0 },
			{ "force_schedes", 0, 0, 0 },
			{ "jent_block_disable", 0, 0, 0 },
			{ "syslog", 0, 0, 0 },
			{ "raise_sched_priority", 0, 0, 0 },
			{ "groupname", 1, 0, 0 },
			{ "memlock", 0, 0, 0 },
			{ "small_memory", 0, 0, 0 },
			{ "keep_ipc", 0, 0, 0 },
			{ "pid_namespace", 0, 0, 0 },
			{ "egd_socket", 1, 0, 0 },
			{ "egd_socket_pr", 1, 0, 0 },
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "hvp:u:fisSPg:mMe:E:", opts,
				&opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* verbose */
				verbosity++;
				break;
			case 1:
				/* pid */
				pidfile = strdup(optarg);
				if (!pidfile) {
					fprintf(stderr,
						"Cannot allocate memory for PID file path\n");
					exit(1);
				}
				break;
			case 2:
				/* help */
				usage();
				break;
			case 3:
				/* version */
				esdm_version(version, sizeof(version));
				fprintf(stderr, "%s\n", version);
				exit(0);
				break;
			case 4:
				/* username */
				username = optarg;
				break;
			case 5:
				/* foreground */
				foreground = 1;
				break;

			case 6:
				/* force_irqes */
				esdm_config_es_irq_retry_set(1);
				break;
			case 7:
				/* force_schedes */
				esdm_config_es_sched_retry_set(1);
				break;

			case 8:
				/* jent_block_disable */
				esdm_config_es_jent_async_enabled_set(0);
				break;

			case 9:
				/* syslog */
				esdm_logger_enable_syslog("esdm-server");
				break;

			case 10:
				/* raise_sched_priority */
				daemon_raise_sched_priority();
				break;
			case 11:
				/* groupname */
				groupname = optarg;
				break;
			case 12:
				/* memlock */
				memlock = 1;
				break;
			case 13:
				/* small_memory */
				small_memory = 1;
				break;
			case 14:
				/* keep_ipc */
				esdm_config_ipc_cleanup_set(0);
				break;
			case 15:
				/* pid_namespace */
				pid_namespace = 1;
				break;
			case 16:
				/* egd_socket */
				if (esdm_egd_server_enable(optarg))
					exit(1);
				break;
			case 17:
				/* egd_socket_pr */
				if (esdm_egd_server_enable_pr(optarg))
					exit(1);
				break;

			default:
				usage();
			}
			break;
		case 'v':
			verbosity++;
			break;
		case 'p':
			pidfile = strdup(optarg);
			if (!pidfile) {
				fprintf(stderr,
					"Cannot allocate memory for PID file path\n");
				exit(1);
			}
			break;
		case 'h':
			usage();
			break;
		case 'u':
			username = optarg;
			break;
		case 'g':
			groupname = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'S':
			esdm_logger_enable_syslog("esdm-server");
			break;
		case 'P':
			/* raise_sched_priority */
			daemon_raise_sched_priority();
			break;

		case 'i':
			/* force_irqes */
			esdm_config_es_irq_retry_set(1);
			break;
		case 's':
			/* force_schedes */
			esdm_config_es_sched_retry_set(1);
			break;
		case 'm':
			/* memlock */
			memlock = 1;
			break;
		case 'M':
			/* small_memory */
			small_memory = 1;
			break;
		case 'e':
			/* egd_socket */
			if (esdm_egd_server_enable(optarg))
				exit(1);
			break;
		case 'E':
			/* egd_socket_pr */
			if (esdm_egd_server_enable_pr(optarg))
				exit(1);
			break;

		default:
			usage();
		}
	}
}

/*******************************************************************
 * Daemon functions
 *******************************************************************/

static int daemon_init(void)
{
	int ret;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER, "Starting ESDM server\n");
	CKINT(esdm_rpc_server_init(username, groupname));

out:
	return ret;
}

static void daemon_release(void)
{
	esdm_rpc_server_fini();
	esdm_fini();
}

static void daemon_raise_sched_priority(void)
{
	/* set nice priority */
	if (setpriority(PRIO_PROCESS, 0, -15) == -1) {
		esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
			    "Raising scheduling priority failed!\n");
	}
}

static void dealloc(void)
{
	if (pidfile_fd != -1) {
		close(pidfile_fd);
		pidfile_fd = -1;
		if (pidfile != NULL) {
			unlink(pidfile);
			free(pidfile);
			pidfile = NULL;
		}
	}

	daemon_release();
}

/*
 * Signal handler: trigger server shutdown.
 *
 * Only perform async-signal-safe operations here.
 * esdm_rpc_server_signal_exit_safe() only sets an atomic flag (a barrier +
 * store), which is async-signal-safe. It deliberately does NOT broadcast a
 * condvar (pthread_cond_broadcast is not async-signal-safe); blocked waiters
 * observe the flag via thread_wait_event()'s bounded re-poll. The full cleanup
 * (thread join, free) happens in esdm_rpc_server_fini() after the main loop
 * exits.
 */
static void sig_term(int sig)
{
	(void)sig;
	esdm_rpc_server_signal_exit_safe();
}

static void install_term(void)
{
	struct sigaction sa;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		    "Install termination signal handler\n");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigemptyset(&sa.sa_mask);
	/* No SA_RESTART: let blocking calls return EINTR so we can exit */
	sa.sa_flags = 0;

	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static void create_pid_file(const char *pid_file)
{
	char pid_str[12] = { 0 }; /* max. integer length + '\n' + null */

	/*
	 * Open or create pid file, then lock it. If the lock fails,
	 * another instance is running. If the file is stale (left
	 * from a crash), the lock will succeed and we can reuse it.
	 */
	/*
	 * O_NOFOLLOW: do not follow a symlink planted at pid_file (the daemon
	 * runs as root and would otherwise ftruncate()/overwrite the target).
	 * O_CLOEXEC: do not leak the descriptor across the exec of helpers.
	 */
	pidfile_fd = open(pid_file, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
			  S_IRUSR | S_IWUSR);
	if (pidfile_fd == -1) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot open pid file\n");
		exit(1);
	}

	if (lockf(pidfile_fd, F_TLOCK, 0) == -1) {
		if (errno == EAGAIN || errno == EACCES) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SERVER,
				"PID file already locked, another instance running\n");
			exit(1);
		} else {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "Cannot lock pid file\n");
			exit(1);
		}
	}

	if (ftruncate(pidfile_fd, 0) == -1) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot truncate pid file\n");
		exit(1);
	}

	/* write our pid to the pid file */
	snprintf(pid_str, sizeof(pid_str), "%i\n", getpid());
	if (write(pidfile_fd, pid_str, strlen(pid_str)) !=
	    (ssize_t)strlen(pid_str)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot write to pid file\n");
		exit(1);
	}
}

static void daemonize(void)
{
	pid_t pid;

	/* forbid daemonization with socket activation */
	if (systemd_listen_fds() > 0) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SERVER,
			"Do not use systemd socket activation and daemonization together.\n"
			"Please run esdm-server in foreground mode.\n");
		exit(1);
	}

	/* already a daemon */
	if (getppid() == 1)
		return;

	pid = fork();
	if (pid < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot fork to daemonize\n");
		exit(1);
	}

	/*
	 * The parent process exits -- nothing has been allocated, nothing
	 * needs to be freed.
	 */
	if (pid > 0)
		exit(0);

	/* we are the child now */

	/* new SID for the child process */
	if (setsid() < 0)
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot obtain new SID for child\n");

	/*
	 * Change the current working directory.  This prevents the current
	 * directory from being locked; hence not being able to remove it.
	 */
	if ((chdir("/")) < 0)
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot change directory\n");

	/* Redirect standard files to /dev/null */
	{
		int devnull = open("/dev/null", O_RDWR);

		if (devnull < 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "Cannot open /dev/null: %s\n",
				    strerror(errno));
		} else {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				close(devnull);
		}
	}
}

int main(int argc, char *argv[])
{
	ssize_t ret;

	may_enable_memory_debugging();

	parse_opts(argc, argv);

	if (geteuid()) {
		esdm_logger_inc_verbosity();
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Program must start as root!\n");
		return 1;
	}

	esdm_logger_set_verbosity(verbosity);

	/*
	 * Evaluate the socket activation environment while we still are the
	 * process systemd started and no thread exists yet. Everything after
	 * this point - daemonize(), the PID namespace prefork, the socket setup
	 * and the shutdown cleanup - uses the latched result, so all of them
	 * agree on whether the RPC sockets belong to systemd.
	 */
	systemd_listen_fds_init();

	if (verbosity == 0 && !foreground)
		daemonize();

	if (small_memory) {
		/*
		 * Shrink the per-thread stack size. This must happen before the
		 * thread pool is initialized in daemon_init() so the reduced
		 * size is applied to every worker thread that gets spawned.
		 */
		thread_set_default_stacksize(ESDM_SERVER_SMALL_MEM_STACKSIZE);

		/*
		 * Collapse the per-CPU DRNG instances down to a single node.
		 * Each node carries its own DRNG state and buffers, so on hosts
		 * with many CPUs this is the largest single memory reduction.
		 */
		esdm_config_max_nodes_set(1);

		/*
		 * Disable the asynchronous Jitter RNG block collection, which
		 * otherwise keeps pre-filled entropy buffers resident.
		 */
		esdm_config_es_jent_async_enabled_set(0);

#ifdef __GLIBC__
		/*
		 * Tune the glibc allocator for a small footprint:
		 *  - cap the number of malloc arenas at one: glibc otherwise
		 *    creates up to 8 arenas per CPU for multi-threaded
		 *    programs, each able to grow to tens of MiB;
		 *  - drop the top pad to zero;
		 *  - use a low trim threshold so the heap top is returned to the
		 *    kernel promptly instead of being retained by the process;
		 *  - use a low (and, by being set explicitly, fixed) mmap
		 *    threshold so larger allocations are served via mmap and
		 *    handed straight back to the kernel on free rather than
		 *    growing the retained heap.
		 */
		if (!mallopt(M_ARENA_MAX, 1) || !mallopt(M_TOP_PAD, 0) ||
		    !mallopt(M_TRIM_THRESHOLD, 64 * 1024) ||
		    !mallopt(M_MMAP_THRESHOLD, 64 * 1024))
			esdm_logger(
				LOGGER_WARN, LOGGER_C_SERVER,
				"Cannot tune glibc allocator for small memory mode\n");
#endif
	}

	if (pidfile && strlen(pidfile))
		create_pid_file(pidfile);

	install_term();

	/*
	 * Fork into an isolating PID namespace (opt-in via --pid_namespace):
	 * this process becomes a pure supervisor that forwards daemon control
	 * signals and mirrors the exit status, the child continues below as
	 * the actual daemon.
	 *
	 * The ordering around this call is deliberate:
	 * - create_pid_file() must run before it so the PID file names the
	 *   supervisor, which is the process external parties must signal;
	 * - install_term() must run before it because a PID namespace init
	 *   only receives a signal from an ancestor namespace for which it
	 *   has a handler installed, so the daemon must inherit the handlers;
	 * - the memlock setup must run after it (in the child) because
	 *   mlockall() is not inherited across fork().
	 *
	 * The supervisor performs the IPC cleanup after the daemon terminated:
	 * the daemon permanently drops its privileges and can no longer remove
	 * the root-owned sockets, SHM segment and semaphores itself.
	 */
	if (pid_namespace)
		CKINT(linux_isolate_namespace_prefork(
			esdm_rpc_server_cleanup));

	/*
	 * The IPC cleanup at shutdown can only succeed in a process that
	 * retained its privileges: the daemon permanently drops them, so its
	 * in-process attempt merely logs EPERM noise. Disable the in-process
	 * cleanup - in PID namespace mode the privileged supervisor (forked
	 * off above, before this override) performs the cleanup after the
	 * daemon terminated. A --keep_ipc request is unaffected as it turns
	 * the cleanup off before the supervisor is forked.
	 */
	esdm_config_ipc_cleanup_set(0);

	if (memlock) {
		/*
		 * its hard to set a sane limit here, as we have a
		 * variable amount of memory in jitterentropy entropy source
		 * and a variable amount of worker threads
		 */
		struct rlimit rl = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY,
		};
		if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "Cannot raise memlock limit\n");
			exit(-1);
		}
		/*
		 * Lock pages only once they are faulted in instead of
		 * pre-faulting and locking every reserved-but-untouched page.
		 * Without this, MCL_FUTURE forces each newly mapped region fully
		 * resident at map time - most notably the whole of every thread
		 * stack and the glibc heap reservation - which dominates the
		 * locked resident set. Any page that ever holds data is faulted
		 * and therefore still locked, so no secret can reach swap; only
		 * the untouched reservations stop being paid for.
		 */
		if (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "Cannot use mlockall\n");
			exit(-1);
		}

		/*
		 * Locking memory keeps the secrets ESDM handles out of swap;
		 * a core dump would defeat that by writing the whole address
		 * space (including the locked pages) to disk. Mark the process
		 * non-dumpable so the kernel refuses to generate a core dump
		 * for it at all - this also covers core_pattern pipe handlers
		 * (e.g. systemd-coredump), which a mere RLIMIT_CORE of 0 does
		 * not reliably suppress.
		 */
		if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "Cannot disable core dumps\n");
			exit(-1);
		}
	}

	CKINT(daemon_init());

	systemd_notify_status("Waiting for subprocesses to terminate");
	systemd_notify_stopping();

out:
	/* dealloc() performs the daemon_release() teardown itself. */
	dealloc();

	if (memlock) {
		munlockall();
	}

	return (int)ret;
}
