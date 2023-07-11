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
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "binhexbin.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_rpc_server.h"
#include "logger.h"
#include "ret_checkers.h"

static unsigned int verbosity = 0;
static unsigned int foreground = 0;
/* "/var/run/esdm-rpc-server.pid" */
static char *pidfile = NULL;
static int pidfile_fd = -1;
static const char *username = NULL;

/*******************************************************************
 * General helper functions
 *******************************************************************/

static void usage(void)
{
	char version[50];

	memset(version, 0, 50);
	esdm_version(version, sizeof(version));

	fprintf(stderr, "\nESDM RPC server\n\n");
	fprintf(stderr, "%s\n\n", version);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-h --help\tThis help information\n");
	fprintf(stderr, "\t   --version\tPrint version\n");
	fprintf(stderr, "\t-v --verbose\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr, "\t\t\tVerbose logging implies running in foreground\n");
	fprintf(stderr, "\t-p --pid\tWrite daemon PID to file\n");
	fprintf(stderr, "\t-u --username\tUnprivileged user name to switch to (default: \"nobody\")\n");
	fprintf(stderr, "\t-f --foreground\tExecute in foreground\n");
	fprintf(stderr, "\t-i --force_irqes\tForce to enable IRQ ES where the ESDM\n");
	fprintf(stderr, "\t\t\t\tretries enabling it\n");
	fprintf(stderr, "\t-s --force_schedes\tForce to enable Sched ES where the ESDM\n");
	fprintf(stderr, "\t\t\t\tretries enabling it\n");
	fprintf(stderr, "\t   --jent_block_disable\tDisable Jitter RNG block collection\n");
	exit(1);
}

static void parse_opts(int argc, char *argv[])
{
	int c = 0;
	char version[30];

	while (1) {
		int opt_index = 0;
		static struct option opts[] = {
			{"verbose", 0, 0, 0},
			{"pid", 1, 0, 0},
			{"help", 0, 0, 0},
			{"version", 0, 0, 0},
			{"username", 0, 0, 0},
			{"foreground", 0, 0, 0},
			{"force_irqes", 0, 0, 0},
			{"force_schedes", 0, 0, 0},
			{"jent_block_disable", 0, 0, 0},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "hvp:u:fis", opts, &opt_index);
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
				pidfile = optarg;
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
				esdm_config_es_jent_buffer_enabled_set(0);
				break;

			default:
				usage();
			}
			break;
		case 'v':
			verbosity++;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'u':
			username = optarg;
			break;
		case 'f':
			foreground = 1;
			break;

		case 'i':
			/* force_irqes */
			esdm_config_es_irq_retry_set(1);
			break;
		case 's':
			/* force_schedes */
			esdm_config_es_sched_retry_set(1);
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

	logger(LOGGER_VERBOSE, LOGGER_C_SERVER, "Starting ESDM server\n");
	CKINT(esdm_init());
	CKINT(esdm_rpc_server_init(username));

out:
	return ret;
}

static void daemon_release(void)
{
	esdm_rpc_server_fini();
	esdm_fini();
}

static void dealloc(void)
{
	if (pidfile_fd != -1) {
		close(pidfile_fd);
		pidfile_fd = -1;
		if (pidfile != NULL)
			unlink(pidfile);
	}

	daemon_release();
}

/* terminate the daemon cleanly */
static void sig_term(int sig)
{
	(void)sig;
	logger(LOGGER_DEBUG, LOGGER_C_SERVER, "Shutting down cleanly\n");

	/* Prevent the kernel from interfering with the shutdown */
	signal(SIGALRM, SIG_IGN);

	/* If we got another termination signal, just get killed */
	signal(SIGHUP, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	dealloc();
	exit(0);
}

static void install_term(void)
{
	logger(LOGGER_DEBUG, LOGGER_C_SERVER, "Install termination signal handler\n");
	signal(SIGHUP, sig_term);
	signal(SIGINT, sig_term);
	signal(SIGQUIT, sig_term);
	signal(SIGTERM, sig_term);
}

static void create_pid_file(const char *pid_file)
{
	char pid_str[12];	/* max. integer length + '\n' + null */

	/* Ensure only one copy */
	pidfile_fd = open(pid_file, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
	if (pidfile_fd == -1)
		logger(LOGGER_ERR, LOGGER_C_SERVER, "Cannot open pid file\n");

	if (lockf(pidfile_fd, F_TLOCK, 0) == -1) {
		if (errno == EAGAIN || errno == EACCES) {
			logger(LOGGER_ERR, LOGGER_C_SERVER,
			       "PID file already locked\n");
			exit(1);
		} else
			logger(LOGGER_ERR, LOGGER_C_SERVER,
			       "Cannot lock pid file\n");
	}

	if (ftruncate(pidfile_fd, 0) == -1) {
		logger(LOGGER_ERR, LOGGER_C_SERVER, "Cannot truncate pid file\n");
		exit(1);
	}

	/* write our pid to the pid file */
	snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
	if (write(pidfile_fd, pid_str, strlen(pid_str)) !=
	    (ssize_t)strlen(pid_str)) {
		logger(LOGGER_ERR, LOGGER_C_SERVER, "Cannot write to pid file\n");
		exit(1);
	}
}

static void daemonize(void)
{
	pid_t pid;

	/* already a daemon */
	if (getppid() == 1)
	       return;

	pid = fork();
	if (pid < 0) {
		logger(LOGGER_ERR, LOGGER_C_SERVER, "Cannot fork to daemonize\n");
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
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "Cannot obtain new SID for child\n");

	/* Change the current working directory.  This prevents the current
	 * directory from being locked; hence not being able to remove it. */
	if ((chdir("/")) < 0)
		logger(LOGGER_ERR, LOGGER_C_SERVER, "Cannot change directory\n");

	if (pidfile && strlen(pidfile))
		create_pid_file(pidfile);

	/* Redirect standard files to /dev/null */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
	freopen( "/dev/null", "r", stdin);
	freopen( "/dev/null", "w", stdout);
	freopen( "/dev/null", "w", stderr);
#pragma GCC diagnostic pop
}

int main(int argc, char *argv[])
{
	ssize_t ret;

	parse_opts(argc, argv);

	if (geteuid()) {
		logger_inc_verbosity();
		logger(LOGGER_ERR, LOGGER_C_SERVER,
		       "Program must start as root!\n");
		return 1;
	}

	logger_set_verbosity(verbosity);

	if (verbosity == 0 && !foreground)
		daemonize();

	install_term();

	CKINT(daemon_init());

out:
	daemon_release();
	dealloc();
	return (int)ret;
}
