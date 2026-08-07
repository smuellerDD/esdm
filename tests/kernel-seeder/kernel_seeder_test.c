/*
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

/*
 * Test of the kernel entropy feeder (esdm-kernel-seeder).
 *
 * The feeder is a daemon, so it is exercised as one: the test spawns the real
 * binary and inspects what it does.
 *
 * Two levels of coverage, depending on the privileges available:
 *
 * 1. Command line contract - always run. All checks here use invocations that
 *    are guaranteed to terminate, so they work as root as well. Beyond the
 *    obvious exit codes this pins down the long option table: the option
 *    handler dispatches on the getopt_long index, so a new entry inserted in
 *    the middle of the table silently re-routes every following option. The
 *    interval option is the one that takes an argument, so a misrouted
 *    --force-pr would hand a NULL optarg to the integer conversion.
 *
 * 2. End-to-end feeding - requires root, skipped otherwise (exit 77), just
 *    like the CUSE tests. An ESDM server is started, the feeder is pointed at
 *    it, and the test waits for the feeder to report that it pulled random
 *    data over RPC and handed it to the kernel via RNDADDENTROPY. Finally the
 *    feeder must react to SIGTERM instead of sitting out its seeding interval,
 *    and report success while doing so - a signal-initiated shutdown is the
 *    ordinary way this daemon ends, and a failure exit code would make every
 *    "systemctl stop" mark the unit as failed.
 *
 * Every diagnostic checked here has to be reachable without any -v: the
 * failures they describe end the process, so a message the logger's default
 * threshold swallows is a message nobody ever sees.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Exit code meson interprets as "test skipped" */
#define EXIT_SKIP 77

/* Upper bound for the feeder to complete one seeding round */
#define SEEDER_SEED_TIMEOUT_MS 60000

/* Upper bound for the feeder to react to SIGTERM */
#define SEEDER_TERM_TIMEOUT_MS 15000

/* Upper bound for a one-shot invocation (--help and friends) to terminate */
#define SEEDER_CLI_TIMEOUT_MS 15000

static const char *seeder_bin;
static const char *server_bin;

static pid_t server_pid = 0;

static void seeder_sleep_ms(unsigned int msecs)
{
	struct timespec ts = { .tv_sec = msecs / 1000,
			       .tv_nsec = (long)(msecs % 1000) * 1000 * 1000 };

	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

/*
 * Spawn @path with @argv, redirecting both stdout and stderr into @logfile.
 * The ESDM logger writes to stderr, usage() to stdout, and the test wants to
 * search both.
 */
static pid_t seeder_spawn(const char *path, char *const argv[],
			  const char *logfile)
{
	pid_t pid = fork();

	if (pid < 0) {
		printf("Kernel seeder - fail: fork failed: %s\n",
		       strerror(errno));
		return -1;
	}

	if (pid == 0) {
		int fd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (fd < 0)
			_exit(EXIT_FAILURE);
		if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
			_exit(EXIT_FAILURE);
		close(fd);

		execv(path, argv);

		/* NOTREACHED on success */
		_exit(EXIT_FAILURE);
	}

	return pid;
}

/*
 * Wait for @pid, but no longer than @timeout_ms. Returns true if it
 * terminated, and then stores the wait status in @status.
 */
static bool seeder_wait(pid_t pid, unsigned int timeout_ms, int *status)
{
	unsigned int waited;

	for (waited = 0; waited < timeout_ms; waited += 20) {
		pid_t rc = waitpid(pid, status, WNOHANG);

		if (rc == pid)
			return true;
		if (rc < 0)
			return false;
		seeder_sleep_ms(20);
	}

	return false;
}

static void seeder_kill(pid_t pid)
{
	if (pid <= 0)
		return;

	kill(pid, SIGTERM);
	if (!seeder_wait(pid, SEEDER_TERM_TIMEOUT_MS, NULL)) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
}

/* Does @logfile currently contain @needle? */
static bool seeder_log_contains(const char *logfile, const char *needle)
{
	char buf[65536];
	ssize_t len;
	int fd = open(logfile, O_RDONLY);
	bool found;

	if (fd < 0)
		return false;

	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (len <= 0)
		return false;

	buf[len] = '\0';
	found = strstr(buf, needle) != NULL;

	return found;
}

static void seeder_dump_log(const char *logfile)
{
	char buf[4096];
	ssize_t len;
	int fd = open(logfile, O_RDONLY);

	if (fd < 0)
		return;

	printf("---- output of the kernel seeder ----\n");
	while ((len = read(fd, buf, sizeof(buf) - 1)) > 0) {
		buf[len] = '\0';
		printf("%s", buf);
	}
	printf("---- end of output ----\n");
	close(fd);
}

/* Wait until @needle shows up in @logfile, but no longer than @timeout_ms. */
static bool seeder_wait_for_log(const char *logfile, const char *needle,
				unsigned int timeout_ms)
{
	unsigned int waited;

	for (waited = 0; waited < timeout_ms; waited += 100) {
		if (seeder_log_contains(logfile, needle))
			return true;
		seeder_sleep_ms(100);
	}

	return seeder_log_contains(logfile, needle);
}

/*************************** Command line contract ***************************/

/*
 * Run the feeder with a set of arguments that must make it terminate with a
 * failure exit code, and - if @expect is not NULL - check its output for that
 * string.
 */
static int seeder_run_expect(const char *desc, char *const argv[],
			     const char *expect)
{
	char logfile[] = "/tmp/esdm-kernel-seeder-test-XXXXXX";
	pid_t pid;
	int status = 0;
	int ret = 0;
	int fd = mkstemp(logfile);

	if (fd < 0) {
		printf("Kernel seeder - fail: temporary file: %s\n",
		       strerror(errno));
		return 1;
	}
	close(fd);

	pid = seeder_spawn(seeder_bin, argv, logfile);
	if (pid < 0) {
		unlink(logfile);
		return 1;
	}

	if (!seeder_wait(pid, SEEDER_CLI_TIMEOUT_MS, &status)) {
		printf("Kernel seeder - fail: %s: did not terminate\n", desc);
		seeder_dump_log(logfile);
		seeder_kill(pid);
		unlink(logfile);
		return 1;
	}

	if (WIFSIGNALED(status)) {
		printf("Kernel seeder - fail: %s: terminated by signal %d\n",
		       desc, WTERMSIG(status));
		ret = 1;
	} else if (WEXITSTATUS(status) == 0) {
		printf("Kernel seeder - fail: %s: unexpected success exit code\n",
		       desc);
		ret = 1;
	}

	if (expect && !seeder_log_contains(logfile, expect)) {
		printf("Kernel seeder - fail: %s: output does not mention \"%s\"\n",
		       desc, expect);
		seeder_dump_log(logfile);
		ret = 1;
	}

	if (!ret)
		printf("Kernel seeder - pass: %s\n", desc);

	unlink(logfile);
	return ret;
}

static int seeder_test_cli(void)
{
	char bin[FILENAME_MAX];
	int ret = 0;

	snprintf(bin, sizeof(bin), "%s", seeder_bin);

	{
		char *argv[] = { bin, "-h", NULL };

		ret += seeder_run_expect("short help option", argv,
					 "esdm-kernel-seeder");
	}
	{
		char *argv[] = { bin, "--help", NULL };

		ret += seeder_run_expect("long help option", argv,
					 "esdm-kernel-seeder");
	}
	/*
	 * A garbage interval must be rejected instead of silently turning into
	 * some arbitrary reseeding period, and it must say so. The conversion
	 * runs inside the option loop, before any -v has been applied, so the
	 * diagnostic cannot go through the logger and be expected to appear.
	 */
	{
		char *argv[] = { bin, "-i", "not-a-number", NULL };

		ret += seeder_run_expect("short interval option rejects garbage",
					 argv, "conversion of interval failed");
	}
	{
		char *argv[] = { bin, "--interval", "not-a-number", NULL };

		ret += seeder_run_expect("long interval option rejects garbage",
					 argv, "conversion of interval failed");
	}
	{
		char *argv[] = { bin, "-i", "12x", NULL };

		ret += seeder_run_expect("interval option rejects trailing garbage",
					 argv, "conversion of interval failed");
	}

	/*
	 * The remaining long options carry no argument. Combined with --help
	 * they terminate regardless of privileges, and reaching the usage
	 * output at all proves they were not dispatched to the interval
	 * handler, which would have read a NULL optarg.
	 */
	{
		char *argv[] = { bin, "--force-pr", "--help", NULL };

		ret += seeder_run_expect("long force-pr option accepted", argv,
					 "esdm-kernel-seeder");
	}
	{
		char *argv[] = { bin, "--verbosity", "--help", NULL };

		ret += seeder_run_expect("long verbosity option accepted", argv,
					 "esdm-kernel-seeder");
	}
	{
		char *argv[] = { bin, "--syslog", "--help", NULL };

		ret += seeder_run_expect("long syslog option accepted", argv,
					 "esdm-kernel-seeder");
	}

	/*
	 * Inserting entropy into the kernel needs root, and the feeder has to
	 * say so rather than fail obscurely later on. Only checkable when the
	 * test itself is unprivileged - as root the feeder would start up and
	 * run forever.
	 */
	if (geteuid()) {
		/* No -v: the refusal has to be audible at the default level */
		char *argv[] = { bin, NULL };

		ret += seeder_run_expect("refuses to run unprivileged", argv,
					 "Program must start as root");
	} else {
		printf("Kernel seeder - info: running as root, unprivileged rejection not checked\n");
	}

	return ret;
}

/****************************** End-to-end feed ******************************/

static int seeder_start_server(void)
{
	char bin[FILENAME_MAX];
	char *argv[] = { bin, "-v", "-v", "-v", NULL };

	snprintf(bin, sizeof(bin), "%s", server_bin);

	server_pid = seeder_spawn(server_bin, argv, "/dev/null");
	if (server_pid < 0)
		return 1;

	/* Give the server a moment to bring up its RPC sockets. */
	seeder_sleep_ms(2000);

	if (waitpid(server_pid, NULL, WNOHANG) == server_pid) {
		printf("Kernel seeder - fail: ESDM server died during startup\n");
		server_pid = 0;
		return 1;
	}

	return 0;
}

static int seeder_test_feed(void)
{
	char logfile[] = "/tmp/esdm-kernel-seeder-feed-XXXXXX";
	char bin[FILENAME_MAX];
	char *argv[] = { bin, "-v", "-v", "-v", "-v", "-v", "-i", "2", NULL };
	pid_t pid;
	int status = 0;
	int ret = 0;
	int fd;

	snprintf(bin, sizeof(bin), "%s", seeder_bin);

	fd = mkstemp(logfile);
	if (fd < 0) {
		printf("Kernel seeder - fail: temporary file: %s\n",
		       strerror(errno));
		return 1;
	}
	close(fd);

	if (seeder_start_server()) {
		unlink(logfile);
		return 1;
	}

	pid = seeder_spawn(seeder_bin, argv, logfile);
	if (pid < 0) {
		unlink(logfile);
		return 1;
	}

	/*
	 * The success path: random data was fetched from the ESDM server over
	 * RPC and accepted by the kernel through RNDADDENTROPY.
	 */
	if (seeder_wait_for_log(logfile, "Entropy data with rate",
				SEEDER_SEED_TIMEOUT_MS)) {
		printf("Kernel seeder - pass: random bits obtained from the ESDM server and inserted into the kernel\n");
	} else {
		/*
		 * Name the stage that did not complete - the two halves fail
		 * for entirely different reasons (RPC connectivity vs. the
		 * RNDADDENTROPY ioctl).
		 */
		if (seeder_log_contains(logfile,
					"Failure in generating random bits"))
			printf("Kernel seeder - fail: could not obtain random bits from the ESDM server\n");
		else if (seeder_log_contains(logfile, "Error in adding entropy"))
			printf("Kernel seeder - fail: kernel rejected the entropy insertion\n");
		else
			printf("Kernel seeder - fail: no successful kernel seeding reported\n");

		seeder_dump_log(logfile);
		ret = 1;
	}

	/*
	 * The seeding interval is 2 seconds here while the shutdown bound is
	 * far larger, so a feeder that only noticed the signal after its sleep
	 * would still pass. What is checked is that it terminates at all
	 * instead of ignoring SIGTERM, and that it reports success while doing
	 * so: a signal is how this daemon is normally stopped, so a failure
	 * exit code would leave every "systemctl stop" marking the unit failed.
	 */
	kill(pid, SIGTERM);
	if (!seeder_wait(pid, SEEDER_TERM_TIMEOUT_MS, &status)) {
		printf("Kernel seeder - fail: did not terminate on SIGTERM\n");
		seeder_kill(pid);
		ret = 1;
	} else if (WIFSIGNALED(status)) {
		printf("Kernel seeder - fail: killed by signal %d instead of exiting cleanly\n",
		       WTERMSIG(status));
		ret = 1;
	} else if (WEXITSTATUS(status)) {
		printf("Kernel seeder - fail: exit code %d after SIGTERM, expected success\n",
		       WEXITSTATUS(status));
		ret = 1;
	} else {
		printf("Kernel seeder - pass: terminates successfully on SIGTERM\n");
	}

	unlink(logfile);
	return ret;
}

/********************************** Driver ***********************************/

static int seeder_check_bin(const char *path, const char *name)
{
	struct stat sb;

	if (!path) {
		printf("Kernel seeder - fail: %s not provided\n", name);
		return 1;
	}

	if (stat(path, &sb)) {
		printf("Kernel seeder - fail: %s (%s): %s\n", name, path,
		       strerror(errno));
		return 1;
	}

	if (!S_ISREG(sb.st_mode)) {
		printf("Kernel seeder - fail: %s (%s) is not a regular file\n",
		       name, path);
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	seeder_bin = getenv("ESDM_KERNEL_SEEDER");
	server_bin = getenv("ESDM_SERVER");

	if (seeder_check_bin(seeder_bin, "ESDM_KERNEL_SEEDER"))
		return 1;

	ret = seeder_test_cli();

	if (geteuid()) {
		printf("Kernel seeder - skip: end-to-end feeding needs root\n");
		return ret ? ret : EXIT_SKIP;
	}

	if (seeder_check_bin(server_bin, "ESDM_SERVER"))
		return ret + 1;

	ret += seeder_test_feed();

	if (server_pid > 0) {
		seeder_kill(server_pid);
		server_pid = 0;
	}

	return ret;
}
