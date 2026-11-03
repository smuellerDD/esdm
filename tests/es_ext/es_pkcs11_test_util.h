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
 * What the tests of esdm-es-pkcs11 share: a directory of their own - the
 * working directory of the test and of the daemon, so that es_pkcs11_shim.c
 * finds its files there - holding the SoftHSM configuration and tokens, the
 * PIN files, the socket and daemon.log, the output of the daemon and of the
 * shim; and the daemon started in front of SoftHSM, through the shim.
 */

#ifndef _ES_PKCS11_TEST_UTIL_H
#define _ES_PKCS11_TEST_UTIL_H

#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "es_ext_test_util.h"

#define PK_TOKEN_LABEL "esdm-test-token"
#define PK_TOKEN_PIN "648219"
#define PK_DIR_TEMPLATE "/tmp/esdm-es-pkcs11-test-XXXXXX"

static struct {
	char daemon[PATH_MAX];
	char shim[PATH_MAX];
	char softhsm[PATH_MAX];
	char dir[sizeof(PK_DIR_TEMPLATE)];
	/* Absolute: /proc/net/unix tells a listening socket by its path */
	char socket[sizeof(PK_DIR_TEMPLATE) + 16];
	pid_t pid;
} pk;

static inline int pk_write_file(const char *path, const char *content,
				mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	ssize_t len = (ssize_t)strlen(content);
	int ret = fd >= 0 && write(fd, content, (size_t)len) == len ? 0 : -1;

	if (fd >= 0)
		close(fd);
	return ret;
}

/*
 * Start @argv - looked up on the path - with SoftHSM, the shim and @env in its
 * environment, its output into @log
 */
static inline pid_t pk_spawn(char *const argv[], const char *const *env,
			     const char *log)
{
	char module[PATH_MAX + 32];
	char *envp[8] = { "SOFTHSM2_CONF=softhsm2.conf", module };
	posix_spawn_file_actions_t fa;
	unsigned int e = 2;
	pid_t pid;
	int ret;

	snprintf(module, sizeof(module), "ESDM_PKCS11_SHIM_MODULE=%s",
		 pk.softhsm);
	while (env && *env && e < 7)
		envp[e++] = (char *)*env++;
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, log,
					 O_WRONLY | O_CREAT | O_TRUNC, 0600);
	posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
	ret = posix_spawnp(&pid, argv[0], &fa, NULL, argv, envp);
	posix_spawn_file_actions_destroy(&fa);
	return ret ? -1 : pid;
}

/* Create a token of @label with the PIN of the test */
static inline bool pk_init_token(const char *label)
{
	char *argv[] = { "softhsm2-util", "--init-token",
			 "--free",	  "--label",
			 (char *)label,	  "--so-pin",
			 "1234567890",	  "--pin",
			 PK_TOKEN_PIN,	  NULL };
	pid_t pid = pk_spawn(argv, NULL, "/dev/null");

	return pid > 0 && !es_ext_test_wait(pid);
}

/*
 * The SoftHSM module next to the softhsm2-util on the path - the one creating
 * the tokens has to read them - or the module of the build if it is SoftHSM
 */
static inline bool pk_find_softhsm(void)
{
	char *paths = strdup(getenv("PATH") ? getenv("PATH") : ""), *dir;
	char util[PATH_MAX], real[PATH_MAX], *save = NULL;
	bool found = false;

	for (dir = paths ? strtok_r(paths, ":", &save) : NULL; dir && !found;
	     dir = strtok_r(NULL, ":", &save)) {
		snprintf(util, sizeof(util), "%s/softhsm2-util", dir);
		if (access(util, X_OK) || !realpath(util, real))
			continue;
		snprintf(pk.softhsm, sizeof(pk.softhsm),
			 "%s/../lib/softhsm/libsofthsm2.so", dirname(real));
		found = !access(pk.softhsm, R_OK);
	}
	free(paths);

	if (!found && strstr(ESDM_PKCS11_MODULE_PATH, "softhsm") &&
	    !access(ESDM_PKCS11_MODULE_PATH, R_OK)) {
		snprintf(pk.softhsm, sizeof(pk.softhsm), "%s",
			 ESDM_PKCS11_MODULE_PATH);
		found = true;
	}
	return found;
}

/*
 * The directory of the test, entered, with the PIN files - and the SoftHSM
 * token of the test: 0, 77 without SoftHSM, or 1
 */
static inline int pk_setup(const char *daemon, const char *shim)
{
	char conf[sizeof(PK_DIR_TEMPLATE) + 128];

	/* Paths the test is given may be relative to where it starts */
	snprintf(pk.dir, sizeof(pk.dir), "%s", PK_DIR_TEMPLATE);
	if (!realpath(daemon, pk.daemon) || !realpath(shim, pk.shim) ||
	    !mkdtemp(pk.dir) || chdir(pk.dir) ||
	    pk_write_file("pin", PK_TOKEN_PIN "\n", 0600) ||
	    pk_write_file("wrong-pin", "000000\n", 0600) ||
	    mkdir("credentials", 0700) || mkdir("tokens", 0700))
		return 1;
	snprintf(pk.socket, sizeof(pk.socket), "%s/pkcs11.socket", pk.dir);

	if (!pk_find_softhsm()) {
		printf("SoftHSM (softhsm2-util) is not available\n");
		return 77;
	}
	snprintf(conf, sizeof(conf),
		 "directories.tokendir = %s/tokens\n"
		 "objectstore.backend = file\n"
		 "log.level = ERROR\n",
		 pk.dir);
	if (pk_write_file("softhsm2.conf", conf, 0600) ||
	    !pk_init_token(PK_TOKEN_LABEL))
		return 1;
	printf("SoftHSM: %s\n", pk.softhsm);
	return 0;
}

/* The daemon on the socket of the test, for its user, with @args and @env */
static inline pid_t pk_daemon(const char *const *args, const char *const *env)
{
	char uid[16];
	char *argv[24] = { pk.daemon, "--socket", pk.socket, "-vvvv" };
	unsigned int n = 4;

	/* As es_ext_test_serve() does */
	if (getuid()) {
		snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());
		argv[n++] = "--client_uid";
		argv[n++] = uid;
	}
	while (args && *args && n < 23)
		argv[n++] = (char *)*args++;
	unlink(pk.socket);
	return pk_spawn(argv, env, "daemon.log");
}

/* Start the daemon and wait for it to serve - see pk_daemon() */
static inline bool pk_start(const char *const *args, const char *const *env)
{
	FILE *log;
	int c;

	pk.pid = pk_daemon(args, env);
	if (pk.pid > 0 && es_ext_test_wait_socket(pk.socket))
		return true;

	printf("esdm-es-pkcs11 did not come up, its log:\n");
	log = fopen("daemon.log", "re");
	while (log && (c = fgetc(log)) != EOF)
		putchar(c);
	if (log)
		fclose(log);
	es_ext_test_terminate(pk.pid);
	pk.pid = 0;
	return false;
}

/* Stop the daemon: did it end cleanly on SIGTERM, removing its socket? */
static inline bool pk_stop(void)
{
	bool ret;

	if (pk.pid <= 0)
		return true;
	ret = !es_ext_test_terminate(pk.pid);
	pk.pid = 0;
	return ret && access(pk.socket, F_OK);
}

static inline int pk_rm(const char *path, const struct stat *sb, int flag,
			struct FTW *ftw)
{
	(void)sb;
	(void)flag;
	(void)ftw;
	return remove(path);
}

/* Stop a daemon left running and remove the directory of the test */
static inline void pk_cleanup(void)
{
	es_ext_test_terminate(pk.pid);
	pk.pid = 0;
	if (pk.dir[0] && strcmp(pk.dir, PK_DIR_TEMPLATE))
		nftw(pk.dir, pk_rm, 16, FTW_DEPTH | FTW_PHYS);
}

#endif /* _ES_PKCS11_TEST_UTIL_H */
