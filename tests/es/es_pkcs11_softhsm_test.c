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
 * PKCS#11 entropy source against a real token.
 *
 * es_pkcs11_test.c only checks that the callbacks behave when there is no
 * token, which is the situation on most build machines - it passes with the
 * source permanently switched off, so nothing downstream of "a slot was
 * actually bound" is ever executed. SoftHSM provides a PKCS#11 module that
 * needs no hardware, so the interesting half can be tested too: discovering
 * the slot, selecting it by token label, logging in with a PIN, and pulling
 * bytes out of C_GenerateRandom.
 *
 * The token is created here, in a directory of this test's own, so the run
 * does not depend on - or disturb - any token configured on the machine.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_pkcs11.h"
#include "esdm_logger.h"

#define ES_IDX esdm_ext_es_pkcs11

/* Must match what the token below is initialized with */
#define TOKEN_LABEL "esdm-test-token"
#define TOKEN_PIN "648219"
#define TOKEN_SO_PIN "1234567890"

static unsigned int failures;
/* confpath holds tokendir plus a filename, so keep room for it */
static char tokendir[400];
static char confpath[512];

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL %s:%d: ", __func__, __LINE__);            \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			failures++;                                            \
		}                                                              \
	} while (0)

/*
 * Run softhsm2-util. Returns its exit status, or -1 if it could not be run at
 * all - the caller distinguishes "no SoftHSM here" (skip) from "SoftHSM is
 * here and refused" (fail).
 */
static int run_softhsm_util(char *const argv[])
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;

	if (pid == 0) {
		/* Keep the log readable; failures are reported by the caller */
		int devnull = open("/dev/null", O_WRONLY);

		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execvp("softhsm2-util", argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/*
 * Build a SoftHSM configuration pointing at a token directory of our own and
 * initialize one token in it. Returns 0 on success, 77 when SoftHSM is not
 * available (the test then skips), 1 on a real failure.
 */
static int softhsm_setup(void)
{
	const char *tmpdir = getenv("TMPDIR");
	FILE *conf;
	char *argv[] = {
		(char *)"softhsm2-util", (char *)"--init-token",
		(char *)"--free",	(char *)"--label",
		(char *)TOKEN_LABEL,	(char *)"--so-pin",
		(char *)TOKEN_SO_PIN,	(char *)"--pin",
		(char *)TOKEN_PIN,	NULL
	};
	int ret;

	snprintf(tokendir, sizeof(tokendir), "%s/esdm-softhsm-%d",
		 tmpdir && *tmpdir ? tmpdir : "/tmp", (int)getpid());
	snprintf(confpath, sizeof(confpath), "%s/softhsm2.conf", tokendir);

	if (mkdir(tokendir, 0700) < 0) {
		printf("cannot create the token directory %s\n", tokendir);
		return 1;
	}

	conf = fopen(confpath, "w");
	if (!conf) {
		printf("cannot write %s\n", confpath);
		return 1;
	}
	fprintf(conf,
		"directories.tokendir = %s\n"
		"objectstore.backend = file\n"
		"log.level = ERROR\n",
		tokendir);
	if (fclose(conf)) {
		printf("cannot write %s\n", confpath);
		return 1;
	}

	/*
	 * Both softhsm2-util below and the module the ESDM loads read this,
	 * so it has to be in place before either runs.
	 */
	if (setenv("SOFTHSM2_CONF", confpath, 1) < 0) {
		printf("cannot set SOFTHSM2_CONF\n");
		return 1;
	}

	ret = run_softhsm_util(argv);
	if (ret == 127 || ret < 0) {
		printf("softhsm2-util is not available - skipping\n");
		return 77;
	}
	if (ret != 0) {
		printf("softhsm2-util --init-token failed with %d\n", ret);
		return 1;
	}

	return 0;
}

static void softhsm_teardown(void)
{
	/*
	 * Only ever removes what this test created, one directory level deep -
	 * SoftHSM puts one subdirectory per token below the token directory.
	 */
	DIR *d = opendir(tokendir);
	struct dirent *e;

	if (!d)
		return;

	while ((e = readdir(d))) {
		char path[1024];
		DIR *sub;
		struct dirent *se;

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", tokendir, e->d_name);
		sub = opendir(path);
		if (!sub) {
			unlink(path);
			continue;
		}

		while ((se = readdir(sub))) {
			char subpath[2048];

			if (!strcmp(se->d_name, ".") ||
			    !strcmp(se->d_name, ".."))
				continue;
			snprintf(subpath, sizeof(subpath), "%.1000s/%.1000s",
				 path, se->d_name);
			unlink(subpath);
		}
		closedir(sub);
		rmdir(path);
	}
	closedir(d);
	rmdir(tokendir);
}

/* The source has to consider itself usable - the module path is compiled in */
static void test_active(void)
{
	CHECK(esdm_es[ES_IDX]->active && esdm_es[ES_IDX]->active(),
	      "the PKCS#11 source is inactive although a module is configured");
}

/*
 * Selecting the token by label is what a deployment with more than one token
 * relies on, and it is also what binds the slot in the first place.
 */
static void test_select_token(void)
{
	CHECK(esdm_es_pkcs11_set_token_label(TOKEN_LABEL) == 0,
	      "cannot select the SoftHSM token by its label");

	/*
	 * A label no token carries must be refused rather than silently
	 * leaving the previous slot in place - otherwise a typo in the
	 * configuration draws entropy from whatever token happens to be there.
	 */
	CHECK(esdm_es_pkcs11_set_token_label("esdm-no-such-token") != 0,
	      "an unknown token label was accepted");

	/* Put the good one back for the tests that follow */
	CHECK(esdm_es_pkcs11_set_token_label(TOKEN_LABEL) == 0,
	      "cannot re-select the SoftHSM token");
}

static void test_login(void)
{
	CHECK(esdm_es_pkcs11_set_pin(TOKEN_PIN) == 0,
	      "login with the token PIN failed");
}

/* With a slot bound, the source must credit the configured rate */
static void test_entropy_level(void)
{
	uint32_t maxe = esdm_es[ES_IDX]->max_entropy();
	uint32_t curr = esdm_es[ES_IDX]->curr_entropy(esdm_security_strength());
	uint32_t rate = esdm_config_es_pkcs11_entropy_rate();

	CHECK(maxe == curr, "max_entropy (%u) disagrees with curr_entropy (%u)",
	      maxe, curr);

	if (rate)
		CHECK(maxe > 0,
		      "no entropy credited although a token is bound and the rate is %u",
		      rate);
}

/*
 * The point of the source: bytes actually come out of the token, and they are
 * bytes rather than a buffer nobody wrote to.
 */
static void test_get_entropy(void)
{
	struct entropy_es eb_es;
	unsigned int i, zero = 0;
	uint32_t rate = esdm_config_es_pkcs11_entropy_rate();

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	CHECK(eb_es.e_bits <= ESDM_DRNG_INIT_SEED_SIZE_BITS,
	      "over-credited: %u bits for a %u bit request", eb_es.e_bits,
	      ESDM_DRNG_INIT_SEED_SIZE_BITS);

	if (rate)
		CHECK(eb_es.e_bits > 0,
		      "the token delivered no credited entropy");

	for (i = 0; i < ESDM_DRNG_INIT_SEED_SIZE_BITS / 8; i++) {
		if (!eb_es.e[i])
			zero++;
	}
	CHECK(zero < ESDM_DRNG_INIT_SEED_SIZE_BITS / 8,
	      "the buffer the token filled is all zero");

	printf("token delivered %u credited bits, %u of %u bytes zero\n",
	       eb_es.e_bits, zero, ESDM_DRNG_INIT_SEED_SIZE_BITS / 8);
}

/* Two draws in a row must not return the same bytes */
static void test_get_entropy_differs(void)
{
	struct entropy_es first, second;

	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));

	esdm_es[ES_IDX]->get_ent(&first, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	esdm_es[ES_IDX]->get_ent(&second, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	CHECK(memcmp(first.e, second.e, ESDM_DRNG_INIT_SEED_SIZE_BITS / 8) != 0,
	      "two consecutive draws from the token returned identical data");
}

/* The status report has to name the token that is actually in use */
static void test_state(void)
{
	char buf[512];

	memset(buf, 0, sizeof(buf));
	esdm_es[ES_IDX]->state(buf, sizeof(buf));

	CHECK(strstr(buf, "Available entropy") != NULL,
	      "state string malformed: %s", buf);
	CHECK(strstr(buf, TOKEN_LABEL) != NULL,
	      "state does not name the bound token: %s", buf);
	CHECK(strstr(buf, "(unset)") == NULL,
	      "state reports no module although one is configured: %s", buf);
}

/*
 * Clearing the runtime overrides must not leave the source wedged: an empty
 * string falls back to the compile-time defaults, and the source has to keep
 * answering either way.
 */
static void test_clear_overrides(void)
{
	char buf[512];

	CHECK(esdm_es_pkcs11_set_pin("") == 0, "clearing the PIN failed");

	/*
	 * Clearing the label re-opens against the compile-time default, which
	 * is empty in this build - the first usable slot is then taken, and
	 * SoftHSM has exactly one. Whatever it decides, asking for the state
	 * afterwards must still work.
	 */
	(void)esdm_es_pkcs11_set_token_label("");

	memset(buf, 0, sizeof(buf));
	esdm_es[ES_IDX]->state(buf, sizeof(buf));
	CHECK(strstr(buf, "Available entropy") != NULL,
	      "state string malformed after clearing the overrides: %s", buf);
}

static void test_reject_null(void)
{
	CHECK(esdm_es_pkcs11_set_pin(NULL) == -EINVAL,
	      "a NULL PIN was not rejected with -EINVAL");
	CHECK(esdm_es_pkcs11_set_token_label(NULL) == -EINVAL,
	      "a NULL token label was not rejected with -EINVAL");
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ret = softhsm_setup();
	if (ret)
		return ret;

	if (esdm_es[ES_IDX]->init()) {
		printf("the PKCS#11 entropy source failed to initialize against SoftHSM\n");
		softhsm_teardown();
		return 1;
	}

	test_active();
	test_select_token();
	test_login();
	test_entropy_level();
	test_get_entropy();
	test_get_entropy_differs();
	test_state();
	test_reject_null();
	/* Last: it drops the overrides the tests above rely on */
	test_clear_overrides();

	esdm_es[ES_IDX]->fini();
	softhsm_teardown();

	if (failures) {
		printf("es_pkcs11_softhsm: %u check(s) FAILED\n", failures);
		return 1;
	}
	printf("es_pkcs11_softhsm: all checks passed\n");
	return 0;
}
