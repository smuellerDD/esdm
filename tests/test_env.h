/*
 * Environment of a daemon a test forks
 *
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

#ifndef TEST_ENV_H
#define TEST_ENV_H

#include <string.h>

extern char **environ;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The daemons are exec'd with an environment built here rather than with the
 * test's own, which would hand them things meant for the test alone - the
 * getrandom tests LD_PRELOAD the interposition library, and a server loading it
 * too would interpose the very calls it is meant to answer.
 *
 * A few variables have to survive that isolation nonetheless: they configure
 * libraries the daemon loads, not the test. SOFTHSM2_CONF is one - the PKCS#11
 * entropy source loads its module at every startup, and SoftHSM logs three
 * errors per load when it finds no configuration.
 */
static const char *const test_env_pass[] = {
	"SOFTHSM2_CONF=",
};

/* Slots a caller has to provide, terminator excluded */
#define TEST_ENV_MAX_VARS (sizeof(test_env_pass) / sizeof(test_env_pass[0]))

/*
 * Fill @envp with the passed-through variables, NULL terminated. @nmemb counts
 * the terminator, so TEST_ENV_MAX_VARS + 1 always suffices. Call before the
 * fork - it is not async-signal-safe, and the strings it hands out are the ones
 * of the caller's own environment.
 */
static inline void test_env_daemon_envp(char **envp, size_t nmemb)
{
	size_t used = 0, i, j;

	for (i = 0; environ && environ[i] && used + 1 < nmemb; i++) {
		for (j = 0; j < TEST_ENV_MAX_VARS; j++) {
			if (!strncmp(environ[i], test_env_pass[j],
				     strlen(test_env_pass[j]))) {
				envp[used++] = environ[i];
				break;
			}
		}
	}

	envp[used] = NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* TEST_ENV_H */
