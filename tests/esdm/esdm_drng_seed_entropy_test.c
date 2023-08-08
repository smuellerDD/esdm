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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched.h"
#include "logger.h"
#include "ret_checkers.h"
#include "test_pertubation.h"

#ifdef ESDM_TESTMODE
static int esdm_drng_seed_entropy_test(void)
{
	uint8_t buf[256];
	unsigned int i;
	uint32_t prev = 0;
	bool fully_seeded = false, reseed = false;
	int ret = 0;

	esdm_get_random_bytes(buf, sizeof(buf));
	/* Give DRNG seed thread some time to seed */
	sleep(1);

	if (!esdm_state_fully_seeded()) {
		printf("ESDM is not fully seeded!\n");
		goto err;
	}

	for (i = 0; i < 3; i++) {
		esdm_drng_force_reseed();
		esdm_get_random_bytes(buf, sizeof(buf));
		if (!esdm_state_operational()) {
			printf("failed to remain in operational mode\n");
			goto err;
		}
	}

	if (atomic_read(&seed_entropy_ptr) < 0) {
		printf("No seed events detected\n");
		goto err;
	}

	for (i = 0; i <= (unsigned int)atomic_read(&seed_entropy_ptr); i++) {
		/* Do not look further for values */
		if (reseed)
			break;

		printf("Entropy value for %u. seed operation: %u\n", i,
		       seed_entropy[i]);

		if (prev < ESDM_DRNG_SECURITY_STRENGTH_BITS &&
		    prev > seed_entropy[i]) {
			printf("Initial seedding is not monotonically increasing entropy rate (previous %u, current %u)\n",
			       prev, seed_entropy[i]);
			goto err;
		}
		prev = seed_entropy[i];

		if (!fully_seeded) {
			if (esdm_sp80090c_compliant() &&
			    seed_entropy[i] >=
				    (ESDM_DRNG_SECURITY_STRENGTH_BITS * 3 /
				     2)) {
				fully_seeded = true;
				continue;
			} else if (seed_entropy[i] >=
				   ESDM_DRNG_SECURITY_STRENGTH_BITS) {
				fully_seeded = true;
				continue;
			}
		}

		if (fully_seeded &&
		    seed_entropy[i] >= ESDM_DRNG_SECURITY_STRENGTH_BITS)
			reseed = true;
	}

	if (!fully_seeded) {
		printf("Fully seed entropy value not reached\n");
		goto err;
	}

	if (!reseed) {
		printf("Reseed not detected\n");
		goto err;
	}

	printf("Seed operation as expected\n");

out:
	return ret;
err:
	ret = 1;
	goto out;
}

static void create_sched_entropy(void)
{
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		pid_t pid = fork();

		if (pid == 0)
			exit(0);
		else if (pid > 0)
			waitpid(pid, NULL, 0);
	}
}
#endif

int main(int argc, char *argv[])
{
#ifdef ESDM_TESTMODE
	unsigned long val;
	unsigned int force_fips = 0;
	unsigned int only_sched = 0;

	int ret;

	if (argc != 3) {
		printf("Provide FIPS mode and ES config\n");
		return 1;
	}

	val = strtoul(argv[1], NULL, 10);
	if (val == ULONG_MAX)
		return errno;

	if (val) {
		esdm_config_force_fips_set(esdm_config_force_fips_enabled);
		force_fips = 1;
	} else
		esdm_config_force_fips_set(esdm_config_force_fips_disabled);

	val = strtoul(argv[2], NULL, 10);

	logger_set_verbosity(LOGGER_DEBUG);

	/* First initialize */
	ret = esdm_init();
	if (ret)
		return ret;

	/* Now set specific entropy rates */
	switch (val) {
	case 0:
		/* Use default configuration */
		break;
	case 1:
		/* JENT: fully seeded */
		esdm_config_es_cpu_entropy_rate_set(0);
		esdm_config_es_jent_entropy_rate_set(
			ESDM_DRNG_SECURITY_STRENGTH_BITS);
		esdm_config_es_krng_entropy_rate_set(0);
		esdm_config_es_sched_entropy_rate_set(0);
		esdm_config_es_irq_entropy_rate_set(0);
		break;
	case 2:
		/* CPU ES: fully seeded */
		esdm_config_es_cpu_entropy_rate_set(
			ESDM_DRNG_SECURITY_STRENGTH_BITS);
		esdm_config_es_jent_entropy_rate_set(0);
		esdm_config_es_krng_entropy_rate_set(0);
		esdm_config_es_sched_entropy_rate_set(0);
		esdm_config_es_irq_entropy_rate_set(0);
		break;
	case 3:
		if (force_fips) {
			printf("FIPS forced, but only kernel ES enabled - ESDM will never reach fully seeded level\n");
			return 77;
		}
		/* Kernel ES: fully seeded */
		esdm_config_es_cpu_entropy_rate_set(0);
		esdm_config_es_jent_entropy_rate_set(0);
		esdm_config_es_krng_entropy_rate_set(
			ESDM_DRNG_SECURITY_STRENGTH_BITS);
		esdm_config_es_sched_entropy_rate_set(0);
		esdm_config_es_irq_entropy_rate_set(0);
		printf("========= %u\n", esdm_config_es_irq_entropy_rate());
		break;
	case 4:
		/* Scheduler ES fully seeded */
		esdm_config_es_cpu_entropy_rate_set(0);
		esdm_config_es_jent_entropy_rate_set(0);
		esdm_config_es_krng_entropy_rate_set(0);
		esdm_config_es_sched_entropy_rate_set(
			ESDM_DRNG_SECURITY_STRENGTH_BITS);
		esdm_config_es_irq_entropy_rate_set(0);
		only_sched = 1;
		break;
	default:
		printf("Unknown ES configuration value\n");
		return 1;
	}

	/*
	 * Having the call below esdm_init also implicitly tests the monitoring
	 * of the scheduler entropy source after initialization in case it was
	 * started when having insufficient entropy.
	 */
	if (only_sched)
		create_sched_entropy();

	if (only_sched && !esdm_sched_enabled()) {
		printf("Only scheduler ES testing requested, but scheduler ES not initialized\n");
		ret = 77;
		goto out;
	}

	ret = esdm_drng_seed_entropy_test();

out:
	esdm_fini();
	return ret;

#else

	(void)argc;
	(void)argv;
	return 77;
#endif
}
