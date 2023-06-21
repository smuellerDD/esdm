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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_es_mgr.h"
#include "logger.h"
#include "ret_checkers.h"

#ifdef ESDM_TESTMODE
static int esdm_drng_mgr_max_wo_reseed_test(bool success)
{
	uint8_t buf[256];
	unsigned int i;
	int ret;

	logger_set_verbosity(LOGGER_DEBUG);

	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	CKINT(esdm_init());

	esdm_get_random_bytes(buf, sizeof(buf));

	/* Wait for fully seeded */
	sleep(1);

	if (!esdm_state_fully_seeded()) {
		printf("ESDM is not fully seeded!\n");
		goto err;
	}

	for (i = 0; i < 10; i++) {
		if (esdm_get_random_bytes(buf, sizeof(buf)) !=
		    sizeof(buf)) {
			printf("cannot obtain random data\n");
			goto err;
		}
	}

	esdm_drng_force_reseed();
	esdm_config_drng_max_wo_reseed_set(2);

	esdm_config_es_cpu_entropy_rate_set(0);
	esdm_config_es_jent_entropy_rate_set(0);
	esdm_config_es_krng_entropy_rate_set(0);
	esdm_config_es_hwrand_entropy_rate_set(0);
	esdm_config_es_irq_entropy_rate_set(0);
	esdm_config_es_sched_entropy_rate_set(0);

	if (!esdm_state_operational()) {
		printf("failed to remain in operational mode\n");
		goto err;
	}

	esdm_drng_force_reseed();
	esdm_get_random_bytes(buf, sizeof(buf));
	if (!esdm_state_operational()) {
		printf("failed to remain in operational mode\n");
		goto err;
	}

	esdm_drng_force_reseed();
	esdm_get_random_bytes(buf, sizeof(buf));
	if (esdm_state_operational() != success) {
		printf("failed to %soperational mode\n",
		       success ? "remain in " : "enter non-");
		goto err;
	}

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif

int main(int argc, char *argv[])
{
#ifdef ESDM_TESTMODE
	cpu_set_t set;
	unsigned long drng_instances;
	int ret;

	if (argc != 2) {
		printf("Provide number of DRNG instances to be created\n");
		return 1;
	}

	drng_instances = strtoul(argv[1], NULL, 10);
	if (drng_instances == ULONG_MAX)
		return errno;
	if (drng_instances > UINT32_MAX)
		return 1;

	/*
	 * Test idea: instantiate 1 DRNG and set the max without reseed
	 * threshold to 2. Also set all entropy sources to deliver insufficient
	 * entropy. Now, cause 2 reseeds and verify that the DRNG goes
	 * into non-operational mode.
	 */
	esdm_config_max_nodes_set((uint32_t)drng_instances);
	if (drng_instances > 1) {
		CPU_ZERO(&set);
		CPU_SET(1, &set);
		if (sched_setaffinity(getpid(), sizeof(cpu_set_t), &set) ==
		    -1) {
			printf("Cannot pin process to CPU 1\n");
			return 1;
		}
		if (sched_getcpu() < 1) {
			printf("Cannot pin process to CPU 1\n");
			return 1;
		}
	}
	ret = esdm_drng_mgr_max_wo_reseed_test(drng_instances > 1 ? true :
								    false);

	return ret;
#else
	(void)argc;
	(void)argv;
	return 77;
#endif
}
