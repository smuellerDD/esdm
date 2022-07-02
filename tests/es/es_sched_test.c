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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched.h"
#include "test_pertubation.h"

static void create_sched_entropy(void)
{
	unsigned int i;

	for (i = 0; i < 2000; i++) {
		pid_t pid = fork();

		if (pid == 0)
			exit(0);
		else if (pid > 0)
			waitpid(pid, NULL, 0);
	}
}

static int es_sched_getstate(void)
{
	char buf[500];

	if (!esdm_es[esdm_int_es_sched]->state) {
		printf("ES Scheduler - fail: state callback missing\n");
		return 1;
	}

	memset(buf, 0, sizeof(buf));

	esdm_es[esdm_int_es_sched]->state(buf, sizeof(buf));

	if (!strncmp(buf, "disabled", 8))
		return -ENOENT;

	if (!strstr(buf, "Hash for operating entropy pool") ||
	    !strstr(buf, "Available entropy") ||
	    !strstr(buf, "per-CPU scheduler event collection size") ||
	    !strstr(buf, "Standards compliance") ||
	    !strstr(buf, "High-resolution timer")) {
		printf("ES Scheduler - fail: state information contains unexpected content: %s\n",
		       buf);
		return 1;
	}
	printf("ES Scheduler - pass: state information found:\n%s\n", buf);

	return 0;
}

static int es_sched_getdata(void)
{
	struct entropy_es eb_es;
	uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES];
	uint32_t loops;

	if (!esdm_es[esdm_int_es_sched]->get_ent) {
		printf("ES Scheduler - fail: get_ent callback missing\n");
		return 1;
	}

	memset(&zero, 0, sizeof(zero));

	for (loops = 0; loops < 10; loops++) {
		memset(&eb_es, 0, sizeof(eb_es));
		create_sched_entropy();
		esdm_es[esdm_int_es_sched]->get_ent(&eb_es,
			ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
		if (eb_es.e_bits == 0) {
			printf("ES Scheduler - pass: get_ent did not collect data\n");
			if (memcmp(eb_es.e, zero,
				   ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
				printf("ES Scheduler - fail: buffer without entropy is not zero\n");
				return 1;
			}
			printf("ES Scheduler - pass: buffer without entropy is zero\n");
		} else {
			if (!memcmp(eb_es.e, zero,
				    ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
				printf("ES Scheduler - fail: get_ent failed to deliver data for iteration %u (reported entropy rate: %u bits)\n",
				       loops, eb_es.e_bits);
				return 1;
			}
			printf("ES Scheduler - pass: buffer with entropy is not zero\n");
		}
	}

	return 0;
}

static int es_sched_poolsize(void)
{
	uint32_t ret, ret2;

	if (!esdm_es[esdm_int_es_sched]->max_entropy) {
		printf("ES Scheduler - fail: max_entropy callback missing\n");
		return 1;
	}

	if (!esdm_es[esdm_int_es_sched]->curr_entropy) {
		printf("ES Scheduler - fail: curr_entropy callback missing\n");
		return 1;
	}

	ret = esdm_es[esdm_int_es_sched]->max_entropy();
	/* Maximum digest size is 512 bits */
	if (ret > 512 * esdm_online_nodes()) {
		printf("ES Scheduler - fail: max_entropy too large: %d\n", ret);
		return 1;
	}
	printf("ES Scheduler - pass: max_entropy: %d\n", ret);

	ret2 = esdm_es[esdm_int_es_sched]->curr_entropy(esdm_security_strength());
	if (ret2 > 512 * esdm_online_nodes()) {
		printf("ES Scheduler - fail: curr_entropy too large: %u\n", ret2);
		return 1;
	}
	printf("ES Scheduler - pass: curr_entropy: %d\n", ret2);

	return 0;
}

static int es_sched_name(void)
{
	const char *name = esdm_es[esdm_int_es_sched]->name;

	if (!name) {
		printf("ES Scheduler - fail: name not set!");
		return 1;
	}

	printf("ES Scheduler - pass: name: %s\n", name);

	return 0;
}

static int es_sched_init(void)
{
	int ret;

	if (!esdm_es[esdm_int_es_sched]->init) {
		printf("ES Scheduler - fail: init callback missing\n");
		return 1;
	}

	ret = esdm_es[esdm_int_es_sched]->init();
	if (ret) {
		printf("ES Scheduler - fail: init failed: %d\n", ret);
		return 1;
	}

	if (!esdm_sched_enabled())
		return 77;

	printf("ES Scheduler - pass: init\n");

	return 0;
}

static int es_sched_fini(void)
{
	if (!esdm_es[esdm_int_es_sched]->fini) {
		printf("ES Scheduler - fail: fini callback missing\n");
		return 1;
	}
	esdm_es[esdm_int_es_sched]->fini();

	printf("ES Scheduler - pass: fini\n");

	return 0;
}

static int es_sched_reset_check(void)
{
	uint32_t ent;

	/* Fill up the entropy to the max */
	create_sched_entropy();
	ent = esdm_es[esdm_int_es_sched]->curr_entropy(esdm_security_strength());
	if (ent < ESDM_DRNG_SECURITY_STRENGTH_BITS) {
		printf("ES Scheduler- fail: curr_entropy too low after entropy events: %u\n",
		       ent);
		return 1;
	} else {
		printf("ES Scheduler - pass: sufficient entropy after entropy events\n");
	}

	esdm_es[esdm_int_es_sched]->reset();

	/*
	 * We allow that between the reset and the curr_entropy call some
	 * entropy is collected.
	 */
	ent = esdm_es[esdm_int_es_sched]->curr_entropy(esdm_security_strength());
	if (ent > 10) {
		printf("ES Scheduler - fail: curr_entropy after reset too large: %u\n",
		       ent);
		return 1;
	} else {
		printf("ES Scheduler - pass: no entropy after reset\n");
	}

	return 0;
}

static int es_sched_reset(void)
{
	if (!esdm_es[esdm_int_es_sched]->reset) {
		printf("ES Scheduler: reset callback missing\n");
		return 1;
	}

#ifdef ESDM_TESTMODE
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
	uint32_t i = 0;
	int ptr = -1;

	atomic_set(&seed_entropy_ptr, -1);

	if (es_sched_reset_check())
		return 1;

	create_sched_entropy();

	do {
		esdm_es[esdm_int_es_sched]->monitor_es();
		ptr = atomic_read(&seed_entropy_ptr);
		nanosleep(&ts, NULL);
		i++;
	} while (ptr < 1 && i < 60);

	if (ptr < 0) {
		printf("ES Scheduler - fail: No seed events detected\n");
		return 1;
	}

	if (ptr == 1) {
		printf("ES Scheduler - info: Entropy value for %u. seed operation: %u\n",
		       0, seed_entropy[0]);
		printf("ES Scheduler - info: Entropy value for %u. seed operation: %u\n",
		       1, seed_entropy[1]);

		if (seed_entropy[0] < ESDM_DRNG_SECURITY_STRENGTH_BITS)
			return 1;
		if (seed_entropy[1] < ESDM_DRNG_SECURITY_STRENGTH_BITS)
			return 1;
		return 0;
	} else {
		printf("ES Scheduler - info: Entropy value for %u. seed operation: %u\n",
		       0, seed_entropy[0]);
		if (seed_entropy[i] < ESDM_DRNG_SECURITY_STRENGTH_BITS)
			return 1;
		return 0;
	}

#else /* ESDM_TESTMODE */
	if (es_sched_reset_check())
		return 1;
	return 0;
#endif /* ESDM_TESTMODE */
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	logger_set_verbosity(LOGGER_DEBUG);

	esdm_config_es_sched_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	ret = es_sched_init();
	if (ret)
		return ret;

	/* If scheduler ES is disabled, do not bother to test */
	ret = es_sched_getstate();
	if (ret == -ENOENT) {
		printf("ES Scheduler: disabled, skipping test\n");
		return 0;
	}

	ret += es_sched_name();
	ret += es_sched_poolsize();
	ret += es_sched_getdata();
	ret += es_sched_reset();
	ret += es_sched_fini();

	return ret;
}
