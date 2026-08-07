/*
 * Test of the interrupt entropy source
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

/*
 * The counterpart of es_sched_test for the interrupt entropy source. Both are
 * served by the same kernel add-on through the same ring buffer and DRBG
 * post-processing, and the userspace halves are deliberate twins - so the
 * source that had no test of its own was reached only through whatever the
 * ESDM as a whole happened to ask of it, which is its extraction path and
 * little else. Its initialization, its monitor, its state reporting and its
 * reset went unexecuted.
 *
 * Skips (77) without /dev/esdm_es, i.e. everywhere but a machine carrying the
 * patched kernel and its esdm_es module.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_es_irq.h"
#include "helper.h"
#include "test_pertubation.h"

/*
 * Short sleeps arm hrtimers whose expiry raises timer interrupts and softirqs
 * on the local CPU - the same generator the eBPF interrupt test uses, and the
 * only one reachable from unprivileged user space.
 */
static void create_irq_entropy(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000 };
	unsigned int i;

	for (i = 0; i < 5000; i++)
		nanosleep(&ts, NULL);
}

static int es_irq_getstate(void)
{
	char buf[500];

	if (!esdm_es[esdm_int_es_irq]->state) {
		printf("ES Interrupt - fail: state callback missing\n");
		return 1;
	}

	memset(buf, 0, sizeof(buf));

	esdm_es[esdm_int_es_irq]->state(buf, sizeof(buf));

	if (!strncmp(buf, " disabled", 9) || !strncmp(buf, "disabled", 8))
		return -ENOENT;

	/*
	 * The labels come from the kernel module (esdm_irq_es_state() of
	 * addon/linux_esdm_es/esdm_es_irq.c), so this pins the two together.
	 */
	if (!strstr(buf, "DRBG for operating entropy pool") ||
	    !strstr(buf, "Available entropy") ||
	    !strstr(buf, "per-CPU interrupt collection size") ||
	    !strstr(buf, "Standards compliance") ||
	    !strstr(buf, "High-resolution timer")) {
		printf("ES Interrupt - fail: state information contains unexpected content: %s\n",
		       buf);
		return 1;
	}
	printf("ES Interrupt - pass: state information found:\n%s\n", buf);

	return 0;
}

/*
 * The JSON status is what the server embeds in its own status document, so a
 * malformed one is not visible until something parses it. Only the framing and
 * the member names are checked here - the values are the plain state's.
 */
static int es_irq_getstate_json(void)
{
	char buf[ESDM_STATUS_JSON_BUFLEN];
	size_t len;

	if (!esdm_es[esdm_int_es_irq]->state_json) {
		printf("ES Interrupt - fail: state_json callback missing\n");
		return 1;
	}

	memset(buf, 0, sizeof(buf));
	esdm_es[esdm_int_es_irq]->state_json(buf, sizeof(buf));

	len = strlen(buf);
	if (len < 2 || buf[0] != '{' || buf[len - 1] != '}') {
		printf("ES Interrupt - fail: state_json is not a JSON object: %s\n",
		       buf);
		return 1;
	}

	if (!strstr(buf, "\"drbg_for_operating_entropy_pool\"") ||
	    !strstr(buf, "\"available_entropy\"") ||
	    !strstr(buf, "\"per_cpu_interrupt_collection_size\"") ||
	    !strstr(buf, "\"high_resolution_timer\"")) {
		printf("ES Interrupt - fail: state_json misses a member: %s\n",
		       buf);
		return 1;
	}

	printf("ES Interrupt - pass: state_json: %s\n", buf);

	return 0;
}

static int es_irq_getdata(void)
{
	struct entropy_es eb_es;
	uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES];
	uint32_t loops;

	if (!esdm_es[esdm_int_es_irq]->get_ent) {
		printf("ES Interrupt - fail: get_ent callback missing\n");
		return 1;
	}

	memset(&zero, 0, sizeof(zero));

	for (loops = 0; loops < 10; loops++) {
		memset(&eb_es, 0, sizeof(eb_es));
		create_irq_entropy();
		esdm_es[esdm_int_es_irq]->get_ent(
			&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
		if (eb_es.e_bits == 0) {
			printf("ES Interrupt - pass: get_ent did not collect data\n");
			if (memcmp(eb_es.e, zero,
				   ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
				printf("ES Interrupt - fail: buffer without entropy is not zero\n");
				return 1;
			}
			printf("ES Interrupt - pass: buffer without entropy is zero\n");
		} else {
			if (!memcmp(eb_es.e, zero,
				    ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
				printf("ES Interrupt - fail: get_ent failed to deliver data for iteration %u (reported entropy rate: %u bits)\n",
				       loops, eb_es.e_bits);
				return 1;
			}
			printf("ES Interrupt - pass: buffer with entropy is not zero\n");
		}
	}

	return 0;
}

/*
 * max_entropy() reports what the collected events are worth, which the DRBG
 * post-processing lets grow with the ring buffer rather than capping at one
 * digest per CPU. So what is checked is the invariant between the two
 * callbacks rather than an absolute ceiling: a request cannot be worth more
 * than the source has.
 */
static int es_irq_poolsize(void)
{
	uint32_t max, curr;

	if (!esdm_es[esdm_int_es_irq]->max_entropy) {
		printf("ES Interrupt - fail: max_entropy callback missing\n");
		return 1;
	}

	if (!esdm_es[esdm_int_es_irq]->curr_entropy) {
		printf("ES Interrupt - fail: curr_entropy callback missing\n");
		return 1;
	}

	max = esdm_es[esdm_int_es_irq]->max_entropy();
	curr = esdm_es[esdm_int_es_irq]->curr_entropy(esdm_security_strength());

	if (curr > max) {
		printf("ES Interrupt - fail: curr_entropy %u exceeds max_entropy %u\n",
		       curr, max);
		return 1;
	}

	printf("ES Interrupt - pass: max_entropy: %u, curr_entropy: %u\n", max,
	       curr);

	return 0;
}

static int es_irq_name(void)
{
	const char *name = esdm_es[esdm_int_es_irq]->name;

	if (!name) {
		printf("ES Interrupt - fail: name not set!\n");
		return 1;
	}

	printf("ES Interrupt - pass: name: %s\n", name);

	return 0;
}

static int es_irq_init(void)
{
	int ret;

	if (!esdm_es[esdm_int_es_irq]->init) {
		printf("ES Interrupt - fail: init callback missing\n");
		return 1;
	}

	ret = esdm_es[esdm_int_es_irq]->init();
	if (ret) {
		printf("ES Interrupt - fail: init failed: %d\n", ret);
		return 1;
	}

	if (!esdm_irq_enabled())
		return 77;

	printf("ES Interrupt - pass: init\n");

	return 0;
}

static int es_irq_fini(void)
{
	if (!esdm_es[esdm_int_es_irq]->fini) {
		printf("ES Interrupt - fail: fini callback missing\n");
		return 1;
	}
	esdm_es[esdm_int_es_irq]->fini();

	printf("ES Interrupt - pass: fini\n");

	return 0;
}

/*
 * A reset has to invalidate what was collected before it. Some entropy is
 * allowed to arrive between the reset and the read below - interrupts do not
 * stop for the test - so this checks that the source dropped back to nothing
 * rather than that it is exactly empty.
 */
static int es_irq_reset_check(void)
{
	uint32_t ent;

	create_irq_entropy();
	ent = esdm_es[esdm_int_es_irq]->curr_entropy(esdm_security_strength());
	if (ent == 0) {
		printf("ES Interrupt - info: no entropy collected, reset not exercised against a filled pool\n");
	} else {
		printf("ES Interrupt - pass: entropy after interrupt events: %u\n",
		       ent);
	}

	esdm_es[esdm_int_es_irq]->reset();

	ent = esdm_es[esdm_int_es_irq]->curr_entropy(esdm_security_strength());
	if (ent > ESDM_DRNG_SECURITY_STRENGTH_BITS) {
		printf("ES Interrupt - fail: curr_entropy after reset too large: %u\n",
		       ent);
		return 1;
	}

	printf("ES Interrupt - pass: entropy dropped after reset: %u\n", ent);

	return 0;
}

static int es_irq_reset(void)
{
	if (!esdm_es[esdm_int_es_irq]->reset) {
		printf("ES Interrupt - fail: reset callback missing\n");
		return 1;
	}

	return es_irq_reset_check();
}

/*
 * The monitor is what the ES manager calls to have the source hand its
 * collected events over. It is driven directly here rather than through the
 * manager, so that it is exercised even when the ESDM is already seeded and
 * would not ask.
 */
static int es_irq_monitor(void)
{
	unsigned int i;

	if (!esdm_es[esdm_int_es_irq]->monitor_es) {
		printf("ES Interrupt - fail: monitor_es callback missing\n");
		return 1;
	}

	for (i = 0; i < 10; i++) {
		create_irq_entropy();
		esdm_es[esdm_int_es_irq]->monitor_es();
	}

	printf("ES Interrupt - pass: monitor_es\n");

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	esdm_config_es_irq_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	ret = es_irq_init();
	if (ret)
		return ret;

	/* If the interrupt ES is disabled, do not bother to test */
	ret = es_irq_getstate();
	if (ret == -ENOENT) {
		printf("ES Interrupt: disabled, skipping test\n");
		return 77;
	}

	ret += es_irq_getstate_json();
	ret += es_irq_name();
	ret += es_irq_poolsize();
	ret += es_irq_getdata();
	ret += es_irq_monitor();
	ret += es_irq_reset();
	ret += es_irq_fini();

	return ret;
}
