/*
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
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
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "es_ebpf/esdm_es_irq_ebpf.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"

/*
 * Generate interrupt and softirq events: short sleeps arm hrtimers whose
 * expiry raises timer interrupts and softirqs on the local CPU.
 */
static void create_irq_events(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000 };
	unsigned int i;

	for (i = 0; i < 5000; i++)
		nanosleep(&ts, NULL);
}

/* Drain the ring buffer into the conditioning pool */
static void consume_events(void)
{
	esdm_es[esdm_int_es_irq_ebpf]->monitor_es();
}

static int es_irq_ebpf_getstate(void)
{
	char buf[500];

	memset(buf, 0, sizeof(buf));
	esdm_es[esdm_int_es_irq_ebpf]->state(buf, sizeof(buf));

	if (!strstr(buf, "Available: true") ||
	    !strstr(buf, "Available entropy") || !strstr(buf, "Total events") ||
	    !strstr(buf, "Entropy Rate per 256 events")) {
		printf("ES InterruptEBPF - fail: state information contains unexpected content: %s\n",
		       buf);
		return 1;
	}
	printf("ES InterruptEBPF - pass: state information found:\n%s\n", buf);

	return 0;
}

static int es_irq_ebpf_poolsize(void)
{
	uint32_t max_ent, curr_ent;

	max_ent = esdm_es[esdm_int_es_irq_ebpf]->max_entropy();
	/* Maximum digest size is 512 bits */
	if (max_ent == 0 || max_ent > 512) {
		printf("ES InterruptEBPF - fail: max_entropy out of range: %u\n",
		       max_ent);
		return 1;
	}
	printf("ES InterruptEBPF - pass: max_entropy: %u\n", max_ent);

	curr_ent = esdm_es[esdm_int_es_irq_ebpf]->curr_entropy(
		esdm_security_strength());
	if (curr_ent > max_ent) {
		printf("ES InterruptEBPF - fail: curr_entropy too large: %u\n",
		       curr_ent);
		return 1;
	}
	printf("ES InterruptEBPF - pass: curr_entropy: %u\n", curr_ent);

	return 0;
}

static int es_irq_ebpf_getdata(void)
{
	struct entropy_es eb_es;
	uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES];
	uint32_t loops;

	memset(&zero, 0, sizeof(zero));

	for (loops = 0; loops < 3; loops++) {
		memset(&eb_es, 0, sizeof(eb_es));
		create_irq_events();
		consume_events();
		esdm_es[esdm_int_es_irq_ebpf]->get_ent(
			&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

		if (!memcmp(eb_es.e, zero, ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
			printf("ES InterruptEBPF - fail: get_ent did not deliver data for iteration %u\n",
			       loops);
			return 1;
		}

		if (eb_es.e_bits < esdm_security_strength()) {
			printf("ES InterruptEBPF - fail: get_ent delivered insufficient entropy for iteration %u: %u bits\n",
			       loops, eb_es.e_bits);
			return 1;
		}

		printf("ES InterruptEBPF - pass: get_ent delivered %u bits\n",
		       eb_es.e_bits);
	}

	return 0;
}

static int es_irq_ebpf_reset(void)
{
	uint32_t ent;

	create_irq_events();
	consume_events();

	ent = esdm_es[esdm_int_es_irq_ebpf]->curr_entropy(
		esdm_security_strength());
	if (ent < esdm_security_strength()) {
		printf("ES InterruptEBPF - fail: curr_entropy too low after entropy events: %u\n",
		       ent);
		return 1;
	}
	printf("ES InterruptEBPF - pass: sufficient entropy after entropy events\n");

	esdm_es[esdm_int_es_irq_ebpf]->reset();

	ent = esdm_es[esdm_int_es_irq_ebpf]->curr_entropy(
		esdm_security_strength());
	if (ent > 10) {
		printf("ES InterruptEBPF - fail: curr_entropy after reset too large: %u\n",
		       ent);
		return 1;
	}
	printf("ES InterruptEBPF - pass: no entropy after reset\n");

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * The default entropy rate of the eBPF interrupt ES is 0 - set a
	 * non-zero rate to exercise the entropy accounting.
	 */
	esdm_config_es_irq_ebpf_entropy_rate_set(
		ESDM_DRNG_SECURITY_STRENGTH_BITS);

	ret = esdm_es[esdm_int_es_irq_ebpf]->init();
	if (ret) {
		printf("ES InterruptEBPF - fail: init failed: %d\n", ret);
		return 1;
	}

	if (!esdm_irq_ebpf_enabled()) {
		printf("ES InterruptEBPF: not available (missing privileges, BTF or kernel support), skipping test\n");
		return 77;
	}
	printf("ES InterruptEBPF - pass: init\n");

	ret = es_irq_ebpf_getstate();
	ret += es_irq_ebpf_poolsize();
	ret += es_irq_ebpf_getdata();
	ret += es_irq_ebpf_reset();

	esdm_es[esdm_int_es_irq_ebpf]->fini();
	printf("ES InterruptEBPF - pass: fini\n");

	return ret;
}
