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
 * The SP800-90B health tests of the eBPF entropy sources, run in user space on
 * time stamp sequences with known failure points (the health test header uses
 * no kernel structures). The kernel module esdm_es must agree on every point:
 *
 * - RCT: the count is B - 1, the cutoff C - 1; B reaching C fails.
 * - APT: a window of 512 time stamps, its first one A with B = 1, each of the
 *   others equal to A increments B; B reaching the cutoff fails. The time
 *   stamp after a window starts the next one as its A.
 * - Startup: two windows; a failure arms one more, for the window it fell into.
 */

#include <stdint.h>
#include <string.h>
#include <sys/cdefs.h>

#include "common_test.h"
#include "es_ebpf/esdm_es_ebpf_shared.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif

/* The read-only data of the programs, set by each test */
static struct esdm_ebpf_config esdm_ebpf_cfg;

/* The unit under test, which the programs include via the common header */
#include "es_ebpf/esdm_es_ebpf_health.bpf.h"

#define NEVER 100000

static struct esdm_ebpf_percpu_state st;
static uint64_t k, last;

static void test_reset(uint32_t rct, uint32_t rct_perm, uint32_t apt,
		       uint32_t apt_perm)
{
	memset(&st, 0, sizeof(st));
	esdm_ebpf_health_reset(&st);
	memset(&esdm_ebpf_cfg, 0, sizeof(esdm_ebpf_cfg));
	esdm_ebpf_cfg.health_enabled = 1;
	esdm_ebpf_cfg.rct_cutoff = rct;
	esdm_ebpf_cfg.rct_cutoff_permanent = rct_perm;
	esdm_ebpf_cfg.apt_cutoff = apt;
	esdm_ebpf_cfg.apt_cutoff_permanent = apt_perm;
	k = 0;
	last = 0;
}

/*
 * @n time stamps that are never stuck, with @masked as their APT bits, or
 * varying for @masked > 15: the third derivative of 16 * k^3 is 96, which no
 * difference of the low four bits can cancel
 */
static void test_good(unsigned int n, unsigned int masked)
{
	while (n--) {
		k++;
		last = 16 * k * k * k + (masked > 15 ? k % 16 : masked);
		CHECK_EQ(esdm_ebpf_health_test(&st, last), 0);
	}
}

/* @n stuck time stamps: the last one again */
static void test_stuck(unsigned int n)
{
	while (n--)
		CHECK_EQ(esdm_ebpf_health_test(&st, last), 1);
}

static void test_rct(void)
{
	test_reset(30, 60, NEVER, NEVER);
	test_good(10, 16);

	/* B = 30 of C = 31 passes, B = 31 fails */
	test_stuck(29);
	CHECK_EQ(st.health_failures, 0);
	test_stuck(1);
	CHECK_EQ(st.health_failures, 1);
	CHECK_EQ(st.health_test, esdm_ebpf_health_test_rct);
	CHECK_EQ(st.permanent_failure, 0);

	/* The count goes on towards the permanent cutoff */
	test_stuck(29);
	CHECK_EQ(st.permanent_failure, 0);
	test_stuck(1);
	CHECK_EQ(st.permanent_failure, 1);
	CHECK_EQ(st.rct_count, 0);
}

static void test_apt(void)
{
	/* B counts A itself */
	test_reset(NEVER, NEVER, 325, 355);
	test_good(324, 5);
	CHECK_EQ(st.health_failures, 0);
	test_good(1, 5);
	CHECK_EQ(st.health_failures, 1);
	CHECK_EQ(st.health_test, esdm_ebpf_health_test_apt);
	test_good(354 - 325, 5);
	CHECK_EQ(st.permanent_failure, 0);
	test_good(1, 5);
	CHECK_EQ(st.permanent_failure, 1);

	/* The time stamp after a permanent failure starts a new window */
	st.health_failures = 0;
	test_good(324, 5);
	CHECK_EQ(st.health_failures, 0);
	test_good(1, 5);
	CHECK_EQ(st.health_failures, 1);

	/* The 513th time stamp is the A of the second window */
	test_reset(NEVER, NEVER, 325, 355);
	test_good(512, 16);
	CHECK_EQ(st.health_failures, 0);
	test_good(324, 7);
	CHECK_EQ(st.health_failures, 0);
	test_good(1, 7);
	CHECK_EQ(st.health_failures, 1);
}

static void test_startup(void)
{
	unsigned int i;

	test_reset(30, 60, NEVER, NEVER);
	test_good(1023, 16);
	CHECK_EQ(st.startup_done, 0);
	test_good(1, 16);
	CHECK_EQ(st.startup_done, 1);
	CHECK(esdm_ebpf_health_ok(&st), "startup passed, collection is not");

	/* A partial batch is discarded with the failure */
	st.pos = 5;
	for (i = 0; i < st.pos; i++)
		st.rec.delta[i] = 0xaa;
	test_stuck(30);
	CHECK_EQ(st.health_failures, 1);
	CHECK_EQ(st.startup_done, 0);
	CHECK_EQ(st.pos, 0);
	for (i = 0; i < ESDM_EBPF_BATCH_EVENTS; i++)
		CHECK(!st.rec.delta[i], "delta %u kept after a failure", i);

	/*
	 * Time stamp 1054: the rest of the third window, which the failure
	 * fell into, does not count - the fourth and fifth do
	 */
	test_good(2559 - 1054, 16);
	CHECK_EQ(st.startup_done, 0);
	test_good(1, 16);
	CHECK_EQ(st.startup_done, 1);
}

int main(void)
{
	test_rct();
	test_apt();
	test_startup();

	return common_test_result("es_ebpf_health_seq");
}
