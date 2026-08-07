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
 * Tests for common/test_pertubation.c - the instrumentation a test mode build
 * carries so the test suite can observe and steer the ESDM from the outside.
 *
 * The shared memory accounting is what needs the attention here. Several
 * independent users attach to the one process-global segment - the privileged
 * and the unprivileged RPC client each on their own, plus the server - so the
 * reference count is the only thing keeping the first of them to shut down from
 * pulling the mapping out from under the others. That is exercised below by
 * nesting init/fini and checking that the data survives until the last user is
 * gone.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common_test.h"
#include "config.h"
#include "test_pertubation.h"

/*
 * Size of the seed_entropy recorder. The header exports the array without a
 * bound, so it is restated here - one slot per external entropy source plus the
 * aux pool, as in common/test_pertubation.c.
 */
#define SEED_ENTROPY_SLOTS 7

static void test_seed_entropy(void)
{
	unsigned int i;

	/* The recorder starts out empty */
	memset(seed_entropy, 0, sizeof(uint32_t) * SEED_ENTROPY_SLOTS);
	atomic_store(&seed_entropy_ptr, -1);

	/*
	 * Every reported entropy estimate is appended, so the test suite can
	 * check what each entropy source contributed to a seeding operation.
	 */
	for (i = 0; i < SEED_ENTROPY_SLOTS; i++)
		esdm_test_seed_entropy(100 + i);

	for (i = 0; i < SEED_ENTROPY_SLOTS; i++) {
		if (seed_entropy[i] != 100 + i) {
			CHECK(0, "slot %u holds %u, expected %u", i,
			      seed_entropy[i], 100 + i);
			break;
		}
	}
	CHECK_EQ(atomic_load(&seed_entropy_ptr), 6);

	/*
	 * More estimates than the recorder holds are dropped rather than
	 * written past its end.
	 */
	esdm_test_seed_entropy(0xdeadbeef);
	esdm_test_seed_entropy(0xdeadbeef);
	CHECK_EQ(seed_entropy[6], 106);
	CHECK_EQ(atomic_load(&seed_entropy_ptr), 8);

	atomic_store(&seed_entropy_ptr, -1);
}

static void test_fallback_fd(void)
{
	/* By default the descriptor is handed through unchanged */
	esdm_test_disable_fallback(0);
	CHECK_EQ(esdm_test_fallback_fd(7), 7);
	CHECK_EQ(esdm_test_fallback_fd(0), 0);
	CHECK_EQ(esdm_test_fallback_fd(-1), -1);

	/*
	 * With the fallback disabled a usable descriptor is turned into an
	 * unusable one, which is how a test forces the code under test onto its
	 * error path instead of quietly using the kernel RNG.
	 */
	esdm_test_disable_fallback(1);
	CHECK_EQ(esdm_test_fallback_fd(7), -1);
	CHECK_EQ(esdm_test_fallback_fd(0), -1);

	/* An already invalid descriptor stays what it is */
	CHECK_EQ(esdm_test_fallback_fd(-1), -1);
	CHECK_EQ(esdm_test_fallback_fd(-5), -5);

	esdm_test_disable_fallback(0);
	CHECK_EQ(esdm_test_fallback_fd(7), 7);
}

static void test_shm_status_detached(void)
{
	/*
	 * Without a mapping the accounting is inert: reads answer zero and
	 * writes go nowhere, rather than faulting on a segment that is not
	 * there.
	 */
	esdm_test_shm_status_add_rpc_client_written(100);
	esdm_test_shm_status_add_rpc_server_written(200);
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 0);
	CHECK_EQ(esdm_test_shm_status_get_rpc_server_written(), 0);

	/* And so is a reset, and a fini nobody has an init for */
	esdm_test_shm_status_reset();
	esdm_test_shm_status_fini();
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 0);
}

static void test_shm_status_accounting(void)
{
	int ret = esdm_test_shm_status_init();

	if (ret) {
		/*
		 * System V shared memory is not available everywhere a build
		 * runs. That is an environment limitation, not a defect of the
		 * code under test.
		 */
		printf("test_pertubation: shared memory unavailable (%d), "
		       "skipping the accounting checks\n",
		       ret);
		return;
	}

	esdm_test_shm_status_reset();
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 0);
	CHECK_EQ(esdm_test_shm_status_get_rpc_server_written(), 0);

	/* The two directions are counted independently and accumulate */
	esdm_test_shm_status_add_rpc_client_written(100);
	esdm_test_shm_status_add_rpc_client_written(50);
	esdm_test_shm_status_add_rpc_server_written(7);
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 150);
	CHECK_EQ(esdm_test_shm_status_get_rpc_server_written(), 7);

	/* A zero sized transfer changes nothing */
	esdm_test_shm_status_add_rpc_client_written(0);
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 150);

	/* The reset clears both counters at once */
	esdm_test_shm_status_reset();
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 0);
	CHECK_EQ(esdm_test_shm_status_get_rpc_server_written(), 0);

	esdm_test_shm_status_fini();
}

static void test_shm_status_refcount(void)
{
	int ret = esdm_test_shm_status_init();

	if (ret) {
		printf("test_pertubation: shared memory unavailable (%d), "
		       "skipping the reference count checks\n",
		       ret);
		return;
	}

	/* A second user takes a reference on the same mapping */
	CHECK_EQ(esdm_test_shm_status_init(), 0);
	CHECK_EQ(esdm_test_shm_status_init(), 0);

	esdm_test_shm_status_reset();
	esdm_test_shm_status_add_rpc_client_written(4711);
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 4711);

	/*
	 * Each of them can shut down on its own without detaching the segment
	 * the others are still writing through.
	 */
	esdm_test_shm_status_fini();
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 4711);
	esdm_test_shm_status_add_rpc_client_written(1);
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 4712);

	esdm_test_shm_status_fini();
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 4712);

	/* Only the last one tears it down */
	esdm_test_shm_status_fini();
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 0);

	/* An unbalanced fini afterwards is a no-op rather than a double free */
	esdm_test_shm_status_fini();
	esdm_test_shm_status_fini();
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 0);

	/*
	 * And the accounting can be set up again afterwards. Whether that
	 * reattaches to the very same segment or creates a fresh one is not
	 * asserted: the key is machine global, so a test mode esdm-server
	 * running next to this test owns it, and then the removal on the last
	 * detach above is refused - which is correct, it is not ours to
	 * destroy.
	 */
	CHECK_EQ(esdm_test_shm_status_init(), 0);
	esdm_test_shm_status_reset();
	CHECK_EQ(esdm_test_shm_status_get_rpc_client_written(), 0);
	esdm_test_shm_status_fini();
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_seed_entropy();
	test_fallback_fd();
	test_shm_status_detached();
	test_shm_status_accounting();
	test_shm_status_refcount();

	return common_test_result("test_pertubation");
}
