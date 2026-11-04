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
 * The kernel crypto API RNG the kernel Jitter RNG source reads.
 *
 * - By default the one the build names (es_jent_kernel_name).
 * - A name set with esdm_es_jent_kernel_set_name() - what esdm-server
 *   --es_jent_kernel_name does - is opened instead, by the init of the source,
 *   and right away while it runs. It outlives the fini of the source, and an
 *   empty name goes back to the build's.
 * - An RNG of that name that is not there leaves the source switched off.
 *
 * The source is compiled into the test, with the libkcapi RNG calls replaced
 * by a stand-in knowing two RNGs: the kernel's and that of a module.
 */

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

struct kcapi_handle;

static ssize_t test_kcapi_rng_generate(struct kcapi_handle *handle,
				       uint8_t *buffer, size_t len);
static int test_kcapi_rng_init(struct kcapi_handle **handle,
			       const char *ciphername, uint32_t flags);
static void test_kcapi_rng_destroy(struct kcapi_handle *handle);

#define kcapi_rng_generate test_kcapi_rng_generate
#define kcapi_rng_init test_kcapi_rng_init
#define kcapi_rng_destroy test_kcapi_rng_destroy

/* The unit under test */
#include "esdm_es_jent_kernel.c"

#include "common_test.h"
#include "esdm_logger.h"

#define TEST_MODULE_RNG "jitterentropy_rng_module"

static uint8_t test_kcapi_handle;
static char test_kcapi_opened[CRYPTO_MAX_ALG_NAME_ESDM];
static unsigned int test_kcapi_open_handles;

static int test_kcapi_rng_init(struct kcapi_handle **handle,
			       const char *ciphername, uint32_t flags)
{
	(void)flags;

	snprintf(test_kcapi_opened, sizeof(test_kcapi_opened), "%s",
		 ciphername);
	if (strcmp(ciphername, ESDM_JENT_KERNEL_NAME) &&
	    strcmp(ciphername, TEST_MODULE_RNG)) {
		errno = ENOENT;
		return -ENOENT;
	}

	test_kcapi_open_handles++;
	*handle = (struct kcapi_handle *)&test_kcapi_handle;
	return 0;
}

static void test_kcapi_rng_destroy(struct kcapi_handle *handle)
{
	(void)handle;
	test_kcapi_open_handles--;
}

static ssize_t test_kcapi_rng_generate(struct kcapi_handle *handle,
				       uint8_t *buffer, size_t len)
{
	static uint8_t counter;

	(void)handle;
	memset(buffer, ++counter, len);
	return (ssize_t)len;
}

static bool test_state_has(const char *what)
{
	char buf[512];

	memset(buf, 0, sizeof(buf));
	esdm_es_jent_kernel.state(buf, sizeof(buf));
	return strstr(buf, what) != NULL;
}

int main(void)
{
	char too_long[CRYPTO_MAX_ALG_NAME_ESDM + 1];

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* The build's */
	CHECK_EQ(esdm_es_jent_kernel.init(), 0);
	CHECK_STR_EQ(test_kcapi_opened, ESDM_JENT_KERNEL_NAME);
	CHECK(esdm_es_jent_kernel.active(), "the kernel RNG was not opened");
	CHECK(test_state_has(ESDM_JENT_KERNEL_NAME),
	      "the state does not name the kernel RNG");
	esdm_es_jent_kernel.fini();
	CHECK_EQ(test_kcapi_open_handles, 0);

	/* Arguments */
	memset(too_long, 'x', sizeof(too_long) - 1);
	too_long[sizeof(too_long) - 1] = '\0';
	CHECK_EQ(esdm_es_jent_kernel_set_name(NULL), -EINVAL);
	CHECK_EQ(esdm_es_jent_kernel_set_name(too_long), -EINVAL);

	/* Set before the init, and kept across a fini */
	CHECK_EQ(esdm_es_jent_kernel_set_name(TEST_MODULE_RNG), 0);
	CHECK_EQ(test_kcapi_open_handles, 0);
	for (unsigned int i = 0; i < 2; i++) {
		CHECK_EQ(esdm_es_jent_kernel.init(), 0);
		CHECK_STR_EQ(test_kcapi_opened, TEST_MODULE_RNG);
		CHECK(esdm_es_jent_kernel.active(),
		      "the module's RNG was not opened");
		CHECK(test_state_has(TEST_MODULE_RNG),
		      "the state does not name the module's RNG");
		esdm_es_jent_kernel.fini();
	}

	/* Set while the source runs: replaced at once */
	CHECK_EQ(esdm_es_jent_kernel.init(), 0);
	CHECK_EQ(esdm_es_jent_kernel_set_name("no_such_rng"), -ENOENT);
	CHECK(!esdm_es_jent_kernel.active(),
	      "an RNG that is not there is used");
	CHECK_EQ(test_kcapi_open_handles, 0);
	CHECK_EQ(esdm_es_jent_kernel_set_name(""), 0);
	CHECK_STR_EQ(test_kcapi_opened, ESDM_JENT_KERNEL_NAME);
	CHECK(esdm_es_jent_kernel.active(),
	      "the build's RNG is not back with the name cleared");
	CHECK_EQ(test_kcapi_open_handles, 1);
	esdm_es_jent_kernel.fini();
	CHECK_EQ(test_kcapi_open_handles, 0);

	return common_test_result("es_jent_kernel_name");
}
