/*
 * Test of what the ESDM library does around its normal operation
 *
 *   - esdm_init() after esdm_fini() is refused.
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

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include "esdm.h"
#include "esdm_logger.h"

#ifdef ESDM_TESTMODE

static int esdm_lifecycle_test(void)
{
	ssize_t rc;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ret = esdm_init();
	if (ret) {
		printf("esdm_init() failed: %d\n", ret);
		return 1;
	}

	esdm_fini();

	rc = esdm_init();
	if (rc != -ESHUTDOWN) {
		printf("esdm_init() after esdm_fini() returned %zd\n", rc);
		return 1;
	}

	printf("esdm_init() after esdm_fini() is refused\n");
	return 0;
}
#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_lifecycle_test();
#else
	return 77;
#endif
}
