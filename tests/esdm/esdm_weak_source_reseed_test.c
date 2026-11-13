/*
 * Reseeding with a single source credited below a full seed per collection
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
 * A single source credited below a full seed per collection (250 bits) in a
 * build capping the output without a full reseed (SP800-90C, AIS 20/31 DRG.4)
 * needs two collections per full reseed. The initial DRNG must still get one
 * once its output is used up, or it serves nothing while reported operational.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_logger.h"
#include "es_rates.h"

#if defined(ESDM_TESTMODE) && (ESDM_DRNG_MAX_RESEED_BITS != 0xffffffff)

/* Entropy per collection, below the 256 bits of a full seed */
#define WS_RATE 250

#define WS_REQUEST 32

/* Four times the output allowed without a full reseed */
#define WS_BYTES (4 * (size_t)(ESDM_DRNG_MAX_RESEED_BITS / 8))

/* Requests answered with nothing - a reseed in progress - besides those */
#define WS_ATTEMPTS (2 * WS_BYTES / WS_REQUEST)

static int ws_test(void)
{
	uint8_t buf[WS_REQUEST];
	size_t done = 0, attempts = 0;
	int ret = 0;

	/* The initial DRNG only, which no node DRNG relieves */
	esdm_config_max_nodes_set(1);
	esdm_test_es_rates_zero();
	esdm_config_es_jent_entropy_rate_set(WS_RATE);

	if (esdm_init()) {
		printf("FAIL: esdm_init failed\n");
		return 1;
	}
	if (!esdm_state_operational()) {
		printf("SKIP: the ESDM did not become operational\n");
		ret = 77;
		goto out;
	}

	while (done < WS_BYTES && attempts < WS_ATTEMPTS) {
		ssize_t got = esdm_get_random_bytes(buf, sizeof(buf));

		attempts++;
		if (got > 0)
			done += (size_t)got;
	}

	printf("%zu of %zu bytes in %zu requests, %soperational\n", done,
	       WS_BYTES, attempts, esdm_state_operational() ? "" : "not ");
	if (done < WS_BYTES) {
		printf("FAIL: the initial DRNG stopped serving\n");
		ret = 1;
	}

out:
	esdm_fini();
	return ret;
}

#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if defined(ESDM_TESTMODE) && (ESDM_DRNG_MAX_RESEED_BITS != 0xffffffff)
	esdm_logger_set_verbosity(LOGGER_NONE);
	return ws_test();
#else
	/* Without a maximum, nothing stops the initial DRNG */
	return 77;
#endif
}
