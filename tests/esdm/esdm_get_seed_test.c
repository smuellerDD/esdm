/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include "inttypes.h"
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_es_mgr.h"
#include "esdm_node.h"
#include "esdm_logger.h"
#include "test_pertubation.h"

/*
 * A source that fails - or is compiled in without its device, like a TPM2 on a
 * machine without one - reports no entropy and writes nothing into its slot.
 * The buffer of esdm_get_seed() is the caller's, which gets it back as seed:
 * the slot of such a source must not carry the caller's bytes back to it.
 *
 * The auxiliary pool, which every build has, plays that source here.
 */
static void esdm_get_seed_failing_get_ent(struct entropy_es *eb_es,
					  uint32_t requested_bits,
					  bool allow_cached)
{
	(void)requested_bits;
	(void)allow_cached;

	eb_es->e_bits = 0;
}

static int esdm_get_seed_failed_source_test(uint64_t *buf, size_t buflen)
{
	struct esdm_es_cb *es = esdm_es[esdm_ext_es_aux];
	void (*get_ent)(struct entropy_es *eb, uint32_t requested_bits,
			bool allow_cached) = es->get_ent;
	struct entropy_buf *eb = (struct entropy_buf *)(buf + 2);
	struct entropy_es pattern;
	ssize_t rc;
	int ret = 0;

	memset(&pattern, 0xa5, sizeof(pattern));

	es->get_ent = esdm_get_seed_failing_get_ent;
	memset(buf, 0xa5, buflen);
	rc = esdm_get_seed(buf, buflen, ESDM_GET_SEED_NONBLOCK);
	es->get_ent = get_ent;

	if (rc == -EAGAIN) {
		printf("esdm_get_seed was unable to produce entropy\n");
		return 77;
	}
	if (rc <= 0) {
		printf("esdm_get_seed returned an error with a failing source %zd\n",
		       rc);
		return 1;
	}

	/*
	 * Only a collection that went to the sources says something: with the
	 * entropy reported too low for a seed nothing is fetched, and every
	 * slot is cleared.
	 */
	if (!buf[1]) {
		printf("esdm_get_seed collected no entropy, sources not asked\n");
		return 77;
	}

	if (!memcmp(eb->entropy_es[esdm_ext_es_aux].e, pattern.e,
		    sizeof(pattern.e))) {
		printf("esdm_get_seed handed the caller's bytes back in the slot of a failing source\n");
		ret = 1;
	} else if (eb->entropy_es[esdm_ext_es_aux].e_bits) {
		printf("esdm_get_seed credited a failing source with %u bits\n",
		       eb->entropy_es[esdm_ext_es_aux].e_bits);
		ret = 1;
	} else {
		printf("esdm_get_seed hands back no caller bytes for a failing source\n");
	}

	return ret;
}

int main(int argc, char *argv[])
{
	/*
	 * Sized from what esdm_get_seed() reports rather than from a constant:
	 * struct entropy_buf carries one entry per compiled-in entropy source,
	 * so the seed grows whenever another source is enabled. A fixed buffer
	 * silently becomes too small - enabling the eBPF sources already pushes
	 * the requirement past the 512 bytes this used to reserve.
	 */
	uint64_t *buf = NULL;
	size_t buflen = 0;
	uint64_t buf2;
	uint64_t size;
	uint32_t cpu;
	int ret;
	ssize_t rc;
	unsigned long val;
	unsigned int force_fips = 0;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	if (argc != 2)
		return 1;

	val = strtoul(argv[1], NULL, 10);
	if (val == ULONG_MAX)
		return errno;

	if (val) {
		esdm_config_force_fips_set(esdm_config_force_fips_enabled);
		force_fips = 1;
	} else
		esdm_config_force_fips_set(esdm_config_force_fips_disabled);

	esdm_logger_set_verbosity(LOGGER_DEBUG);
	ret = esdm_init();
	if (ret)
		return ret;

	rc = esdm_get_seed(&buf2, 1, ESDM_GET_SEED_NONBLOCK);
	if (rc != -EINVAL) {
		printf("esdm_get_seed does not indicate that the buffer is too small\n");
		ret = 1;
		goto out;
	}

	rc = esdm_get_seed(&size, sizeof(size), ESDM_GET_SEED_NONBLOCK);
	if (rc != -EMSGSIZE) {
		printf("esdm_get_seed does not indicate that the buffer is too small\n");
		ret = 1;
		goto out;
	}
	buflen = (size_t)size;
	buf = malloc(buflen);
	if (!buf) {
		printf("cannot allocate a %zu byte seed buffer\n", buflen);
		ret = 1;
		goto out;
	}

	/*
	 * get_seed only returns data after all DRNGs are seeded, but each
	 * request only seeds one DRNG - thus allow requests up to the allowed
	 * number of DRNGs.
	 */
	for_each_online_node (cpu) {
		rc = esdm_get_seed(buf, buflen, ESDM_GET_SEED_NONBLOCK);
		if (rc != -EAGAIN)
			break;
	}

	/*
	 * Now that we guaranteed that all DRNGs are initialized, get the seed
	 */
	rc = esdm_get_seed(buf, buflen, ESDM_GET_SEED_NONBLOCK);
	if (rc < 0) {
		printf("esdm_get_seed returned an error %zd\n", rc);
		ret = 1;
		goto out;
	}

	if (rc == 0) {
		printf("esdm_get_seed was unable to produce entropy\n");
		ret = 77;
		goto out;
	}

	if (buf[0] > buflen) {
		printf("esdm_get_seed returned a strange size value %" PRIu64
		       "\n",
		       buf[0]);
		ret = 1;
		goto out;
	}

	if (buf[1] < (force_fips ? 384 : 128)) {
		printf("esdm_get_seed returned insufficient seed: %" PRIu64
		       "\n",
		       buf[1]);
		ret = 1;
		goto out;
	} else {
		printf("esdm_get_seed returned proper seed size value %" PRIu64
		       " bytes and entropy value %" PRIu64 " bits\n",
		       buf[0], buf[1]);
	}

	rc = esdm_get_seed(buf, buflen,
			   ESDM_GET_SEED_NONBLOCK | ESDM_GET_SEED_FULLY_SEEDED);
	if (rc < 0) {
		printf("esdm_get_seed returned an error for fully seeded request %zd\n",
		       rc);
		ret = 1;
		goto out;
	}

	if (rc == 0) {
		printf("esdm_get_seed was unable to produce entropy\n");
		ret = 77;
		goto out;
	}

	if (buf[1] < (force_fips ? 256 : 128)) {
		printf("esdm_get_seed returned insufficient seed: %" PRIu64
		       "\n",
		       buf[1]);
		ret = 1;
		goto out;
	} else {
		printf("esdm_get_seed returned proper seed size value %" PRIu64
		       " bytes and entropy value %" PRIu64 " bits\n",
		       buf[0], buf[1]);
	}

	ret = esdm_get_seed_failed_source_test(buf, buflen);

out:
	free(buf);
	esdm_fini();
	return ret;
}
