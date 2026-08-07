/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * Test of the TPM 2.0 entropy source.
 *
 * The source talks the TPM command protocol over the resource manager device
 * itself rather than through a library, so what is worth checking is on both
 * sides of the device being there:
 *
 * - Without a TPM the source must disable itself and stay harmless: every
 *   callback safe to call, no entropy claimed, no crash. That half runs
 *   everywhere and is what keeps the source from breaking a machine that has
 *   no TPM.
 *
 * - With a TPM, the command exchange, the response parsing, the chunking of a
 *   request across the 32 byte maximum of TPM2_CC_GetRandom, the entropy
 *   accounting and the block cache in front of it are all reachable and are
 *   driven here. A software TPM is enough for that, which is what the VM based
 *   runs of this suite provide.
 *
 * Whether a TPM is present is asked of the source itself: ->active() reports
 * whether init() got the device open, which is exactly the distinction the two
 * halves below need.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "helper.h"

#define ES_IDX esdm_ext_es_tpm2
#define ES_NAME "tpm2"

static int es_tpm2_name(void)
{
	const char *name = esdm_es[ES_IDX]->name;

	if (!name) {
		printf("ES %s - fail: name not set!\n", ES_NAME);
		return 1;
	}
	printf("ES %s - pass: name: %s\n", ES_NAME, name);
	return 0;
}

static int es_tpm2_state(void)
{
	char buf[512];

	/* state is optional; nothing to check if absent */
	if (!esdm_es[ES_IDX]->state)
		return 0;

	memset(buf, 0, sizeof(buf));
	esdm_es[ES_IDX]->state(buf, sizeof(buf));
	if (!strstr(buf, "Available entropy")) {
		printf("ES %s - fail: state string malformed: %s\n", ES_NAME,
		       buf);
		return 1;
	}
	printf("ES %s - pass: state:\n%s\n", ES_NAME, buf);
	return 0;
}

static int es_tpm2_poolsize(void)
{
	uint32_t maxe, curr;

	if (!esdm_es[ES_IDX]->max_entropy || !esdm_es[ES_IDX]->curr_entropy)
		return 0;

	/*
	 * Both may legitimately be 0 when the device is absent. The invariant
	 * that must hold either way is that max_entropy() agrees with
	 * curr_entropy() evaluated at the security strength.
	 */
	maxe = esdm_es[ES_IDX]->max_entropy();
	curr = esdm_es[ES_IDX]->curr_entropy(esdm_security_strength());
	if (maxe != curr) {
		printf("ES %s - fail: max_entropy (%u) inconsistent with curr_entropy (%u)\n",
		       ES_NAME, maxe, curr);
		return 1;
	}
	printf("ES %s - pass: entropy accounting consistent (%u bits)\n",
	       ES_NAME, maxe);
	return 0;
}

static int es_tpm2_getdata(void)
{
	struct entropy_es eb_es;

	if (!esdm_es[ES_IDX]->get_ent)
		return 0;

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	/*
	 * With no device present, get_ent must gracefully return 0 credited
	 * bits rather than crash or over-credit. When a device IS present it
	 * may return up to the requested amount.
	 */
	if (eb_es.e_bits > ESDM_DRNG_INIT_SEED_SIZE_BITS) {
		printf("ES %s - fail: get_ent over-credited entropy: %u bits\n",
		       ES_NAME, eb_es.e_bits);
		return 1;
	}
	printf("ES %s - pass: get_ent returned %u bits (device %s)\n", ES_NAME,
	       eb_es.e_bits, eb_es.e_bits ? "present" : "absent");
	return 0;
}

static bool buf_is_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return false;
	}

	return true;
}

/*
 * init() is called again on every esdm_reinit(), so it has to be repeatable:
 * it closes the device it holds before opening it anew, and resets rather than
 * reallocates the block cache. Leaking the descriptor or losing the cache here
 * would only show up after a reinit in a long running daemon.
 */
static int es_tpm2_reinit(void)
{
	bool before = esdm_es[ES_IDX]->active();
	int ret;

	ret = esdm_es[ES_IDX]->init();
	if (ret) {
		printf("ES %s - fail: repeated init failed: %d\n", ES_NAME,
		       ret);
		return 1;
	}

	if (esdm_es[ES_IDX]->active() != before) {
		printf("ES %s - fail: repeated init changed the source from %s to %s\n",
		       ES_NAME, before ? "active" : "inactive",
		       before ? "inactive" : "active");
		return 1;
	}
	printf("ES %s - pass: init is repeatable\n", ES_NAME);
	return 0;
}

/*
 * The configured rate is what the delivered data is credited with; it says
 * nothing about whether there is data. A rate of 0 is a legitimate
 * configuration - it is what the ESDM package defaults several sources to - and
 * must still yield a full buffer.
 */
static int es_tpm2_getdata_rate(uint32_t rate)
{
	struct entropy_es eb_es;
	uint32_t expected = esdm_fast_noise_entropylevel(
		rate, ESDM_DRNG_INIT_SEED_SIZE_BITS);

	esdm_config_es_tpm2_entropy_rate_set(rate);

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	if (eb_es.e_bits != expected) {
		printf("ES %s - fail: rate %u credited %u bits, expected %u\n",
		       ES_NAME, rate, eb_es.e_bits, expected);
		return 1;
	}

	if (buf_is_zero(eb_es.e, ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
		printf("ES %s - fail: rate %u delivered no data\n", ES_NAME,
		       rate);
		return 1;
	}
	printf("ES %s - pass: rate %u credited %u bits and delivered data\n",
	       ES_NAME, rate, eb_es.e_bits);
	return 0;
}

/*
 * TPM2_CC_GetRandom is answered 32 bytes at a time, so anything larger is
 * assembled from several exchanges. Ask for both a single-command amount and
 * the seed size the ES manager uses, and require that a repeat of either comes
 * back different - a response parser that returned the same buffer twice, or
 * one that left the tail of a chunked request untouched, would otherwise pass.
 */
static int es_tpm2_getdata_chunked(void)
{
	static const uint32_t sizes[] = { 256, ESDM_DRNG_INIT_SEED_SIZE_BITS };
	unsigned int i;
	int ret = 0;

	esdm_config_es_tpm2_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		struct entropy_es first, second;
		uint32_t bytes = sizes[i] >> 3;

		/* The two coincide in a build without oversampling. */
		if (i && sizes[i] == sizes[i - 1])
			continue;

		memset(&first, 0, sizeof(first));
		memset(&second, 0, sizeof(second));

		esdm_es[ES_IDX]->get_ent(&first, sizes[i], true);
		esdm_es[ES_IDX]->get_ent(&second, sizes[i], true);

		if (buf_is_zero(first.e, bytes) ||
		    buf_is_zero(second.e, bytes)) {
			printf("ES %s - fail: request of %u bits delivered no data\n",
			       ES_NAME, sizes[i]);
			ret++;
			continue;
		}

		if (!memcmp(first.e, second.e, bytes)) {
			printf("ES %s - fail: two requests of %u bits returned identical data\n",
			       ES_NAME, sizes[i]);
			ret++;
			continue;
		}
		printf("ES %s - pass: %u bits delivered in %u command(s), data differs between pulls\n",
		       ES_NAME, sizes[i], (bytes + 31) / 32);
	}

	return ret;
}

/*
 * The cache in front of the device, filled by the ES manager monitor so a
 * consumer does not wait for the TPM. The first monitor run after an init is
 * skipped by design to keep ESDM startup responsive, so it takes two to fill
 * anything - and a request served from a filled cache must be credited and
 * populated exactly as the synchronous path is.
 */
static int es_tpm2_buffered(void)
{
	struct entropy_es eb_es;
	uint32_t expected;
	int ret;

	if (!esdm_es[ES_IDX]->monitor_es) {
		printf("ES %s: built without a block cache, monitor not tested\n",
		       ES_NAME);
		return 0;
	}

	esdm_config_es_tpm2_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	/* Skipped run */
	ret = esdm_es[ES_IDX]->monitor_es();
	if (ret) {
		printf("ES %s - fail: first monitor run returned %d\n", ES_NAME,
		       ret);
		return 1;
	}

	/* Filling run */
	ret = esdm_es[ES_IDX]->monitor_es();
	if (ret) {
		printf("ES %s - fail: monitor run returned %d\n", ES_NAME, ret);
		return 1;
	}

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	expected =
		esdm_fast_noise_entropylevel(esdm_config_es_tpm2_entropy_rate(),
					     ESDM_DRNG_INIT_SEED_SIZE_BITS);
	if (eb_es.e_bits != expected) {
		printf("ES %s - fail: cached block credited %u bits, expected %u\n",
		       ES_NAME, eb_es.e_bits, expected);
		return 1;
	}

	if (buf_is_zero(eb_es.e, ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
		printf("ES %s - fail: cached block carries no data\n", ES_NAME);
		return 1;
	}
	printf("ES %s - pass: block cache filled and served\n", ES_NAME);
	return 0;
}

/*
 * After fini() the device is gone as far as the source is concerned, and it has
 * to behave like a machine that never had one: no entropy claimed, no data
 * delivered, no use of the closed descriptor. This is the state the ES manager
 * leaves the source in while a reinit is in flight, and the only way the
 * absent-device paths are reached on a machine that does have a TPM.
 */
static int es_tpm2_absent_after_fini(void)
{
	struct entropy_es eb_es;
	char buf[512];
	int ret = 0;

	esdm_config_es_tpm2_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_es[ES_IDX]->fini();

	if (esdm_es[ES_IDX]->active()) {
		printf("ES %s - fail: source still active after fini\n",
		       ES_NAME);
		ret++;
	}

	if (esdm_es[ES_IDX]->max_entropy()) {
		printf("ES %s - fail: source claims %u bits after fini\n",
		       ES_NAME, esdm_es[ES_IDX]->max_entropy());
		ret++;
	}

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[ES_IDX]->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	if (eb_es.e_bits) {
		printf("ES %s - fail: get_ent credited %u bits after fini\n",
		       ES_NAME, eb_es.e_bits);
		ret++;
	}

	memset(buf, 0, sizeof(buf));
	esdm_es[ES_IDX]->state(buf, sizeof(buf));
	if (!strstr(buf, "Available entropy: 0")) {
		printf("ES %s - fail: state after fini does not report an empty source:\n%s\n",
		       ES_NAME, buf);
		ret++;
	}

	if (!ret)
		printf("ES %s - pass: source is inert after fini\n", ES_NAME);

	/* Hand the source back in the state it was found in. */
	if (esdm_es[ES_IDX]->init()) {
		printf("ES %s - fail: re-init after fini failed\n", ES_NAME);
		return ret + 1;
	}

	if (!esdm_es[ES_IDX]->active()) {
		printf("ES %s - fail: source did not recover from fini\n",
		       ES_NAME);
		return ret + 1;
	}
	printf("ES %s - pass: source recovers from fini\n", ES_NAME);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (esdm_es[ES_IDX]->init)
		/* init may fail when the device is absent - tolerate it */
		(void)esdm_es[ES_IDX]->init();

	ret += es_tpm2_name();
	ret += es_tpm2_state();
	ret += es_tpm2_poolsize();
	ret += es_tpm2_getdata();

	if (!esdm_es[ES_IDX]->active()) {
		printf("ES %s: no TPM on this machine, only the absent-device behaviour was tested\n",
		       ES_NAME);
		goto out;
	}

	ret += es_tpm2_reinit();
	ret += es_tpm2_getdata_rate(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	ret += es_tpm2_getdata_rate(ESDM_DRNG_SECURITY_STRENGTH_BITS / 2);
	ret += es_tpm2_getdata_rate(0);
	ret += es_tpm2_getdata_chunked();
	ret += es_tpm2_buffered();
	ret += es_tpm2_absent_after_fini();

out:
	if (esdm_es[ES_IDX]->fini)
		esdm_es[ES_IDX]->fini();

	return ret;
}
