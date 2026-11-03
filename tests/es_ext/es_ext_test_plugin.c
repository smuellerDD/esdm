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
 * An external entropy source for the tests, steered through
 * esdm_es_ext_test_control. Its data is a counter, one byte value per call, so
 * that a test can tell which call delivered a buffer.
 *
 * Compiled into a test serving it in process, or - ES_EXT_TEST_PROVIDER -
 * into a provider program, steered through ES_EXT_TEST_PLUGIN_ENV.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "es_ext_test_plugin.h"
#include "es_ext_test_util.h"
#include "esdm_es_ext.h"

struct esdm_es_ext_test_control esdm_es_ext_test_control = {
	.claim_bits = UINT32_MAX,
	.name = ES_EXT_TEST_NAME,
	.entropy_rate = ES_EXT_TEST_RATE_NONE,
};

static void es_ext_test_env(struct esdm_es_ext_test_control *ctl)
{
	const char *env = getenv(ES_EXT_TEST_PLUGIN_ENV);
	char settings[256], *s, *val, *save = NULL;

	snprintf(settings, sizeof(settings), "%s", env ? env : "");
	for (s = strtok_r(settings, ";", &save); s;
	     s = strtok_r(NULL, ";", &save)) {
		val = strchr(s, '=');
		if (!val)
			continue;
		*val++ = '\0';
		if (!strcmp(s, "name")) {
			snprintf(ctl->name, sizeof(ctl->name), "%s", val);
			es_ext_test_plugin.name = val[0] ? ctl->name : NULL;
		} else if (!strcmp(s, "init_ret")) {
			ctl->init_ret = atoi(val);
		} else if (!strcmp(s, "rate")) {
			ctl->entropy_rate = (uint32_t)strtoul(val, NULL, 0);
		}
	}
}

static uint32_t es_ext_test_entropy_rate(void *ctx)
{
	return ((struct esdm_es_ext_test_control *)ctx)->entropy_rate;
}

static int es_ext_test_init(void **ctx)
{
	struct esdm_es_ext_test_control *ctl = &esdm_es_ext_test_control;

	es_ext_test_env(ctl);
	ctl->init_calls++;
	*ctx = ctl;

	return ctl->init_ret;
}

static void es_ext_test_fini(void *ctx)
{
	struct esdm_es_ext_test_control *ctl = ctx;

	ctl->fini_calls++;
}

static int es_ext_test_get_entropy(void *ctx, uint8_t *buf, size_t buflen,
				   uint32_t *entropy_bits)
{
	struct esdm_es_ext_test_control *ctl = ctx;
	unsigned int calls = ++ctl->get_calls;
	uint32_t claim;
	int ret;

	ctl->last_buflen = buflen;
	es_ext_test_sleep_ms(ctl->get_delay_ms);

	/* Filled in any case, so that a test sees whether the data is wiped */
	memset(buf, (int)(calls & 0xff), buflen);

	ret = ctl->get_ret;
	if (ret)
		return ret;

	claim = ctl->claim_bits;
	*entropy_bits = claim == UINT32_MAX ? (uint32_t)buflen * 8 : claim;
	return 0;
}

static int es_ext_test_selftest(void *ctx)
{
	struct esdm_es_ext_test_control *ctl = ctx;

	ctl->selftest_calls++;
	return ctl->selftest_ret;
}

static int es_ext_test_status_json(void *ctx, char *buf, size_t buflen)
{
	struct esdm_es_ext_test_control *ctl = ctx;
	const char *text;
	int len, ret;

	ctl->status_calls++;
	ctl->last_status_buflen = buflen;

	if (ctl->status_unterminated) {
		memset(buf, '{', buflen);
		return 0;
	}

	ret = ctl->status_ret;
	if (ret)
		return ret;

	text = ctl->status_text;
	len = snprintf(buf, buflen, "%s", text ? text : ES_EXT_TEST_STATUS);
	return len >= 0 && (size_t)len < buflen ? 0 : -EMSGSIZE;
}

struct esdm_es_ext_plugin es_ext_test_plugin = {
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.name = esdm_es_ext_test_control.name,
	.init = es_ext_test_init,
	.fini = es_ext_test_fini,
	.get_entropy = es_ext_test_get_entropy,
	.selftest = es_ext_test_selftest,
	.status_json = es_ext_test_status_json,
	.entropy_rate = es_ext_test_entropy_rate,
};

#ifdef ES_EXT_TEST_PROVIDER
int main(int argc, char *argv[])
{
	return esdm_es_ext_provider_main(&es_ext_test_plugin, argc, argv);
}
#endif
