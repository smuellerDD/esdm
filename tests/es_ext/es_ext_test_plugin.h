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

#ifndef _ES_EXT_TEST_PLUGIN_H
#define _ES_EXT_TEST_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

/* The name it declares unless the test sets another one */
#define ES_EXT_TEST_NAME "es-ext-test"

/* No entropy rate declared */
#define ES_EXT_TEST_RATE_NONE UINT32_MAX

/*
 * What the test source does, set by the test, and what was asked of it.
 *
 * @claim_bits: Entropy claimed for a buffer; UINT32_MAX claims all its bits
 * @get_ret: Return value of get_entropy; the buffer is filled anyway
 * @status_text: What status_json writes, NULL for ES_EXT_TEST_STATUS
 * @status_unterminated: status_json fills its buffer without a NUL
 * @get_delay_ms: How long get_entropy takes
 * @name: The name the source declares - see es_ext_test_plugin.name
 * @entropy_rate: The rate the source declares, ES_EXT_TEST_RATE_NONE for none
 *
 * Atomic what a test changes or reads while a provider thread serves the
 * source; @init_ret, @name and @entropy_rate are taken by the init.
 */
struct esdm_es_ext_test_control {
	_Atomic uint32_t claim_bits;
	int init_ret;
	_Atomic int get_ret;
	_Atomic int selftest_ret;
	_Atomic int status_ret;
	const char *_Atomic status_text;
	_Atomic int status_unterminated;
	_Atomic unsigned int get_delay_ms;
	char name[64];
	uint32_t entropy_rate;

	_Atomic unsigned int init_calls;
	_Atomic unsigned int fini_calls;
	_Atomic unsigned int get_calls;
	_Atomic unsigned int selftest_calls;
	_Atomic unsigned int status_calls;
	_Atomic size_t last_buflen;
	_Atomic size_t last_status_buflen;
};

extern struct esdm_es_ext_test_control esdm_es_ext_test_control;

/* Not const: a test sets the name it declares, NULL for none */
extern struct esdm_es_ext_plugin es_ext_test_plugin;

/*
 * The settings of a provider program of the test, which the source reads in
 * its init: init_ret=N;rate=N;name=NAME - an empty NAME declares none.
 */
#define ES_EXT_TEST_PLUGIN_ENV "ESDM_ES_EXT_TEST_PLUGIN"

/* The status of the test source unless the test sets another one */
#define ES_EXT_TEST_STATUS "{\"plugin\":\"es-ext-test\",\"healthy\":true}"

#endif /* _ES_EXT_TEST_PLUGIN_H */
