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

#include <ctype.h>
#include <errno.h>
#include <json-c/json.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_config.h"
#include "esdm.h"
#include "esdm_es_aux.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_irq.h"
#include "esdm_es_mgr.h"
#include "esdm_es_jent.h"
#include "esdm_es_sched.h"
#include "esdm_info.h"
#include "esdm_logger.h"
#include "test_pertubation.h"
#include "visibility.h"

static unsigned int esdm_nodes = 1;

static inline size_t esdm_used_buf_len(char *buf, size_t buflen)
{
	size_t len = strlen(buf);

	return min_size(len, buflen);
}

void esdm_pool_inc_node_node(void)
{
	esdm_nodes++;
}

DSO_PUBLIC
void esdm_version(char *buf, size_t buflen)
{
	snprintf(buf, buflen, "%slibrary version: %s\n", TESTMODE_STR, VERSION);
}

DSO_PUBLIC
void esdm_status(char *buf, size_t buflen)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	size_t len;
	uint32_t i;

	if (!buf) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return;
	}

	snprintf(buf, buflen, "ESDM %slibrary version: %s\n", TESTMODE_STR,
		 VERSION);
	len = esdm_used_buf_len(buf, buflen);

	snprintf(buf + len, buflen - len,
		 "DRNG name: %s\n"
		 "ESDM security strength in bits: %d\n"
		 "Number of DRNG instances: %u\n"
		 "Standards compliance: %s%s%s%s%s%s\n"
		 "ESDM fully seeded: %s\n"
		 "ESDM entropy level: %u\n",
		 drng->drng_cb->drng_name(), esdm_security_strength(),
		 esdm_nodes, esdm_config_fips_enabled() ? "FIPS 140 " : "",
		 /* A DRG.4 build satisfies DRG.3 and reports both */
		 esdm_drg3_compliant() ? "DRG.3 " : "",
		 esdm_drg4_compliant() ? "DRG.4 " : "",
		 esdm_sp80090c_compliant() ? "SP800-90C " : "",
		 esdm_ntg1_compliant() ? "NTG.1(2011) " : "",
		 (esdm_ntg1_2024_compliant() || esdm_jent_ntg1()) ?
			 "NTG.1(2024)" :
			 "",
		 esdm_state_fully_seeded() ? "true" : "false",
		 esdm_avail_entropy());

	/* Concatenate the output of the entropy sources. */
	for_each_esdm_es (i) {
		len = esdm_used_buf_len(buf, buflen);
		snprintf(buf + len, buflen - len,
			 "Entropy Source %u properties:\n"
			 " Name: %s\n",
			 i, esdm_es[i]->name);

		len = esdm_used_buf_len(buf, buflen);
		esdm_es[i]->state(buf + len, buflen - len);
	}
}

/****************************** JSON status ***********************************/

/*
 * Turn a status label into a JSON member name: the label is lower-cased and
 * every run of non-alphanumeric characters becomes one underscore, e.g.
 * "Entropy Rate per 256 data bits" turns into "entropy_rate_per_256_data_bits".
 */
static void esdm_json_key(const char *label, char *key, size_t keylen)
{
	bool pending_sep = false;
	size_t used = 0;

	while (*label && used < keylen - 1) {
		unsigned char c = (unsigned char)*label++;

		if (!isalnum(c)) {
			pending_sep = true;
			continue;
		}

		if (pending_sep && used) {
			key[used++] = '_';
			if (used >= keylen - 1)
				break;
		}

		key[used++] = (char)tolower(c);
		pending_sep = false;
	}

	key[used] = '\0';
}

/*
 * Add a status value to an object: an integer or a boolean is added as such,
 * anything else as a string.
 */
static void esdm_json_add_value(struct json_object *obj, const char *key,
				const char *val)
{
	long long num;
	char *end;

	if (!strcmp(val, "true") || !strcmp(val, "false")) {
		json_object_object_add(
			obj, key,
			json_object_new_boolean(!strcmp(val, "true")));
		return;
	}

	errno = 0;
	num = strtoll(val, &end, 10);
	if (!errno && end != val && !*end) {
		json_object_object_add(obj, key, json_object_new_int64(num));
		return;
	}

	json_object_object_add(obj, key, json_object_new_string(val));
}

/*
 * Add the members an entropy source renders itself. Used by the sources whose
 * state lives outside this process (the kernel add-on returns a JSON object
 * through its status IOCTL), so that no status text has to be parsed.
 *
 * Returns true when the object was consumed.
 */
static bool esdm_json_es_state_native(struct json_object *es_obj, uint32_t es)
{
	char state[1024] = { 0 };
	struct json_object *obj;
	bool consumed = false;

	if (!esdm_es[es]->state_json)
		return false;

	esdm_es[es]->state_json(state, sizeof(state));

	/*
	 * A source that cannot render its state (e.g. a truncated or otherwise
	 * malformed document) falls back to the status text below rather than
	 * corrupting the status document.
	 */
	obj = json_tokener_parse(state);
	if (!obj)
		return false;

	if (json_object_is_type(obj, json_type_object)) {
		json_object_object_foreach(obj, key, val)
		{
			json_object_object_add(es_obj, key,
					       json_object_get(val));
		}
		consumed = true;
	}

	json_object_put(obj);

	return consumed;
}

/*
 * Turn the status text of one entropy source into JSON members: its lines are
 * of the shape " Label: value", which become "label": value.
 */
static void esdm_json_es_state(struct json_object *es_obj, uint32_t es)
{
	char state[1024] = { 0 };
	char *line, *saveptr = NULL;

	if (esdm_json_es_state_native(es_obj, es))
		return;

	esdm_es[es]->state(state, sizeof(state));

	for (line = strtok_r(state, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		char key[128];
		char *val = strchr(line, ':');

		/* Lines without a label (e.g. an error report) carry no member */
		if (!val)
			continue;

		*val++ = '\0';
		while (*line == ' ' || *line == '\t')
			line++;
		while (*val == ' ' || *val == '\t')
			val++;

		esdm_json_key(line, key, sizeof(key));
		if (!key[0])
			continue;

		esdm_json_add_value(es_obj, key, val);
	}
}

DSO_PUBLIC
void esdm_status_json(char *buf, size_t buflen)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct json_object *root, *compliance, *sources;
	const char *doc;
	uint32_t i;

	if (!buf || !buflen) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return;
	}
	buf[0] = '\0';

	root = json_object_new_object();
	compliance = json_object_new_array();
	sources = json_object_new_array();
	if (!root || !compliance || !sources) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		goto out;
	}

	json_object_object_add(root, "library_version",
			       json_object_new_string(VERSION));
	json_object_object_add(root, "test_mode",
			       json_object_new_boolean(sizeof(TESTMODE_STR) >
						       1));
	json_object_object_add(
		root, "drng_name",
		json_object_new_string(drng->drng_cb->drng_name()));
	json_object_object_add(root, "security_strength_bits",
			       json_object_new_int64(esdm_security_strength()));
	json_object_object_add(root, "drng_instances",
			       json_object_new_int64(esdm_nodes));

	if (esdm_config_fips_enabled())
		json_object_array_add(compliance,
				      json_object_new_string("FIPS 140"));
	/* A DRG.4 build satisfies DRG.3 and reports both */
	if (esdm_drg3_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("DRG.3"));
	if (esdm_drg4_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("DRG.4"));
	if (esdm_sp80090c_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("SP800-90C"));
	if (esdm_ntg1_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("NTG.1(2011)"));
	if (esdm_ntg1_2024_compliant() || esdm_jent_ntg1())
		json_object_array_add(compliance,
				      json_object_new_string("NTG.1(2024)"));
	json_object_object_add(root, "standards_compliance", compliance);
	compliance = NULL;

	json_object_object_add(
		root, "fully_seeded",
		json_object_new_boolean(esdm_state_fully_seeded()));
	json_object_object_add(root, "entropy_level_bits",
			       json_object_new_int64(esdm_avail_entropy()));

	for_each_esdm_es (i) {
		struct json_object *es_obj = json_object_new_object();

		if (!es_obj)
			continue;

		json_object_object_add(es_obj, "id",
				       json_object_new_int((int32_t)i));
		json_object_object_add(
			es_obj, "name",
			json_object_new_string(esdm_es[i]->name));
		esdm_json_es_state(es_obj, i);
		json_object_array_add(sources, es_obj);
	}
	json_object_object_add(root, "entropy_sources", sources);
	sources = NULL;

	/*
	 * The document is truncated if it does not fit into the caller's
	 * buffer - as with the plain status text, and detectable by the
	 * consumer as the JSON is then incomplete.
	 */
	doc = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
	if (doc)
		snprintf(buf, buflen, "%s\n", doc);

out:
	json_object_put(root);
	json_object_put(compliance);
	json_object_put(sources);
}

DSO_PUBLIC
void esdm_status_machine(struct esdm_status_st *status)
{
	status->es_irq_enabled = esdm_irq_enabled();
	status->es_sched_enabled = esdm_sched_enabled();
}
