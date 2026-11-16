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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esdm_config.h"
#include "esdm.h"
#include "esdm_es_aux.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_irq.h"
#include "esdm_es_mgr.h"
#include "esdm_es_jent.h"
#include "esdm_es_sched.h"
#include "esdm_info.h"
#include "helper.h"
#include "esdm_logger.h"
#include "esdm_selftest.h"
#include "test_pertubation.h"
#include "visibility.h"

static unsigned int esdm_nodes = 1;

void esdm_pool_inc_node_node(void)
{
	esdm_nodes++;
}

DSO_PUBLIC
void esdm_version(char *buf, size_t buflen)
{
	snprintf(buf, buflen, "%slibrary version: %s\n", TESTMODE_STR, VERSION);
}

/*
 * Render a wall clock time given in seconds since the epoch as an ISO 8601
 * timestamp in UTC.
 */
static void esdm_time_str(long long wtime, char *buf, size_t buflen)
{
	time_t t = (time_t)wtime;
	struct tm tm;

	buf[0] = '\0';

	if (!gmtime_r(&t, &tm))
		return;

	if (!strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tm))
		buf[0] = '\0';
}

/****************************** JSON status ***********************************/

/* The state of one ES, with room for the status of an external provider */
#define ESDM_ES_STATE_BUFLEN 4096

/* Add the members of the JSON state of entropy source @es to @es_obj */
static void esdm_json_es_state(struct json_object *es_obj, uint32_t es)
{
	char state[ESDM_ES_STATE_BUFLEN] = { 0 };
	struct json_object *obj;

	esdm_es[es]->state_json(state, sizeof(state));

	/* A state that did not fit, or is no object, adds no members */
	obj = json_tokener_parse(state);
	if (json_object_is_type(obj, json_type_object)) {
		json_object_object_foreach(obj, key, val)
		{
			json_object_object_add(es_obj, key,
					       json_object_get(val));
		}
	}

	json_object_put(obj);
}

/* Render the statistics of one DRNG instance as a JSON object. */
static struct json_object *
esdm_drng_status_obj(const struct esdm_drng_stats *stats)
{
	struct json_object *obj = json_object_new_object();
	char stamp[32] = "";

	if (!obj)
		return NULL;

	json_object_object_add(obj, "type",
			       json_object_new_string(stats->type));
	/*
	 * Every member is present on every DRNG: one the DRNG does not have -
	 * the node of the DRNG that is not bound to one, the seeding time of
	 * one that was never seeded - is reported as null rather than left out,
	 * so a consumer can address it without checking for its existence.
	 */
	json_object_object_add(
		obj, "node",
		stats->node_valid ? json_object_new_int((int32_t)stats->node) :
				    NULL);
	/* A DRNG that is not allocated yet has no name to report */
	json_object_object_add(
		obj, "name",
		stats->drng_name ? json_object_new_string(stats->drng_name) :
				   NULL);
	json_object_object_add(obj, "fully_seeded",
			       json_object_new_boolean(stats->fully_seeded));
	json_object_object_add(obj, "initiated",
			       json_object_new_boolean(stats->initiated));
	json_object_object_add(obj, "force_reseed",
			       json_object_new_boolean(stats->force_reseed));
	json_object_object_add(
		obj, "requests_until_reseed",
		json_object_new_int64(stats->requests_until_reseed));
	json_object_object_add(
		obj, "seconds_until_reseed",
		json_object_new_int64(stats->seconds_until_reseed));
	json_object_object_add(
		obj, "requests_since_fully_seeded",
		json_object_new_int64(stats->requests_since_fully_seeded));
	json_object_object_add(
		obj, "generated_bits_since_fully_seeded",
		json_object_new_int64(stats->bits_since_fully_seeded));
	json_object_object_add(obj, "seed_generation",
			       json_object_new_int64(stats->seed_generation));
	if (stats->seeded_wtime_valid)
		esdm_time_str(stats->seeded_wtime, stamp, sizeof(stamp));
	json_object_object_add(obj, "last_seeding_time",
			       stamp[0] ? json_object_new_string(stamp) : NULL);
	json_object_object_add(
		obj, "seconds_since_last_reseed",
		stats->seeded_time_valid ?
			json_object_new_int64(stats->seconds_since_reseed) :
			NULL);

	return obj;
}

/* Render one DRNG instance as an object of the "drngs" array */
static void esdm_drng_status_json(const struct esdm_drng_stats *stats,
				  void *priv)
{
	struct json_object *drngs = priv;
	struct json_object *obj = esdm_drng_status_obj(stats);

	if (obj)
		json_object_array_add(drngs, obj);
}

/* Collect the object of a single DRNG instance for the caller */
static void esdm_drng_status_json_one(const struct esdm_drng_stats *stats,
				      void *priv)
{
	struct json_object **out = priv;

	*out = esdm_drng_status_obj(stats);
}

/* Serialize the object of a single DRNG instance into the caller's buffer. */
static int esdm_json_write(const char *doc, char *buf, size_t buflen)
{
	int len;

	if (!doc)
		return -ENOMEM;

	len = snprintf(buf, buflen, "%s\n", doc);
	if (len < 0)
		return -EFAULT;

	/*
	 * A JSON document that is cut in half is not a JSON document at all,
	 * and a consumer that is handed one has no way to tell that from a
	 * document the ESDM meant to send.
	 */
	if ((size_t)len >= buflen) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"Status document of %d bytes does not fit into the buffer of %zu bytes\n",
			len + 1, buflen);
		buf[0] = '\0';
		return -EMSGSIZE;
	}

	return 0;
}

static int esdm_drng_status_json_write(struct json_object *obj, char *buf,
				       size_t buflen)
{
	int ret;

	if (!obj)
		return -ENOMEM;

	ret = esdm_json_write(
		json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN),
		buf, buflen);

	json_object_put(obj);
	return ret;
}

DSO_PUBLIC
int esdm_status_drng_json(uint32_t node, char *buf, size_t buflen)
{
	struct json_object *obj = NULL;
	int ret;

	if (!buf || !buflen)
		return -EINVAL;

	buf[0] = '\0';

	ret = esdm_drng_stats_node(node, esdm_drng_status_json_one, &obj);
	if (ret)
		return ret;

	return esdm_drng_status_json_write(obj, buf, buflen);
}

DSO_PUBLIC
int esdm_status_drng_pr_json(char *buf, size_t buflen)
{
	struct json_object *obj = NULL;

	if (!buf || !buflen)
		return -EINVAL;

	buf[0] = '\0';

	esdm_drng_stats_pr(esdm_drng_status_json_one, &obj);

	return esdm_drng_status_json_write(obj, buf, buflen);
}

/* The status document, NULL when it cannot be created */
static struct json_object *esdm_status_obj(void)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct json_object *root, *compliance, *sources, *drngs, *worker,
		*selftest;
	uint32_t i;

	root = json_object_new_object();
	compliance = json_object_new_array();
	sources = json_object_new_array();
	drngs = json_object_new_array();
	worker = json_object_new_object();
	selftest = json_object_new_object();
	if (!root || !compliance || !sources || !drngs || !worker ||
	    !selftest) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		json_object_put(root);
		root = NULL;
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

	/* The initial and the prediction resistance DRNG only */
	esdm_drng_stats_summary(esdm_drng_status_json, drngs);
	json_object_object_add(root, "drngs", drngs);
	drngs = NULL;

	json_object_object_add(
		worker, "running",
		json_object_new_boolean(esdm_drng_mgr_reseed_worker_running()));
	json_object_object_add(
		worker, "reseed_interval_seconds",
		json_object_new_int64(esdm_get_reseed_max_time()));
	json_object_object_add(root, "reseed_worker", worker);
	worker = NULL;

	json_object_object_add(
		selftest, "state",
		json_object_new_string(esdm_selftest_crypto_state_name()));
	json_object_object_add(
		selftest, "running",
		json_object_new_boolean(esdm_selftest_periodic_running()));
	json_object_object_add(selftest, "completed_self_tests",
			       json_object_new_int64(esdm_selftest_passes()));
	json_object_object_add(
		selftest, "self_test_interval_seconds",
		json_object_new_int64(esdm_selftest_periodic_interval()));
	json_object_object_add(
		selftest, "entropy_source_state",
		json_object_new_string(esdm_selftest_es_state_name()));
	json_object_object_add(
		selftest, "entropy_sources_tested",
		json_object_new_int64(esdm_selftest_es_sources()));
	json_object_object_add(
		selftest, "entropy_sources_failed",
		json_object_new_int64(esdm_selftest_es_failures()));
	json_object_object_add(root, "periodic_self_test", selftest);
	selftest = NULL;

out:
	json_object_put(compliance);
	json_object_put(sources);
	json_object_put(drngs);
	json_object_put(worker);
	json_object_put(selftest);

	return root;
}

DSO_PUBLIC
int esdm_status_json(char *buf, size_t buflen)
{
	struct json_object *root;
	int ret;

	if (!buf || !buflen) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return -EINVAL;
	}
	buf[0] = '\0';

	root = esdm_status_obj();
	if (!root)
		return -ENOMEM;

	ret = esdm_json_write(
		json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY),
		buf, buflen);
	json_object_put(root);

	return ret;
}

/****************************** Status text ***********************************/

/* Words of member names that a label spells as written here */
static const struct {
	const char *word;
	const char *label;
} esdm_status_words[] = {
	{ "cpu", "CPU" },     { "drbg", "DRBG" }, { "drng", "DRNG" },
	{ "drngs", "DRNGs" }, { "ebpf", "eBPF" }, { "fips", "FIPS" },
	{ "id", "ID" },	      { "rng", "RNG" },
};

struct esdm_status_txt {
	char *buf;
	size_t buflen;
	size_t len;
	bool overflow;
};

static void esdm_status_txt_add(struct esdm_status_txt *txt, const char *fmt,
				...) __attribute__((format(printf, 2, 3)));
static void esdm_status_txt_add(struct esdm_status_txt *txt, const char *fmt,
				...)
{
	va_list ap;
	int ret;

	if (txt->overflow)
		return;

	va_start(ap, fmt);
	ret = vsnprintf(txt->buf + txt->len, txt->buflen - txt->len, fmt, ap);
	va_end(ap);

	/* What did not fit stays cut off, as far as it got */
	if (ret < 0 || (size_t)ret >= txt->buflen - txt->len) {
		txt->overflow = true;
		return;
	}
	txt->len += (size_t)ret;
}

/* "fully_seeded" turns into "Fully seeded", "drng_name" into "DRNG name" */
static void esdm_status_label(const char *key, char *label, size_t labellen)
{
	bool first_spelled = false;
	size_t used = 0;

	label[0] = '\0';
	while (*key) {
		size_t wlen = strcspn(key, "_"), i;
		const char *word = NULL;
		int ret;

		for (i = 0; i < ARRAY_SIZE(esdm_status_words); i++) {
			if (!strncmp(key, esdm_status_words[i].word, wlen) &&
			    !esdm_status_words[i].word[wlen])
				word = esdm_status_words[i].label;
		}
		if (!used)
			first_spelled = word != NULL;

		if (word)
			ret = snprintf(label + used, labellen - used, "%s%s",
				       used ? " " : "", word);
		else
			ret = snprintf(label + used, labellen - used, "%s%.*s",
				       used ? " " : "", (int)wlen, key);
		if (ret < 0 || (size_t)ret >= labellen - used)
			break;
		used += (size_t)ret;

		key += wlen;
		if (*key)
			key++;
	}

	if (!first_spelled)
		label[0] = (char)toupper((unsigned char)label[0]);
}

static bool esdm_status_is_scalar(struct json_object *val)
{
	return !json_object_is_type(val, json_type_object) &&
	       !json_object_is_type(val, json_type_array);
}

/*
 * A scalar as text. A string with a control character is JSON-quoted, so that
 * no line break in it forges a line of the text.
 */
static const char *esdm_status_scalar(struct json_object *val)
{
	const char *str;

	if (!val)
		return "N/A";

	str = json_object_get_string(val);
	if (json_object_is_type(val, json_type_string)) {
		const unsigned char *c;

		for (c = (const unsigned char *)str; *c; c++) {
			if (*c < 0x20)
				return json_object_to_json_string_ext(
					val,
					JSON_C_TO_STRING_PLAIN |
						JSON_C_TO_STRING_NOSLASHESCAPE);
		}
	}

	return str;
}

static void esdm_status_txt_obj(struct esdm_status_txt *txt,
				struct json_object *obj, int depth,
				bool headed);

/*
 * Heading of an array element: "<name> (ID <id>)" for an object with an ID
 * (an entropy source), whose lines then omit both; the index otherwise.
 */
static bool esdm_status_heading(struct json_object *elem, size_t idx,
				char *head, size_t headlen)
{
	struct json_object *id, *name;

	if (!json_object_is_type(elem, json_type_object) ||
	    !json_object_object_get_ex(elem, "id", &id) ||
	    !esdm_status_is_scalar(id)) {
		snprintf(head, headlen, "%zu", idx);
		return false;
	}

	if (json_object_object_get_ex(elem, "name", &name) &&
	    esdm_status_is_scalar(name))
		snprintf(head, headlen, "%s (ID %s)",
			 esdm_status_scalar(name), esdm_status_scalar(id));
	else
		snprintf(head, headlen, "ID %s", esdm_status_scalar(id));

	return true;
}

static void esdm_status_txt_member(struct esdm_status_txt *txt,
				   const char *label, struct json_object *val,
				   int depth)
{
	size_t i, n;

	if (esdm_status_is_scalar(val)) {
		esdm_status_txt_add(txt, "%*s%s: %s\n", depth, "", label,
				    esdm_status_scalar(val));
		return;
	}

	if (json_object_is_type(val, json_type_object)) {
		esdm_status_txt_add(txt, "%*s%s:\n", depth, "", label);
		esdm_status_txt_obj(txt, val, depth + 1, false);
		return;
	}

	/* An array of scalars is one line, any other a block per element */
	n = json_object_array_length(val);
	for (i = 0; i < n; i++) {
		if (!esdm_status_is_scalar(json_object_array_get_idx(val, i)))
			break;
	}

	if (i == n) {
		esdm_status_txt_add(txt, "%*s%s: %s", depth, "", label,
				    n ? "" : "none");
		for (i = 0; i < n; i++) {
			esdm_status_txt_add(
				txt, "%s%s", i ? ", " : "",
				esdm_status_scalar(
					json_object_array_get_idx(val, i)));
		}
		esdm_status_txt_add(txt, "\n");
		return;
	}

	esdm_status_txt_add(txt, "%*s%s:\n", depth, "", label);
	for (i = 0; i < n; i++) {
		struct json_object *elem = json_object_array_get_idx(val, i);
		char head[160];

		if (esdm_status_heading(elem, i, head, sizeof(head))) {
			esdm_status_txt_add(txt, "%*s%s:\n", depth + 1, "",
					    head);
			esdm_status_txt_obj(txt, elem, depth + 2, true);
		} else {
			esdm_status_txt_member(txt, head, elem, depth + 1);
		}
	}
}

/* @headed: the ID and the name are in the heading, see esdm_status_heading() */
static void esdm_status_txt_obj(struct esdm_status_txt *txt,
				struct json_object *obj, int depth,
				bool headed)
{
	json_object_object_foreach(obj, key, val)
	{
		char label[128];

		if (headed && (!strcmp(key, "id") || !strcmp(key, "name")))
			continue;

		esdm_status_label(key, label, sizeof(label));
		esdm_status_txt_member(txt, label, val, depth);
	}
}

int esdm_status_text(struct json_object *doc, char *buf, size_t buflen)
{
	struct esdm_status_txt txt = { .buf = buf, .buflen = buflen };

	buf[0] = '\0';
	esdm_status_txt_obj(&txt, doc, 0, false);

	if (txt.overflow) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"Status report does not fit into the buffer of %zu bytes\n",
			buflen);
		return -EMSGSIZE;
	}

	return 0;
}

DSO_PUBLIC
int esdm_status(char *buf, size_t buflen)
{
	struct json_object *root;
	int ret;

	if (!buf || !buflen) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return -EINVAL;
	}
	buf[0] = '\0';

	root = esdm_status_obj();
	if (!root)
		return -ENOMEM;

	ret = esdm_status_text(root, buf, buflen);
	json_object_put(root);

	return ret;
}

DSO_PUBLIC
void esdm_status_machine(struct esdm_status_st *status)
{
	status->es_irq_enabled = esdm_irq_enabled();
	status->es_sched_enabled = esdm_sched_enabled();
}
