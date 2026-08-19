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
#include "esdm_logger.h"
#include "esdm_selftest.h"
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

/* Rendering state of the DRNG section of the status text */
struct esdm_drng_txt_state {
	char *buf;
	size_t buflen;
	uint32_t idx;
};

/* Render the statistics of one DRNG instance into the status text */
static void esdm_drng_status_txt(const struct esdm_drng_stats *stats,
				 void *priv)
{
	struct esdm_drng_txt_state *txt = priv;
	size_t len = esdm_used_buf_len(txt->buf, txt->buflen);
	char node[16] = "";
	char stamp[32] = "";
	char reseed[32] = "";

	/*
	 * A value the DRNG does not have - the node of the DRNG that is not
	 * bound to one, the seeding time of one that was never seeded - is
	 * reported as N/A.
	 */
	if (stats->node_valid)
		snprintf(node, sizeof(node), "%u", stats->node);
	if (stats->seeded_wtime_valid)
		esdm_time_str(stats->seeded_wtime, stamp, sizeof(stamp));
	if (stats->seeded_time_valid)
		snprintf(reseed, sizeof(reseed), "%lld",
			 stats->seconds_since_reseed);

	if (!node[0])
		snprintf(node, sizeof(node), "N/A");
	if (!stamp[0])
		snprintf(stamp, sizeof(stamp), "N/A");
	if (!reseed[0])
		snprintf(reseed, sizeof(reseed), "N/A");

	snprintf(txt->buf + len, txt->buflen - len,
		 "DRNG instance %u properties:\n"
		 " Type: %s\n"
		 " Node: %s\n"
		 " Name: %s\n"
		 " Fully seeded: %s\n"
		 " Initiated: %s\n"
		 " Force reseed: %s\n"
		 " Reseed pending: %s\n"
		 " Requests until reseed: %d\n"
		 " Seconds until reseed: %lld\n"
		 " Requests since fully seeded: %u\n"
		 " Generated bits since fully seeded: %u\n"
		 " Seed generation: %lld\n"
		 " Last seeding time: %s\n"
		 " Seconds since last reseed: %s\n",
		 txt->idx++, stats->type, node,
		 stats->drng_name ? stats->drng_name : "N/A",
		 stats->fully_seeded ? "true" : "false",
		 stats->initiated ? "true" : "false",
		 stats->force_reseed ? "true" : "false",
		 stats->reseed_pending ? "true" : "false",
		 stats->requests_until_reseed, stats->seconds_until_reseed,
		 stats->requests_since_fully_seeded,
		 stats->bits_since_fully_seeded, stats->seed_generation, stamp,
		 reseed);
}

DSO_PUBLIC
int esdm_status(char *buf, size_t buflen)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	size_t len;
	struct esdm_drng_txt_state txt;
	uint32_t i;

	if (!buf || !buflen) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return -EINVAL;
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

	/* The initial and the prediction resistance DRNG only. */
	txt.buf = buf;
	txt.buflen = buflen;
	txt.idx = 0;
	esdm_drng_stats_summary(esdm_drng_status_txt, &txt);

	/*
	 * The thread that reseeds the DRNGs before a request runs into their
	 * reseed condition.
	 */
	len = esdm_used_buf_len(buf, buflen);
	snprintf(buf + len, buflen - len,
		 "Reseed worker properties:\n"
		 " Running: %s\n"
		 " Reseed interval in seconds: %u\n",
		 esdm_drng_mgr_reseed_worker_running() ? "true" : "false",
		 esdm_get_reseed_max_time());

	/*
	 * The self tests of the hash and the DRNG implementation and of the
	 * entropy sources.
	 */
	len = esdm_used_buf_len(buf, buflen);
	snprintf(buf + len, buflen - len,
		 "Periodic self test properties:\n"
		 " State: %s\n"
		 " Running: %s\n"
		 " Completed self tests: %lld\n"
		 " Self test interval in seconds: %u\n"
		 " Entropy source state: %s\n"
		 " Entropy sources tested: %u\n"
		 " Entropy sources failed: %u\n",
		 esdm_selftest_crypto_state_name(),
		 esdm_selftest_periodic_running() ? "true" : "false",
		 esdm_selftest_passes(), esdm_selftest_periodic_interval(),
		 esdm_selftest_es_state_name(), esdm_selftest_es_sources(),
		 esdm_selftest_es_failures());

	/*
	 * Every section above appends with snprintf(), which stops where the
	 * buffer ends.
	 */
	if (esdm_used_buf_len(buf, buflen) + 1 >= buflen) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"Status report does not fit into the buffer of %zu bytes\n",
			buflen);
		return -EMSGSIZE;
	}

	return 0;
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
	json_object_object_add(obj, "reseed_pending",
			       json_object_new_boolean(stats->reseed_pending));
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

DSO_PUBLIC
int esdm_status_json(char *buf, size_t buflen)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct json_object *root, *compliance, *sources, *drngs, *worker,
		*selftest;
	int ret = -ENOMEM;
	uint32_t i;

	if (!buf || !buflen) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return -EINVAL;
	}
	buf[0] = '\0';

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

	/* The initial and the prediction resistance DRNG - see esdm_status() */
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

	ret = esdm_json_write(
		json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY),
		buf, buflen);

out:
	json_object_put(root);
	json_object_put(compliance);
	json_object_put(sources);
	json_object_put(drngs);
	json_object_put(worker);
	json_object_put(selftest);

	return ret;
}

DSO_PUBLIC
void esdm_status_machine(struct esdm_status_st *status)
{
	status->es_irq_enabled = esdm_irq_enabled();
	status->es_sched_enabled = esdm_sched_enabled();
}
