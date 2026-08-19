/*
 * Shared validation of the JSON status document (esdm_status_json /
 * esdm_rpcc_status_json) for the test suite: the document is parsed with
 * json-c and the mandatory members are checked for presence and type.
 *
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

#ifndef ESDM_TEST_STATUS_JSON_CHECK_H
#define ESDM_TEST_STATUS_JSON_CHECK_H

#include <json-c/json.h>
#include <stdio.h>
#include <string.h>

static inline int esdm_status_json_member(struct json_object *obj,
					  const char *key, json_type type)
{
	struct json_object *val;

	if (!json_object_object_get_ex(obj, key, &val)) {
		printf("JSON status: member \"%s\" is missing\n", key);
		return 1;
	}

	if (!json_object_is_type(val, type)) {
		printf("JSON status: member \"%s\" has type %s, expected %s\n",
		       key, json_type_to_name(json_object_get_type(val)),
		       json_type_to_name(type));
		return 1;
	}

	return 0;
}

/*
 * Like esdm_status_json_member(), but the member may also be null: the status
 * document reports a property a DRNG does not have as null instead of leaving
 * it out, so its presence is mandatory while its type is not.
 */
static inline int esdm_status_json_member_or_null(struct json_object *obj,
						  const char *key,
						  json_type type)
{
	struct json_object *val;

	if (!json_object_object_get_ex(obj, key, &val)) {
		printf("JSON status: member \"%s\" is missing\n", key);
		return 1;
	}

	if (json_object_is_type(val, json_type_null))
		return 0;

	return esdm_status_json_member(obj, key, type);
}

/*
 * Returns 0 if @drng is a well-formed DRNG instance object - the shape the
 * status document carries below "drngs" and esdm_status_drng_json() returns
 * on its own.
 */
static inline int esdm_status_json_drng(struct json_object *drng)
{
	struct json_object *generation;

	if (!json_object_is_type(drng, json_type_object)) {
		printf("JSON status: DRNG instance is no object\n");
		return 1;
	}

	if (esdm_status_json_member(drng, "type", json_type_string) ||
	    esdm_status_json_member(drng, "name", json_type_string) ||
	    esdm_status_json_member(drng, "fully_seeded", json_type_boolean) ||
	    esdm_status_json_member(drng, "requests_until_reseed",
				    json_type_int) ||
	    esdm_status_json_member(drng, "requests_since_fully_seeded",
				    json_type_int) ||
	    esdm_status_json_member(drng, "generated_bits_since_fully_seeded",
				    json_type_int) ||
	    esdm_status_json_member(drng, "seed_generation", json_type_int) ||
	    esdm_status_json_member_or_null(drng, "node", json_type_int) ||
	    esdm_status_json_member_or_null(drng, "last_seeding_time",
					    json_type_string) ||
	    esdm_status_json_member_or_null(drng, "seconds_since_last_reseed",
					    json_type_int))
		return 1;

	/* A DRNG that was seeded reports when that happened */
	json_object_object_get_ex(drng, "seed_generation", &generation);
	if (json_object_get_int64(generation) &&
	    esdm_status_json_member(drng, "last_seeding_time",
				    json_type_string))
		return 1;

	return 0;
}

/*
 * Returns 0 if @doc is the status of a single DRNG instance
 * (esdm_status_drng_json / esdm_rpcc_drng_status_json), 1 otherwise.
 */
static inline int esdm_status_drng_json_check(const char *doc)
{
	struct json_object *drng;
	int ret;

	drng = json_tokener_parse(doc);
	if (!drng) {
		printf("DRNG status is no JSON document: %s\n", doc);
		return 1;
	}

	ret = esdm_status_json_drng(drng);
	json_object_put(drng);

	return ret;
}

/* Returns 0 if the document is a well-formed ESDM status, 1 otherwise */
static inline int esdm_status_json_check(const char *doc)
{
	struct json_object *root, *sources, *source, *name;
	struct json_object *drngs, *drng, *worker, *selftest;
	struct json_object *state;
	size_t i, n;
	int ret = 1;

	root = json_tokener_parse(doc);
	if (!root) {
		printf("JSON status cannot be parsed: %s\n", doc);
		return 1;
	}

	if (!json_object_is_type(root, json_type_object)) {
		printf("JSON status is no object: %s\n", doc);
		goto out;
	}

	if (esdm_status_json_member(root, "library_version",
				    json_type_string) ||
	    esdm_status_json_member(root, "test_mode", json_type_boolean) ||
	    esdm_status_json_member(root, "drng_name", json_type_string) ||
	    esdm_status_json_member(root, "security_strength_bits",
				    json_type_int) ||
	    esdm_status_json_member(root, "drng_instances", json_type_int) ||
	    esdm_status_json_member(root, "standards_compliance",
				    json_type_array) ||
	    esdm_status_json_member(root, "fully_seeded", json_type_boolean) ||
	    esdm_status_json_member(root, "entropy_level_bits",
				    json_type_int) ||
	    esdm_status_json_member(root, "entropy_sources", json_type_array) ||
	    esdm_status_json_member(root, "drngs", json_type_array) ||
	    esdm_status_json_member(root, "reseed_worker", json_type_object) ||
	    esdm_status_json_member(root, "periodic_self_test",
				    json_type_object))
		goto out;

	json_object_object_get_ex(root, "reseed_worker", &worker);
	if (esdm_status_json_member(worker, "running", json_type_boolean) ||
	    esdm_status_json_member(worker, "reseed_interval_seconds",
				    json_type_int))
		goto out;

	json_object_object_get_ex(root, "periodic_self_test", &selftest);
	if (esdm_status_json_member(selftest, "state", json_type_string) ||
	    esdm_status_json_member(selftest, "running", json_type_boolean) ||
	    esdm_status_json_member(selftest, "completed_self_tests",
				    json_type_int) ||
	    esdm_status_json_member(selftest, "self_test_interval_seconds",
				    json_type_int) ||
	    esdm_status_json_member(selftest, "entropy_source_state",
				    json_type_string) ||
	    esdm_status_json_member(selftest, "entropy_sources_tested",
				    json_type_int) ||
	    esdm_status_json_member(selftest, "entropy_sources_failed",
				    json_type_int))
		goto out;

	/*
	 * A status is only handed out by an ESDM that produces random bits, and
	 * that is exactly what a state other than "passed" rules out.
	 */
	json_object_object_get_ex(selftest, "state", &state);
	if (strcmp(json_object_get_string(state), "passed")) {
		printf("JSON status: self test state is \"%s\"\n",
		       json_object_get_string(state));
		goto out;
	}

	json_object_object_get_ex(root, "entropy_sources", &sources);
	n = json_object_array_length(sources);
	if (!n) {
		printf("JSON status reports no entropy source\n");
		goto out;
	}

	/* Every entropy source is an object carrying at least its identity */
	for (i = 0; i < n; i++) {
		source = json_object_array_get_idx(sources, i);

		if (!json_object_is_type(source, json_type_object)) {
			printf("JSON status: entropy source %zu is no object\n",
			       i);
			goto out;
		}

		if (esdm_status_json_member(source, "id", json_type_int) ||
		    esdm_status_json_member(source, "name", json_type_string))
			goto out;

		json_object_object_get_ex(source, "name", &name);
		if (!strlen(json_object_get_string(name))) {
			printf("JSON status: entropy source %zu is unnamed\n",
			       i);
			goto out;
		}
	}

	/*
	 * The initial and the prediction resistance DRNG, and only those two:
	 * the node instances follow the number of CPUs, so a document holding
	 * them would grow past the buffers it is carried in - they are asked
	 * for one at a time instead.
	 */
	json_object_object_get_ex(root, "drngs", &drngs);
	n = json_object_array_length(drngs);
	if (n != 2) {
		printf("JSON status reports %zu DRNG instances, expected the initial and the prediction resistance one\n",
		       n);
		goto out;
	}

	/* Every DRNG instance is an object carrying at least its identity */
	for (i = 0; i < n; i++) {
		drng = json_object_array_get_idx(drngs, i);

		if (esdm_status_json_drng(drng)) {
			printf("JSON status: DRNG instance %zu\n", i);
			goto out;
		}
	}

	ret = 0;

out:
	json_object_put(root);
	return ret;
}

#endif /* ESDM_TEST_STATUS_JSON_CHECK_H */
