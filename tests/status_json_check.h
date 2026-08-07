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

/* Returns 0 if the document is a well-formed ESDM status, 1 otherwise */
static inline int esdm_status_json_check(const char *doc)
{
	struct json_object *root, *sources, *source, *name;
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
	    esdm_status_json_member(root, "entropy_sources", json_type_array))
		goto out;

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

	ret = 0;

out:
	json_object_put(root);
	return ret;
}

#endif /* ESDM_TEST_STATUS_JSON_CHECK_H */
