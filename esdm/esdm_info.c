/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include <stdio.h>
#include <json-c/json.h>

#include "esdm.h"
#include "esdm_es_aux.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_irq.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched.h"
#include "esdm_info.h"
#include "logger.h"
#include "test_pertubation.h"
#include "visibility.h"

static unsigned int esdm_nodes = 1;

static inline size_t esdm_remaining_buf_len(char *buf, size_t buflen)
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
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Status information cannot be created\n");
		return;
	}

	snprintf(buf, buflen, "ESDM %slibrary version: %s\n", TESTMODE_STR,
		 VERSION);
	len = esdm_remaining_buf_len(buf, buflen);

	snprintf(buf + len, buflen - len,
		 "DRNG name: %s\n"
		 "ESDM security strength in bits: %d\n"
		 "Number of DRNG instances: %u\n"
		 "Standards compliance: %s%s%s\n"
		 "ESDM minimally seeded: %s\n"
		 "ESDM fully seeded: %s\n"
		 "ESDM entropy level: %u\n",
		 drng->drng_cb->drng_name(), esdm_security_strength(),
		 esdm_nodes, esdm_sp80090c_compliant() ? "SP800-90C, " : "",
		 esdm_ntg1_compliant() ? "NTG.1 (2011), " : "",
		 esdm_ntg1_2022_compliant() ? "NTG.1 (2022)" : "",
		 esdm_state_min_seeded() ? "true" : "false",
		 esdm_state_fully_seeded() ? "true" : "false",
		 esdm_avail_entropy());

	/* Concatenate the output of the entropy sources. */
	for_each_esdm_es (i) {
		len = esdm_remaining_buf_len(buf, buflen);
		snprintf(buf + len, buflen - len,
			 "Entropy Source %u properties:\n"
			 " Name: %s\n",
			 i, esdm_es[i]->name);

		len = esdm_remaining_buf_len(buf, buflen);
		esdm_es[i]->state(buf + len, buflen - len);
	}
}

DSO_PUBLIC
void esdm_status_json(char *buf, size_t buflen)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct json_object *stat_obj;
	struct json_object *std_arr;
	struct json_object *es_obj;
	size_t len;
	uint32_t i;

	if (!buf) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Status information cannot be created\n");
		return;
	}

	stat_obj = json_object_new_object();
	if(!stat_obj) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Status JSON object cannot be created\n");
		return;
	}

	json_object_object_add(stat_obj, "version", json_object_new_string(VERSION));
	json_object_object_add(stat_obj, "drng_name", json_object_new_string(drng->drng_cb->drng_name()));
	json_object_object_add(stat_obj, "security_strength_bits", json_object_new_int(esdm_security_strength()));
	json_object_object_add(stat_obj, "drng_instances", json_object_new_int(esdm_nodes));
	std_arr = json_object_new_array();
	if(esdm_sp80090c_compliant())
		json_object_array_add(std_arr, json_object_new_string("SP800-90C"));
	if(esdm_ntg1_compliant())
		json_object_array_add(std_arr, json_object_new_string("NTG.1 (2011)"));
	if(esdm_ntg1_2022_compliant())
		json_object_array_add(std_arr, json_object_new_string("NTG.1 (2022)"));
	json_object_object_add(stat_obj, "standards_compliance", std_arr);
	json_object_object_add(stat_obj, "minimally_seeded", json_object_new_boolean(esdm_state_min_seeded()));
	json_object_object_add(stat_obj, "fully_seeded", json_object_new_boolean(esdm_state_fully_seeded()));
	json_object_object_add(stat_obj, "available_entropy", json_object_new_int(esdm_avail_entropy()));
	
	es_obj = json_object_new_object();
	/* Concatenate the output of the entropy sources. */
	for_each_esdm_es (i) {
		struct json_object *current_es_obj = json_object_new_object();
		esdm_es[i]->state_json(current_es_obj);
		json_object_object_add(es_obj, esdm_es[i]->name, current_es_obj);
	}
	json_object_object_add(stat_obj, "entropy_sources", es_obj);

	/*
	snprintf(buf, buflen, "%s", json_object_to_json_string(stat_obj));
	*/
	snprintf(buf, buflen, "%s", json_object_to_json_string_ext(stat_obj, JSON_C_TO_STRING_PRETTY));
	
	json_object_put(stat_obj);
}

DSO_PUBLIC
void esdm_status_machine(struct esdm_status_st *status)
{
	status->es_irq_enabled = esdm_irq_enabled();
	status->es_sched_enabled = esdm_sched_enabled();
}
