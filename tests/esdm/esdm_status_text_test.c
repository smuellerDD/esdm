/*
 * The status text rendered from a status document: labels, nesting, values
 * without a plain form, and a buffer too small.
 *
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

#include <errno.h>
#include <json-c/json.h>
#include <string.h>

#include "common_test.h"
#include "esdm_info.h"
#include "esdm_logger.h"

static const char doc_json[] =
	"{\"library_version\":\"1.2.4\","
	"\"drng_name\":\"Hash DRBG\","
	"\"fully_seeded\":true,"
	"\"standards_compliance\":[\"FIPS 140\",\"DRG.3\"],"
	"\"failed_sources\":[],"
	"\"last_seeding_time\":null,"
	"\"reseed_worker\":{\"running\":false,\"interval_seconds\":600},"
	"\"entropy_sources\":["
	"{\"id\":0,\"name\":\"SchedulerEBPF\",\"ebpf_programs_loaded\":false,"
	"\"per_cpu_size\":8},"
	"{\"id\":1,\"provider\":{\"status\":\"a\\nForged: yes\","
	"\"esc\":\"\\u001b[31m\"}}]}";

static const char doc_text[] = "Library version: 1.2.4\n"
			       "DRNG name: Hash DRBG\n"
			       "Fully seeded: true\n"
			       "Standards compliance: FIPS 140, DRG.3\n"
			       "Failed sources: none\n"
			       "Last seeding time: N/A\n"
			       "Reseed worker:\n"
			       " Running: false\n"
			       " Interval seconds: 600\n"
			       "Entropy sources:\n"
			       /* Headed by name and ID, which their lines omit */
			       " SchedulerEBPF (ID 0):\n"
			       "  eBPF programs loaded: false\n"
			       "  Per CPU size: 8\n"
			       " ID 1:\n"
			       "  Provider:\n"
			       /* A line break or escape in a value is quoted */
			       "   Status: \"a\\nForged: yes\"\n"
			       "   Esc: \"\\u001b[31m\"\n";

int main(void)
{
	struct json_object *doc = json_tokener_parse(doc_json);
	char buf[sizeof(doc_text)];

	esdm_logger_set_verbosity(LOGGER_NONE);

	CHECK(doc, "the test document does not parse");
	if (!doc)
		return common_test_result("esdm_status_text");

	CHECK_EQ(esdm_status_text(doc, buf, sizeof(buf)), 0);
	CHECK_STR_EQ(buf, doc_text);

	/* What does not fit is reported, the text kept as far as it got */
	memset(buf, 'x', sizeof(buf));
	CHECK_EQ(esdm_status_text(doc, buf, 40), -EMSGSIZE);
	CHECK(strlen(buf) < 40 && !strncmp(buf, doc_text, strlen(buf)),
	      "the cut text is no prefix of the text: %s", buf);

	json_object_put(doc);

	return common_test_result("esdm_status_text");
}
