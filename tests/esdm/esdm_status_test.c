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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_logger.h"
#include "test_pertubation.h"

#include "../status_json_check.h"

int main(int argc, char *argv[])
{
	/*
	 * Large enough to hold the full status / JSON document for all
	 * entropy sources without truncation - matching the buffer the
	 * esdm-tool frontend uses. A short buffer would clip the JSON
	 * mid-document and fail esdm_status_json_check().
	 */
	char buf[65536];
	uint32_t node, nodes;
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * Ask for several DRNG instances: what is under test below is that the
	 * status document does not carry them - with a single instance there
	 * would be nothing to leave out.
	 */
	esdm_config_max_nodes_set(4);

	ret = esdm_init();
	if (ret)
		return ret;

	ret = esdm_status(buf, sizeof(buf));
	if (ret) {
		printf("Status report could not be created: %d\n", ret);
		ret = 1;
		goto out;
	}

	if (!strstr(buf, "DRNG name") ||
	    !strstr(buf, "ESDM security strength") ||
	    !strstr(buf, "Number of DRNG instances") ||
	    !strstr(buf, "Standards compliance") ||
	    !strstr(buf, "ESDM fully seeded") ||
	    !strstr(buf, "DRNG instance 0 properties") ||
	    !strstr(buf, " Type: initial") ||
	    !strstr(buf, " Type: prediction resistance") ||
	    !strstr(buf, "Requests until reseed") ||
	    !strstr(buf, "Seed generation") ||
	    !strstr(buf, "Last seeding time") ||
	    !strstr(buf, "Reseed worker properties") ||
	    !strstr(buf, "Periodic self test properties") ||
	    !strstr(buf, "Entropy sources tested") ||
	    /* The ESDM only hands out a status when its self tests passed */
	    !strstr(buf, " State: passed")) {
		printf("Unexpected status: %s\n", buf);
		ret = 1;
		goto out;
	}

	/*
	 * The node instances are not in there: there is one per CPU, so a
	 * report carrying them grows with the size of the machine and runs
	 * into the buffers it travels in.
	 */
	if (strstr(buf, " Type: node")) {
		printf("Status reports a node DRNG instance: %s\n", buf);
		ret = 1;
		goto out;
	}

	printf("Status information:\n%s\n", buf);

	ret = esdm_status_json(buf, sizeof(buf));
	if (ret) {
		printf("JSON status could not be created: %d\n", ret);
		ret = 1;
		goto out;
	}

	if (esdm_status_json_check(buf)) {
		ret = 1;
		goto out;
	}

	printf("JSON status information:\n%s\n", buf);

	/* The node instances are reported one at a time instead */
	nodes = esdm_config_online_nodes();
	for (node = 0; node < nodes; node++) {
		ret = esdm_status_drng_json(node, buf, sizeof(buf));
		if (ret) {
			printf("No status for node %u: %d\n", node, ret);
			ret = 1;
			goto out;
		}

		if (esdm_status_drng_json_check(buf)) {
			ret = 1;
			goto out;
		}

		printf("DRNG status of node %u: %s", node, buf);
	}

	/* And a node that has none says so, which is how a caller stops */
	ret = esdm_status_drng_json(nodes, buf, sizeof(buf));
	if (ret != -ENODEV) {
		printf("Status of a node without a DRNG instance: %d\n", ret);
		ret = 1;
		goto out;
	}

	/* The prediction resistance instance is not addressed by a node */
	ret = esdm_status_drng_pr_json(buf, sizeof(buf));
	if (ret || esdm_status_drng_json_check(buf)) {
		printf("No status for the prediction resistance DRNG: %d\n",
		       ret);
		ret = 1;
		goto out;
	}

	if (!strstr(buf, "\"type\":\"prediction resistance\"")) {
		printf("Unexpected prediction resistance DRNG status: %s\n",
		       buf);
		ret = 1;
		goto out;
	}

	printf("DRNG status of the prediction resistance instance: %s", buf);

	/*
	 * A document that does not fit is reported rather than cut in half: a
	 * consumer handed half a JSON document cannot tell it from a whole
	 * one, so the buffer comes back empty with -EMSGSIZE.
	 */
	memset(buf, 'x', sizeof(buf));
	ret = esdm_status_drng_json(0, buf, 32);
	if (ret != -EMSGSIZE || buf[0]) {
		printf("A DRNG status was truncated into 32 bytes: %d, %.32s\n",
		       ret, buf);
		ret = 1;
		goto out;
	}

	memset(buf, 'x', sizeof(buf));
	ret = esdm_status_drng_pr_json(buf, 32);
	if (ret != -EMSGSIZE || buf[0]) {
		printf("The PR DRNG status was truncated into 32 bytes: %d\n",
		       ret);
		ret = 1;
		goto out;
	}

	/* The text report is reported as incomplete, and stays readable */
	memset(buf, 0, sizeof(buf));
	ret = esdm_status(buf, 512);
	if (ret != -EMSGSIZE || !strstr(buf, "library version")) {
		printf("The status report was truncated into 512 bytes: %d\n",
		       ret);
		ret = 1;
		goto out;
	}

	memset(buf, 'x', sizeof(buf));
	ret = esdm_status_json(buf, 512);
	if (ret != -EMSGSIZE || buf[0]) {
		printf("The status document was truncated into 512 bytes: %d\n",
		       ret);
		ret = 1;
		goto out;
	}

	printf("Documents that do not fit are reported, not truncated\n");
	ret = 0;

out:
	esdm_fini();
	return ret;
}
