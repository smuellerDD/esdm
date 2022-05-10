/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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
#include <string.h>
#include <unistd.h>

#include "esdm.h"
#include "logger.h"
#include "test_pertubation.h"

int main(int argc, char *argv[])
{
	char buf[2048];
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	logger_set_verbosity(LOGGER_DEBUG);
	ret = esdm_init();
	if (ret)
		return ret;

	esdm_status(buf, sizeof(buf));

	if (!strstr(buf, "DRNG name") ||
	    !strstr(buf, "ESDM security strength") ||
	    !strstr(buf, "Number of DRNG instances") ||
	    !strstr(buf, "Standards compliance") ||
	    !strstr(buf, "ESDM minimally seeded") ||
	    !strstr(buf, "ESDM fully seeded")) {
		printf("Unexpected status: %s\n", buf);
		ret = 1;
		goto out;
	}

	printf("Status information:\n%s\n", buf);

out:
	esdm_fini();
	return ret;
}
