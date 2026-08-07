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

/*
 * Tests for the part of common/linux_support.c that does not need privileges:
 * the personalization string the server derives from the DMI product UUID.
 *
 * Whether that file can be read depends on the machine - it is root only and a
 * VM may expose it empty - so the test asserts the contract rather than a
 * value. The caller tells "got a string" from "did not" by the return code
 * alone, so a failure leaving *ptr NULL while reporting success feeds a NULL
 * personalization string into the DRNG. An empty product_uuid used to do just
 * that: fgets() returns NULL at end of file without setting errno.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_test.h"
#include "linux_support.h"

static void check_personalization_string(const char *what)
{
	char *ptr = NULL;
	size_t length = 0;
	int ret = linux_personalization_string(&ptr, &length);

	if (ret) {
		/*
		 * On failure nothing is handed out - neither a pointer the
		 * caller would have to free nor a length it might trust.
		 */
		CHECK(ret < 0, "%s: failed with a positive return code %d",
		      what, ret);
		CHECK(ptr == NULL, "%s: failed but still returned a string",
		      what);
		CHECK(length == 0, "%s: failed but reported a length of %zu",
		      what, length);
		return;
	}

	CHECK(ptr != NULL, "%s: reported success without a string", what);
	if (!ptr)
		return;

	CHECK(length == strlen(ptr),
	      "%s: reported a length of %zu for a string of %zu characters",
	      what, length, strlen(ptr));
	CHECK(length > 0, "%s: reported success with an empty string", what);

	/* The trailing newline of the sysfs file is not part of the string */
	CHECK(strchr(ptr, '\n') == NULL,
	      "%s: the string still carries a newline", what);

	free(ptr);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	check_personalization_string("first call");

	/*
	 * Nothing about it is cached, so a second caller - the server asks once
	 * per DRNG instance - has to get the same answer rather than a stale or
	 * half-released one.
	 */
	check_personalization_string("second call");

	return common_test_result("linux_support");
}
