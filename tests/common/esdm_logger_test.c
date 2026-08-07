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
 * Tests for common/esdm_logger.c.
 *
 * Two things decide whether a record is emitted at all - the verbosity level
 * and the class filter - and both are consulted in different places (the
 * severity comparison at the top of _esdm_logger(), the class lookup a few
 * lines further down). The tests below drive the logger into a temporary file
 * and assert on what actually lands there, so a filter that silently stops
 * filtering, or one that swallows everything, is caught.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common_test.h"
#include "esdm_logger.h"

/* Filled in by mkstemp(), below the temporary directory of the test run */
static char logfile[256];

/* Read the whole log file back; the caller frees the result. */
static char *read_logfile(void)
{
	FILE *stream = esdm_logger_log_stream();
	char *content;
	long size;
	FILE *in;

	if (stream)
		fflush(stream);

	in = fopen(logfile, "r");
	if (!in)
		return NULL;

	if (fseek(in, 0, SEEK_END) < 0) {
		fclose(in);
		return NULL;
	}
	size = ftell(in);
	rewind(in);

	if (size < 0) {
		fclose(in);
		return NULL;
	}

	content = calloc(1, (size_t)size + 1);
	if (content && size)
		if (fread(content, 1, (size_t)size, in) != (size_t)size) {
			free(content);
			content = NULL;
		}

	fclose(in);
	return content;
}

/* Truncate the log file so the next check sees only what follows. */
static void reset_logfile(void)
{
	FILE *stream = esdm_logger_log_stream();

	if (stream)
		fflush(stream);
	if (truncate(logfile, 0) < 0)
		CHECK(0, "cannot truncate %s: %s", logfile, strerror(errno));
	if (stream)
		fseek(stream, 0, SEEK_END);
}

static void check_logged(const char *needle, bool expected, const char *what)
{
	char *content = read_logfile();

	if (!content) {
		CHECK(0, "cannot read back %s", logfile);
		return;
	}

	if (expected)
		CHECK(strstr(content, needle) != NULL,
		      "%s: \"%s\" is missing from the log (log is \"%s\")",
		      what, needle, content);
	else
		CHECK(strstr(content, needle) == NULL,
		      "%s: \"%s\" was logged although it should be filtered",
		      what, needle);

	free(content);
	reset_logfile();
}

static void test_verbosity(void)
{
	esdm_logger_set_verbosity(LOGGER_DEBUG);
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_ANY), LOGGER_DEBUG);

	esdm_logger_set_verbosity(LOGGER_STATUS);
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_ANY), LOGGER_STATUS);

	/* Increasing steps one level at a time ... */
	esdm_logger_set_verbosity(LOGGER_NONE);
	esdm_logger_inc_verbosity();
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_ANY), LOGGER_STATUS);
	esdm_logger_inc_verbosity();
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_ANY), LOGGER_ERR);

	/* ... and saturates at the highest defined level */
	esdm_logger_set_verbosity(LOGGER_TRACE);
	esdm_logger_inc_verbosity();
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_ANY), LOGGER_TRACE);
	esdm_logger_inc_verbosity();
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_ANY), LOGGER_TRACE);
}

static void test_class(void)
{
	unsigned int i;

	/* Every defined class is accepted */
	for (i = 0; i < LOGGER_C_LAST; i++)
		CHECK_EQ(esdm_logger_set_class((enum esdm_logger_class)i), 0);

	/* while anything beyond the list is rejected and changes nothing */
	CHECK_EQ(esdm_logger_set_class(LOGGER_C_LAST), -EINVAL);
	CHECK_EQ(esdm_logger_set_class((enum esdm_logger_class)(LOGGER_C_LAST +
								10)),
		 -EINVAL);

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * With a class filter in place, a query for any other class reports
	 * that nothing is logged for it.
	 */
	CHECK_EQ(esdm_logger_set_class(LOGGER_C_TOOL), 0);
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_TOOL), LOGGER_DEBUG);
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_DRNG), LOGGER_NONE);
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_ANY), LOGGER_NONE);

	/* LOGGER_C_ANY as the filter lets every class through again */
	CHECK_EQ(esdm_logger_set_class(LOGGER_C_ANY), 0);
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_DRNG), LOGGER_DEBUG);
	CHECK_EQ(esdm_logger_get_verbosity(LOGGER_C_ANY), LOGGER_DEBUG);
}

static void test_get_class(void)
{
	char buf[4096];
	ssize_t rd;
	int fds[2];
	unsigned int i;

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	esdm_logger_get_class(fds[1]);
	close(fds[1]);

	memset(buf, 0, sizeof(buf));
	rd = read(fds[0], buf, sizeof(buf) - 1);
	close(fds[0]);

	CHECK(rd > 0, "esdm_logger_get_class wrote nothing");

	/* One line per class, and the unclassified default is named */
	{
		unsigned int lines = 0;
		const char *p = buf;

		while ((p = strchr(p, '\n')) != NULL) {
			lines++;
			p++;
		}
		CHECK_EQ(lines, LOGGER_C_LAST);
	}

	CHECK(strstr(buf, "(unclassified)") != NULL,
	      "the unclassified class is not listed");
	CHECK(strstr(buf, "Entropy Source") != NULL,
	      "the entropy source class is not listed");
	CHECK(strstr(buf, "CLI Tool") != NULL, "the tool class is not listed");

	/* Every class identifier appears in the listing */
	for (i = 0; i < LOGGER_C_LAST; i++) {
		char needle[16];

		snprintf(needle, sizeof(needle), "\n%u ", i);
		CHECK(i == 0 || strstr(buf, needle) != NULL,
		      "class %u is not listed", i);
	}
}

static void test_set_file(void)
{
	FILE *before = esdm_logger_log_stream();
	int fd;

	CHECK(before == stderr,
	      "the logger does not start out logging to stderr");

	/* A path that cannot be opened is reported as a negative errno */
	CHECK_EQ(esdm_logger_set_file("/nonexistent-directory/esdm.log"),
		 -ENOENT);
	CHECK(esdm_logger_log_stream() == before,
	      "a failed esdm_logger_set_file changed the log stream");

	snprintf(logfile, sizeof(logfile), "%s/esdm_logger_test_XXXXXX",
		 getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	fd = mkstemp(logfile);
	if (fd < 0) {
		CHECK(0, "mkstemp failed: %s", strerror(errno));
		return;
	}
	close(fd);

	CHECK_EQ(esdm_logger_set_file(logfile), 0);
	CHECK(esdm_logger_log_stream() != stderr,
	      "esdm_logger_set_file did not redirect the log stream");

	/* The log file is set once - a second attempt is refused */
	CHECK_EQ(esdm_logger_set_file(logfile), -EFAULT);
	reset_logfile();
}

static void test_logging(void)
{
	esdm_logger_set_class(LOGGER_C_ANY);
	esdm_logger_set_verbosity(LOGGER_STATUS);

	/* A record at or below the configured verbosity is emitted ... */
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "status-record\n");
	check_logged("status-record", true, "status at verbosity status");

	/* ... one above it is dropped */
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "debug-record\n");
	check_logged("debug-record", false, "debug at verbosity status");

	esdm_logger_set_verbosity(LOGGER_TRACE);

	/* Every severity has its own label */
	esdm_logger(LOGGER_ERR, LOGGER_C_ANY, "severity-err\n");
	check_logged("Error", true, "error severity label");
	esdm_logger(LOGGER_WARN, LOGGER_C_ANY, "severity-warn\n");
	check_logged("Warning", true, "warning severity label");
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "severity-verbose\n");
	check_logged("Verbose", true, "verbose severity label");
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "severity-status\n");
	check_logged("Status", true, "status severity label");
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "severity-debug\n");
	check_logged("Debug", true, "debug severity label");
	esdm_logger(LOGGER_DEBUG2, LOGGER_C_ANY, "severity-debug2\n");
	check_logged("Debug2", true, "debug2 severity label");
	esdm_logger(LOGGER_TRACE, LOGGER_C_ANY, "severity-trace\n");
	check_logged("Trace", true, "trace severity label");

	/*
	 * At the debug levels the record carries the origin of the call. The
	 * verbosity level - not the record's severity - selects that format.
	 */
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "origin-record\n");
	check_logged("esdm_logger_test.c", true, "call origin at debug level");

	/* The class name is part of the record ... */
	esdm_logger(LOGGER_STATUS, LOGGER_C_DRNG, "class-record\n");
	check_logged("DRNG", true, "class name");

	/* ... and the unclassified default adds none */
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "anyclass-record\n");
	check_logged("Entropy Source", false, "unclassified record");

	/* Format arguments are expanded */
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "formatted %d %s\n", 42,
		    "arg");
	check_logged("formatted 42 arg", true, "format expansion");

	/* The class filter suppresses everything else */
	CHECK_EQ(esdm_logger_set_class(LOGGER_C_TOOL), 0);
	esdm_logger(LOGGER_STATUS, LOGGER_C_DRNG, "filtered-record\n");
	check_logged("filtered-record", false, "class filter");
	esdm_logger(LOGGER_STATUS, LOGGER_C_TOOL, "passing-record\n");
	check_logged("passing-record", true, "class filter pass through");

	/* A verbosity of none silences the logger entirely */
	CHECK_EQ(esdm_logger_set_class(LOGGER_C_ANY), 0);
	esdm_logger_set_verbosity(LOGGER_NONE);
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "silenced-record\n");
	check_logged("silenced-record", false, "verbosity none");
}

static void test_syslog(void)
{
	/*
	 * Switching to syslog is a one-way door for the process, so this runs
	 * last. There is no portable way to read the records back - the point
	 * here is that both header variants are formatted and handed over
	 * without crashing, and that the log file stops receiving records.
	 */
	esdm_logger_enable_syslog("esdm-logger-test");
	esdm_logger_set_verbosity(LOGGER_TRACE);

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "syslog-status\n");
	esdm_logger(LOGGER_ERR, LOGGER_C_SERVER, "syslog-error\n");
	esdm_logger(LOGGER_WARN, LOGGER_C_RPC, "syslog-warning\n");
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES, "syslog-debug\n");
	esdm_logger(LOGGER_TRACE, LOGGER_C_MD, "syslog-trace\n");

	check_logged("syslog-status", false, "record diverted to syslog");
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	test_verbosity();
	test_class();
	test_get_class();
	test_set_file();
	test_logging();
	test_syslog();

	ret = common_test_result("esdm_logger");
	unlink(logfile);
	return ret;
}
