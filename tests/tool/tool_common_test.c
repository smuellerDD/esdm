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
 * Tests for frontends/tool/common.c - the timing arithmetic, the human readable
 * formatters and the result collector the esdm-tool stress modes report through.
 *
 * The formatters pick a unit by magnitude, and the boundaries are where a wrong
 * comparison hides: "1000 ms" instead of "1.000 s" is plausible enough to go
 * unnoticed, so every threshold is checked from both sides.
 *
 * handle_messages() is driven over real socket pairs with hand-built result
 * messages, exercising the aggregation across workers - and its returning once
 * every worker reported rather than waiting for its report timer - without
 * running an actual stress test against a server.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "tool.h"

/******************************************************************************
 * Timing arithmetic
 ******************************************************************************/

static void check_diff(time_t s_sec, long s_nsec, time_t e_sec, long e_nsec,
		       double expect_sec, long expect_ns, const char *what)
{
	struct timespec start = { .tv_sec = s_sec, .tv_nsec = s_nsec };
	struct timespec end = { .tv_sec = e_sec, .tv_nsec = e_nsec };
	double got = timespec_diff(&start, &end);
	long got_ns = timespec_diff_ns(&start, &end);

	CHECK(got > expect_sec - 1e-9 && got < expect_sec + 1e-9,
	      "%s: timespec_diff returned %.9f, expected %.9f", what, got,
	      expect_sec);
	CHECK(got_ns == expect_ns, "%s: timespec_diff_ns returned %ld, "
				   "expected %ld",
	      what, got_ns, expect_ns);
}

static void test_timespec_diff(void)
{
	check_diff(0, 0, 0, 0, 0.0, 0, "zero interval");
	check_diff(1, 0, 2, 0, 1.0, 1000000000L, "one second");
	check_diff(1, 500000000L, 2, 0, 0.5, 500000000L, "half a second");
	check_diff(0, 100, 0, 350, 250e-9, 250L, "250 nanoseconds");
	check_diff(5, 250000000L, 7, 750000000L, 2.5, 2500000000L,
		   "two and a half seconds");

	/* A borrow across the seconds boundary */
	check_diff(1, 900000000L, 2, 100000000L, 0.2, 200000000L,
		   "interval crossing a second");

	/* An end before the start yields a negative interval, not a wrap */
	check_diff(2, 0, 1, 0, -1.0, -1000000000L, "negative interval");
	check_diff(0, 350, 0, 100, -250e-9, -250L, "negative nanoseconds");
}

/******************************************************************************
 * Formatters
 ******************************************************************************/

static void check_time_format(double time_sec, const char *expect)
{
	char *got = format_time_sec(time_sec);

	if (!got) {
		CHECK(0, "format_time_sec(%g) returned NULL", time_sec);
		return;
	}

	CHECK(!strcmp(got, expect), "format_time_sec(%g) returned \"%s\", "
				    "expected \"%s\"",
	      time_sec, got, expect);
	free(got);
}

static void test_format_time_sec(void)
{
	/* Below a microsecond the value is reported in whole nanoseconds */
	check_time_format(0.0, "0 ns");
	check_time_format(1e-9, "1 ns");
	check_time_format(500e-9, "500 ns");
	check_time_format(999e-9, "999 ns");

	/* From a microsecond on, in microseconds ... */
	check_time_format(1e-6, "1.000 us");
	check_time_format(1.5e-6, "1.500 us");
	check_time_format(999e-6, "999.000 us");

	/* ... from a millisecond on, in milliseconds ... */
	check_time_format(1e-3, "1.000 ms");
	check_time_format(250e-3, "250.000 ms");
	check_time_format(999e-3, "999.000 ms");

	/* ... and from a second on, in seconds */
	check_time_format(1.0, "1.000 s");
	check_time_format(1.5, "1.500 s");
	check_time_format(3600.0, "3600.000 s");

	/* A negative duration falls into the smallest unit */
	check_time_format(-1e-3, "-1000000 ns");
}

static void check_byte_format(double byte_sec, const char *expect)
{
	char *got = format_byte_sec(byte_sec);

	if (!got) {
		CHECK(0, "format_byte_sec(%g) returned NULL", byte_sec);
		return;
	}

	CHECK(!strcmp(got, expect), "format_byte_sec(%g) returned \"%s\", "
				    "expected \"%s\"",
	      byte_sec, got, expect);
	free(got);
}

static void test_format_byte_sec(void)
{
	/* The unit changes at every power of a thousand, the field stays 7 wide */
	check_byte_format(0.0, "      0 B/s");
	check_byte_format(999.0, "    999 B/s");
	check_byte_format(1000.0, "  1.000 KB/s");
	check_byte_format(1500.0, "  1.500 KB/s");
	check_byte_format(999999.0, "999.999 KB/s");
	check_byte_format(1e6, "  1.000 MB/s");
	check_byte_format(123.456e6, "123.456 MB/s");
	check_byte_format(1e9, "  1.000 GB/s");
	check_byte_format(2.5e9, "  2.500 GB/s");
	check_byte_format(1e12, "1000.000 GB/s");
}

/******************************************************************************
 * Result collection
 ******************************************************************************/

static int saved_stdout = -1;
static char capture_path[512];

static bool capture_start(void)
{
	const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	int fd;

	snprintf(capture_path, sizeof(capture_path), "%s/esdm_tool_out_%u.txt",
		 tmp, (unsigned int)getpid());

	fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	fd = open(capture_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (saved_stdout < 0 || fd < 0) {
		CHECK(0, "cannot redirect stdout: %s", strerror(errno));
		if (saved_stdout >= 0)
			close(saved_stdout);
		if (fd >= 0)
			close(fd);
		saved_stdout = -1;
		return false;
	}

	dup2(fd, STDOUT_FILENO);
	close(fd);
	return true;
}

/* Restore stdout and hand back what was written to it; caller frees. */
static char *capture_end(void)
{
	char *content = NULL;
	long size = 0;
	FILE *in;

	fflush(stdout);
	if (saved_stdout >= 0) {
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdout);
		saved_stdout = -1;
	}

	in = fopen(capture_path, "r");
	if (!in)
		return NULL;

	if (fseek(in, 0, SEEK_END) < 0 || (size = ftell(in)) < 0) {
		fclose(in);
		return NULL;
	}
	rewind(in);

	content = calloc(1, (size_t)size + 1);
	if (content && size &&
	    fread(content, 1, (size_t)size, in) != (size_t)size) {
		free(content);
		content = NULL;
	}

	fclose(in);
	unlink(capture_path);
	return content;
}

static struct test_msg make_msg(int is_exit, long id, double req_per_sec,
				double bytes_per_sec, uint32_t request_size)
{
	struct test_msg m;

	memset(&m, 0, sizeof(m));
	m.is_exit = is_exit;
	m.id = id;
	m.request_size = request_size;
	m.duration = 1e-3;
	m.mean_duration = 2e-3;
	m.max_duration = 5e-3;
	m.req_per_sec = req_per_sec;
	m.bytes_per_sec = bytes_per_sec;
	m.requests = 100;
	m.bytes = 3200;

	return m;
}

static void test_handle_messages(void)
{
#define NUM_WORKERS 3
	int pairs[NUM_WORKERS][2];
	int sockets[NUM_WORKERS];
	char *out;
	unsigned int i;

	for (i = 0; i < NUM_WORKERS; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
			       pairs[i]) < 0) {
			CHECK(0, "socketpair() failed: %s", strerror(errno));
			while (i--) {
				close(pairs[i][0]);
				close(pairs[i][1]);
			}
			return;
		}
		sockets[i] = pairs[i][0];
	}

	/*
	 * Every worker reports one outlier and one final result. The collector
	 * has to consume both, print only the final one and stop as soon as all
	 * of them have arrived - long before its eight second report timer.
	 */
	for (i = 0; i < NUM_WORKERS; i++) {
		struct test_msg outlier = make_msg(0, (long)i, 0.0, 0.0, 32);
		struct test_msg final =
			make_msg(1, (long)i, 1000.0 * (double)(i + 1),
				 32000.0 * (double)(i + 1), 32);

		CHECK_EQ(write(pairs[i][1], &outlier, sizeof(outlier)),
			 (ssize_t)sizeof(outlier));
		CHECK_EQ(write(pairs[i][1], &final, sizeof(final)),
			 (ssize_t)sizeof(final));
	}

	if (!capture_start())
		goto out;

	handle_messages(sockets, NUM_WORKERS, false);

	out = capture_end();
	if (!out) {
		CHECK(0, "the collector output could not be read back");
		goto out;
	}

	/* The aggregate of 1000 + 2000 + 3000 calls per second */
	CHECK(strstr(out, "Total calls/sec: 6000.00") != NULL,
	      "the call rates were not summed up (output: %s)", out);
	/* and of 32000 + 64000 + 96000 bytes per second */
	CHECK(strstr(out, "Total Byte/sec: 192.000 KB/s") != NULL,
	      "the byte rates were not summed up (output: %s)", out);
	CHECK(strstr(out, "Used request size: 32") != NULL,
	      "the request size was not reported (output: %s)", out);
	CHECK(strstr(out, "Average Load:") != NULL,
	      "the load average was not reported (output: %s)", out);

	/* One final line per worker, and no line for the outliers */
	for (i = 0; i < NUM_WORKERS; i++) {
		char needle[64];

		snprintf(needle, sizeof(needle), "ID: %u, Final: 1", i);
		CHECK(strstr(out, needle) != NULL,
		      "worker %u did not report a final result", i);
	}
	CHECK(strstr(out, "Final: 0") == NULL,
	      "an outlier was reported although only finals are printed");
	CHECK(strstr(out, "Outlier:") == NULL,
	      "an outlier was reported although only finals are printed");

	/* Every worker that reported its final result is dropped */
	for (i = 0; i < NUM_WORKERS; i++)
		CHECK(sockets[i] == -1,
		      "the socket of worker %u was not retired", i);

	free(out);

out:
	for (i = 0; i < NUM_WORKERS; i++) {
		close(pairs[i][0]);
		close(pairs[i][1]);
	}
#undef NUM_WORKERS
}

static void test_handle_messages_cpu_usage(void)
{
	int pair[2];
	int sockets[1];
	struct test_msg final;
	char *out;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) {
		CHECK(0, "socketpair() failed: %s", strerror(errno));
		return;
	}
	sockets[0] = pair[0];

	final = make_msg(1, 7, 500.0, 16000.0, 64);
	CHECK_EQ(write(pair[1], &final, sizeof(final)),
		 (ssize_t)sizeof(final));

	if (!capture_start()) {
		close(pair[0]);
		close(pair[1]);
		return;
	}

	handle_messages(sockets, 1, true);

	out = capture_end();
	if (!out) {
		CHECK(0, "the collector output could not be read back");
		close(pair[0]);
		close(pair[1]);
		return;
	}

	/*
	 * The CPU utilization is sampled once at the start of every run. The
	 * first sample of the process has nothing to compare against, so the
	 * table only appears from the second run on - which this is, the
	 * previous test having taken the first sample. Without a readable
	 * /proc/stat there is nothing to sample and nothing to assert.
	 */
	if (!access("/proc/stat", R_OK)) {
		CHECK(strstr(out, "# CPU  A Usage:") != NULL,
		      "no CPU utilization was reported (output: %s)", out);
		CHECK(strstr(out, "# t:") != NULL,
		      "the utilization report carries no timestamp (output: %s)",
		      out);
	}

	CHECK(strstr(out, "Used request size: 64") != NULL,
	      "the request size was not reported (output: %s)", out);
	CHECK(strstr(out, "Total calls/sec: 500.00") != NULL,
	      "the call rate was not reported (output: %s)", out);

	free(out);
	close(pair[0]);
	close(pair[1]);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_timespec_diff();
	test_format_time_sec();
	test_format_byte_sec();
	test_handle_messages();
	test_handle_messages_cpu_usage();

	return common_test_result("tool_common");
}
