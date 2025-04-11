/*
 * Copyright (C) 2025, Markus Theil <theil.markus@gmail.com>
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

#include "tool.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/timerfd.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_CORES 256

struct cpu_stats {
	unsigned long long user, nice, system, idle, iowait, irq, softirq,
		steal, guest;
};

static struct cpu_stats prev[MAX_CORES] = { 0 };
static struct cpu_stats curr[MAX_CORES] = { 0 };

static void get_cpu_utilization(struct timespec *start)
{
	FILE *file = fopen("/proc/stat", "r");
	if (file == NULL) {
		perror("Error opening /proc/stat");
		return;
	}

	char line[256];
	size_t core_count = 0;

	while (fgets(line, sizeof(line), file) && core_count < MAX_CORES) {
		if (strncmp(line, "cpu", 3) != 0) {
			break;
		}
		char cpu[10];
		sscanf(line, "%s %llu %llu %llu %llu %llu %llu %llu %llu %llu",
		       cpu, &curr[core_count].user, &curr[core_count].nice,
		       &curr[core_count].system, &curr[core_count].idle,
		       &curr[core_count].iowait, &curr[core_count].irq,
		       &curr[core_count].softirq, &curr[core_count].steal,
		       &curr[core_count].guest);
		core_count++;
	}
	fclose(file);

	if (prev[0].user != 0) {
		struct timespec curr_time;
		char *t;

		clock_gettime(CLOCK_MONOTONIC, &curr_time);
		t = format_time_sec(timespec_diff(start, &curr_time));
		printf("#########################\n");
		printf("# t: %s\n", t);
		free(t);

		for (size_t i = 0; i < core_count; i++) {
			unsigned long long prev_idle_time =
				prev[i].idle + prev[i].iowait;
			unsigned long long prev_total_time =
				prev[i].user + prev[i].nice + prev[i].system +
				prev[i].idle + prev[i].iowait + prev[i].irq +
				prev[i].softirq + prev[i].steal + prev[i].guest;
			unsigned long long curr_idle_time =
				curr[i].idle + curr[i].iowait;
			unsigned long long curr_total_time =
				curr[i].user + curr[i].nice + curr[i].system +
				curr[i].idle + curr[i].iowait + curr[i].irq +
				curr[i].softirq + curr[i].steal + curr[i].guest;

			unsigned long long total_diff =
				curr_total_time - prev_total_time;
			unsigned long long idle_diff =
				curr_idle_time - prev_idle_time;
			double usage = (100.0 * ((double)total_diff -
						 (double)idle_diff)) /
				       (double)total_diff;

			char cpu[16];
			sprintf(cpu, "# CPU%3li", i);
			printf("%s Usage: %6.2lf%%\n",
			       i == 0 ? "# CPU  A" : cpu, usage);
		}
		printf("#########################\n\n");
	}

	memcpy(prev, curr, sizeof(struct cpu_stats) * core_count);
}

double timespec_diff(const struct timespec *start, const struct timespec *end)
{
	return ((double)end->tv_sec - (double)start->tv_sec) +
	       ((double)end->tv_nsec - (double)start->tv_nsec) / 1E9;
}

long timespec_diff_ns(const struct timespec *start, const struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000000000 +
	       (end->tv_nsec - start->tv_nsec);
}

char *format_time_sec(double time_sec)
{
	const size_t buffer_size = 32;
	char *buffer = calloc(1, buffer_size);
	if (time_sec < 1e-6) {
		snprintf(buffer, buffer_size, "%.0f ns", time_sec * 1e9);
	} else if (time_sec < 1e-3) {
		snprintf(buffer, buffer_size, "%.3f us", time_sec * 1e6);
	} else if (time_sec < 1) {
		snprintf(buffer, buffer_size, "%.3f ms", time_sec * 1e3);
	} else {
		snprintf(buffer, buffer_size, "%.3f s", time_sec);
	}
	return buffer;
}

char *format_byte_sec(double byte_sec)
{
	const size_t buffer_size = 32;
	char *buffer = calloc(1, buffer_size);
	if (byte_sec < 1e3) {
		snprintf(buffer, buffer_size, "%7.0f B/s", byte_sec);
	} else if (byte_sec < 1e6) {
		snprintf(buffer, buffer_size, "%7.3f KB/s", byte_sec / 1e3);
	} else if (byte_sec < 1e9) {
		snprintf(buffer, buffer_size, "%7.3f MB/s", byte_sec / 1e6);
	} else {
		snprintf(buffer, buffer_size, "%7.3f GB/s", byte_sec / 1e9);
	}
	return buffer;
}

static void handle_message(struct test_msg *m)
{
	/* don't print outliers */
	if (!m->is_exit)
		return;

	char *t_a = format_time_sec(m->duration);
	char *t_b = format_time_sec(m->mean_duration);
	char *t_c = format_time_sec(m->max_duration);

	/* final does not send current timestamp */
	if (m->is_exit) {
		printf("ID: %li, Final: %i, Current mean: %s, Current max: %s, Calls/Sec: %lf\n",
		       m->id, m->is_exit, t_b, t_c, m->req_per_sec);
	} else {
		printf("ID: %li, Final: %i, Outlier: %s, Current mean: %s, Current max: %s, Calls/Sec: %lf\n",
		       m->id, m->is_exit, t_a, t_b, t_c, m->req_per_sec);
	}

	free(t_a);
	free(t_b);
	free(t_c);
}

void handle_messages(int *sockets, size_t num_sockets, bool show_cpu_usage)
{
	struct itimerspec timeout_timer = { 0 };
	static const long report_interval_sec = 8;
	size_t num_exits_seen = 0;
	struct timespec start;
	double total_bytes = 0.0;
	double total_calls = 0.0;
	int util_timer_fd;
	double loadavg;
	uint32_t request_size = 0;
	int ret;

	util_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	assert(util_timer_fd > 0);

	timeout_timer.it_value.tv_sec = report_interval_sec;
	timeout_timer.it_interval.tv_sec = report_interval_sec;
	timerfd_settime(util_timer_fd, 0, &timeout_timer, NULL);

	clock_gettime(CLOCK_MONOTONIC, &start);
	get_cpu_utilization(&start);

	while (num_exits_seen < num_sockets) {
		fd_set rfds;
		FD_ZERO(&rfds);
		int max_fd = 0;

		for (size_t i = 0; i < num_sockets; ++i) {
			if (sockets[i] > 0) {
				FD_SET(sockets[i], &rfds);
			}
			if (sockets[i] > max_fd) {
				max_fd = sockets[i];
			}
		}
		FD_SET(util_timer_fd, &rfds);
		if (util_timer_fd > max_fd) {
			max_fd = util_timer_fd;
		}

		ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
		assert(ret > 0);

		if (FD_ISSET(util_timer_fd, &rfds)) {
			uint64_t ticks;
			ssize_t r =
				read(util_timer_fd, &ticks, sizeof(uint64_t));
			assert(r == sizeof(uint64_t));
			if (show_cpu_usage) {
				get_cpu_utilization(&start);
			}
		}

		for (size_t i = 0; i < num_sockets; ++i) {
			if (sockets[i] > 0 && FD_ISSET(sockets[i], &rfds)) {
				struct test_msg m;
				ssize_t bytes_read =
					read(sockets[i], &m,
					     sizeof(struct test_msg));
				assert(bytes_read == sizeof(struct test_msg));
				handle_message(&m);
				if (m.is_exit) {
					num_exits_seen++;
					sockets[i] = -1;
					total_calls += m.req_per_sec;
					total_bytes += m.bytes_per_sec;
					request_size = m.request_size;
					assert(request_size == 0 ||
					       m.request_size == request_size);
				}
			}
		}
	}

	ret = getloadavg(&loadavg, 1);
	assert(ret == 1);

	printf("\n");

	char *bytes_s = format_byte_sec(total_bytes);
	printf("Used request size: %u\n", request_size);
	printf("Average Load: %lf\n", loadavg);
	printf("Total calls/sec: %.2lf\n", total_calls);
	printf("Total Byte/sec: %s\n", bytes_s);
	free(bytes_s);

	close(util_timer_fd);
}
