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
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <esdm_rpc_client.h>
#include <unistd.h>
#include <assert.h>

void handle_stress_delay_one_core(double timeout_sec, long id, int sock_fd)
{
	struct timespec start;
	struct timespec before;
	struct timespec after;
	double mean_duration = 0.0;
	double max_duration = 0.0;
	double total_duration = 0.0;
	uint64_t iterations = 0;
	double alpha = 0.2;
	double duration;
	uint32_t rnd;
	ssize_t ret;

	clock_gettime(CLOCK_MONOTONIC, &start);

	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &before);

		esdm_invoke(esdm_rpcc_get_random_bytes_full((uint8_t *)&rnd,
							    sizeof(rnd)));

		clock_gettime(CLOCK_MONOTONIC, &after);

		total_duration = timespec_diff(&start, &before);
		if (total_duration >= timeout_sec)
			break;

		iterations++;
		duration = timespec_diff(&before, &after);

		if (mean_duration > 0.0 && duration > 100.0 * mean_duration) {
			struct test_msg msg = { 0 };
			msg.id = id;
			msg.duration = duration;
			msg.max_duration = max_duration;
			msg.mean_duration = mean_duration;
			msg.req_per_sec = (double)iterations / total_duration;
			msg.iterations = iterations;

			ssize_t written =
				write(sock_fd, &msg, sizeof(struct test_msg));
			assert(written == sizeof(struct test_msg));
		}

		mean_duration =
			alpha * duration + (1.0 - alpha) * mean_duration;

		if (duration > max_duration) {
			max_duration = duration;
		}
	}

	struct test_msg msg = { 0 };
	msg.is_exit = 1;
	msg.id = id;
	msg.duration = 0.0;
	msg.max_duration = max_duration;
	msg.mean_duration = mean_duration;
	msg.iterations = iterations;
	msg.req_per_sec = (double)iterations / total_duration;

	ssize_t written = write(sock_fd, &msg, sizeof(struct test_msg));
	assert(written == sizeof(struct test_msg));

	close(sock_fd);
}
