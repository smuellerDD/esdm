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

#ifndef ESDM_TOOL_H
#define ESDM_TOOL_H

#include <stdint.h>
#include <time.h>

struct test_msg {
	/* set to 1 to signal test fn exit and give final results, otherwise outlier info */
	int is_exit;

	long id;

	double duration;
	double mean_duration;
	double max_duration;
	double req_per_sec;

	uint64_t iterations;
};

extern double timespec_diff(const struct timespec *start,
			    const struct timespec *end);
extern char *format_time_sec(double time_sec);

extern void handle_stress_delay_one_core(double timeout_sec, long id,
					 int sock_fd);
extern void handle_stress_process(double timeout_sec);
extern void handle_stress_thread(double timeout_sec, int num_threads);

extern void handle_messages(int *sockets, size_t num_sockets);

#endif /* ESDM_TOOL_H */
