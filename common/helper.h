/*
 * Copyright (C) 2018 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef HELPER_H
#define HELPER_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define __aligned(x) __attribute__((aligned(x)))
#define __unused __attribute__((__unused__))
#define __maybe_unused __attribute__((__unused__))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define member_to_struct(member, data_type, member_var)                        \
	(data_type *)((char *)(member) - (char *)&((data_type *)0)->member_var)

/* Whole seconds on CLOCK_MONOTONIC, 0 if the clock cannot be read */
static inline long long esdm_monotonic_now(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return 0;

	return (long long)now.tv_sec;
}

/* Seconds elapsed since timeout_sec (CLOCK_MONOTONIC), 0 if not yet reached */
static inline time_t esdm_time_after_now(time_t timeout_sec)
{
	time_t curr = (time_t)esdm_monotonic_now();

	return (curr > timeout_sec) ? (curr - timeout_sec) : 0;
}

static inline int aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

uint32_t esdm_online_nodes(void);
uint32_t esdm_curr_node(void);
ssize_t esdm_safe_read(int fd, uint8_t *buf, size_t buflen);
ssize_t esdm_safe_write(int fd, uint8_t *buf, size_t buflen);
void may_enable_memory_debugging(void);

#ifdef __cplusplus
}
#endif

#endif /* HELPER_H */
