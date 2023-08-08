/*
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef ARCH_H
#define ARCH_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__linux__)

#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>

#include <stdint.h>

#include "config.h"
#include "helper.h"
#include "threading_support.h"

static inline uint32_t esdm_arch_curr_node(void)
{
	int cpu = sched_getcpu();

	if (cpu < 0)
		return 0;
	return (uint32_t)cpu;
}

#else /* __linux__ */

#error "Unknown Operating System"

#endif /* __linux__ */

#ifdef __cplusplus
}
#endif

#endif /* ARCH_H */
