/*
 * Environment of the code shared with the kernel module esdm_es
 *
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

#ifndef _ESDM_PORTABLE_H
#define _ESDM_PORTABLE_H

/*
 * The code the kernel module esdm_es (kernel/esdm_es) compiles from the ESDM
 * - esdm/crypto/esdm_xdrbg.c - takes the C library and the helpers of the
 * ESDM from here, which provides them from the kernel in the module.
 */

#ifdef __KERNEL__

#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

/* As the one of memset_secure.h */
static inline void memset_secure(void *s, int c, size_t n)
{
	memset(s, c, n);
	barrier_data(s);
}

/* As the one of ret_checkers.h */
#define CKINT(x)                                                               \
	do {                                                                   \
		ret = (x);                                                     \
		if (ret < 0)                                                   \
			goto out;                                              \
	} while (0)

#else /* __KERNEL__ */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "build_bug_on.h"
#include "memset_secure.h"
#include "ret_checkers.h"

#endif /* __KERNEL__ */

#endif /* _ESDM_PORTABLE_H */
