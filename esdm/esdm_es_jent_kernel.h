/*
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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

#ifndef _ESDM_ES_JENT_KERNEL_H
#define _ESDM_ES_JENT_KERNEL_H

#include <errno.h>

#include "config.h"
#include "esdm_es_mgr_cb.h"
#include "visibility.h"

/*
 * The longest name of an algorithm of the kernel crypto API the source opens,
 * the terminating NUL included - CRYPTO_MAX_ALG_NAME of the kernel
 */
#define CRYPTO_MAX_ALG_NAME_ESDM 128

#ifdef ESDM_ES_JENT_KERNEL

extern struct esdm_es_cb esdm_es_jent_kernel;

/**
 * @brief Select the kernel crypto API RNG the source reads
 *
 * The name replaces the compile-time default ESDM_JENT_KERNEL_NAME (meson
 * option es_jent_kernel_name, "jitterentropy_rng" by default): the name or the
 * driver name of an RNG of /proc/crypto, opened through AF_ALG - e.g. that of a
 * jitterentropy kernel module registering its RNG under another name than the
 * one of the kernel. Set before esdm_init(), as the server does for its
 * --es_jent_kernel_name option, it is opened by the initialization of the
 * source; set later, the RNG in use is replaced right away. Pass an empty
 * string to go back to the compile-time default. The name is kept across
 * esdm_fini().
 *
 * @param [in] name NUL-terminated name, must not be NULL.
 *
 * @return 0 on success, -EINVAL if name is NULL or too long, -ENOMEM on
 *	   allocation failure, or - when the source already runs - a negative
 *	   errno from opening the RNG.
 */
DSO_PUBLIC
int esdm_es_jent_kernel_set_name(const char *name);

#else /* ESDM_ES_JENT_KERNEL */

static inline int esdm_es_jent_kernel_set_name(const char *name)
{
	(void)name;
	return -ENOENT;
}

#endif /* ESDM_ES_JENT_KERNEL */

#endif /* _ESDM_ES_JENT_KERNEL_H */
