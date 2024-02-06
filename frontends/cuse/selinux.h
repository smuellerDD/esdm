/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef SELINUX_H
#define SELINUX_H

#include <fuse3/fuse_opt.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ESDM_SELINUX_ENABLED

int esdm_cuse_restore_label(const char *pathname);
int esdm_cuse_add_label(const char *pathname, struct fuse_args *fuse_args);

#else /* ESDM_SELINUX_ENABLED */

static inline int esdm_cuse_restore_label(const char *pathname)
{
	(void)pathname;
	return 0;
}

static inline int esdm_cuse_add_label(const char *pathname,
				      struct fuse_args *fuse_args)
{
	(void)pathname;
	(void)fuse_args;
	return 0;
}

#endif /* ESDM_SELINUX_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* SELINUX_H */
