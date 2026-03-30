/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include <selinux/selinux.h>
#include <selinux/restorecon.h>
#include <stdio.h>
#include <stdlib.h>

#include "esdm_logger.h"
#include "ret_checkers.h"
#include "selinux.h"

int esdm_cuse_restore_label(const char *pathname)
{
	return selinux_restorecon(pathname, 0);
}

int esdm_cuse_add_label(const char *pathname, struct fuse_args *fuse_args)
{
	char *tmp = NULL;
	char *con = NULL;
	int ret;
	int len;

	CKINT_LOG(getfilecon(pathname, &con),
		  "Cannot obtain label for file %s\n", pathname);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE, "Obtained SELinux label %s\n",
		    con);

	len = snprintf(NULL, 0, "-ocontext=%s", con);
	if (len < 0) {
		ret = -EINVAL;
		goto out;
	}
	tmp = malloc((size_t)len + 1);
	if (!tmp) {
		ret = -ENOMEM;
		goto out;
	}
	snprintf(tmp, (size_t)len + 1, "-ocontext=%s", con);
	CKINT_LOG(fuse_opt_add_arg(fuse_args, tmp),
		  "Cannot add FUSE argument\n");

out:
	free(tmp);
	if (con)
		freecon(con);
	return ret;
}
