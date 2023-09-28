/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef CUSE_DEVICE_H
#define CUSE_DEVICE_H

#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS 64
#include <fuse3/fuse.h>
#include <fuse3/cuse_lowlevel.h>

#include "esdm_rpc_client.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ssize_t (*get_func_t)(uint8_t *buf, size_t buflen, void *int_data);

void esdm_cuse_init_done(void *userdata);
void esdm_cuse_open(fuse_req_t req, struct fuse_file_info *fi);
void esdm_cuse_read_internal(fuse_req_t req, size_t size, off_t off,
			     struct fuse_file_info *fi, get_func_t get,
			     int fallback_fd);
void esdm_cuse_write_internal(fuse_req_t req, const char *buf, size_t size,
			      off_t off, struct fuse_file_info *fi,
			      int fallback_fd);
void esdm_cuse_ioctl(int backend_fd, fuse_req_t req, unsigned long cmd,
		     void *arg, struct fuse_file_info *fi, unsigned flags,
		     const void *in_buf, size_t in_bufsz, size_t out_bufsz);
void esdm_cuse_poll(fuse_req_t req, struct fuse_file_info *fi,
		    struct fuse_pollhandle *ph);
void esdm_cuse_release(fuse_req_t req, struct fuse_file_info *fi);
int main_common(const char *devname, const char *target, const char *semname,
		const struct cuse_lowlevel_ops *clop, int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* CUSE_DEVICE_H */
