/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef LINUX_SUPPORT_H
#define LINUX_SUPPORT_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Leave the mount, cgroup and network namespaces of the host.
 *
 * unshare(2) moves the calling thread only: call before creating threads.
 */
int linux_isolate_namespace(void);
/**
 * @brief Whether a task holds CAP_SYS_ADMIN in our user namespace.
 *
 * @param [in] pid Thread or process ID in the PID namespace of our /proc.
 *
 * @return 1 if it does, 0 if not, < 0 where that cannot be told.
 */
int linux_task_has_cap_sys_admin(pid_t pid);
/**
 * @brief Fork the daemon into an isolating PID namespace.
 *
 * The calling process becomes a pure supervisor that forwards signals and
 * mirrors the daemon's exit status; only the child returns from this call.
 *
 * @param [in] supervisor_exit_cb Optional callback (may be NULL) the
 *	       supervisor invokes - with its retained privileges - after the
 *	       daemon terminated and before it exits itself.
 */
int linux_isolate_namespace_prefork(void (*supervisor_exit_cb)(void));
int linux_personalization_string(char **ptr, size_t *length);

#ifdef __cplusplus
}
#endif

#endif /* LINUX_SUPPORT_H */
