/*
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

#ifndef _ESDM_PPOLL_H
#define _ESDM_PPOLL_H

/* ppoll(2) is a GNU extension: _GNU_SOURCE before the first include */
#include <poll.h>
#include <time.h>

/* ppoll(2) with a timeout in milliseconds, a negative one for none */
static inline int esdm_ppoll_ms(struct pollfd *fds, nfds_t nfds,
				int timeout_ms)
{
	struct timespec ts = {
		.tv_sec = timeout_ms / 1000,
		.tv_nsec = (long)(timeout_ms % 1000) * 1000000,
	};

	return ppoll(fds, nfds, timeout_ms < 0 ? NULL : &ts, NULL);
}

#endif /* _ESDM_PPOLL_H */
