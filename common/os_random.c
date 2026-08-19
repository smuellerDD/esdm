/*
 * Random numbers from the operating system
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "os_random.h"

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif

ssize_t esdm_os_getrandom(uint8_t *buf, size_t buflen, unsigned int flags)
{
#if defined(USE_GLIBC_GETRANDOM) || defined(__NR_getrandom)
	ssize_t ret, totallen = 0;

	if (buflen > INT_MAX)
		return -EINVAL;

	do {
#ifdef USE_GLIBC_GETRANDOM
		ret = getrandom(buf, buflen, flags);
#else
		ret = syscall(__NR_getrandom, buf, buflen, flags);
#endif
		if (ret > 0) {
			buflen -= (size_t)ret;
			buf += ret;
			totallen += ret;
		}
	} while ((ret > 0 || errno == EINTR) && buflen);

	return ((ret < 0) ? -errno : totallen);
#else
	(void)buf;
	(void)buflen;
	(void)flags;
	return -ENOSYS;
#endif
}

int esdm_os_random(uint8_t *buf, size_t buflen)
{
	ssize_t ret = esdm_os_getrandom(buf, buflen, GRND_NONBLOCK);

	if (ret == (ssize_t)buflen)
		return 0;

	/*
	 * A refusal is passed on as it is - -EAGAIN from a kernel RNG that is
	 * not initialized yet, -ENOSYS from a kernel without the system call.
	 */
	return (ret < 0) ? (int)ret : -EIO;
}
