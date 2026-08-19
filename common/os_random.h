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

#ifndef OS_RANDOM_H
#define OS_RANDOM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Read random numbers from getrandom(2)
 * @param [out] buf buffer to fill
 * @param [in] buflen size of @p buf in bytes
 * @param [in] flags flags for getrandom(2), e.g. GRND_NONBLOCK
 * @return number of bytes obtained, < 0 on error (negative errno)
 */
ssize_t esdm_os_getrandom(uint8_t *buf, size_t buflen, unsigned int flags);

/**
 * @brief Fill a buffer with random numbers from the operating system
 * @param [out] buf buffer to fill
 * @param [in] buflen size of @p buf in bytes
 * @return 0 on success, < 0 on error (negative errno). The buffer is only
 * 	filled completely or not used at all.
 */
int esdm_os_random(uint8_t *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* OS_RANDOM_H */
