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

#ifndef _ESDM_ES_READER_H
#define _ESDM_ES_READER_H

#include <stddef.h>
#include <stdint.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The device read of an entropy source, bounded by a deadline.
 *
 * Some devices block a read indefinitely, O_NONBLOCK or not: /dev/hwrng waits
 * for the kernel hwrng thread's mutex, held across a virtio-rng request
 * without timeout, /dev/tpmrm0 for whoever has the TPM. As sources are read
 * under the pool and DRNG locks, each read runs on a thread of its own and the
 * caller waits only until a deadline: then -ETIMEDOUT, and the thread is
 * cancelled. One the kernel holds in an uninterruptible wait leaves once that
 * returns; until then every request gets -EBUSY at once.
 */

/*
 * One read of @len bytes from @fd into @buf, which is to give up once the
 * monotonic clock passes @deadline_ns where it can: 0 or a negative errno.
 * It may be cancelled at any cancellation point it does not disable.
 */
typedef int (*esdm_es_reader_op_t)(int fd, uint8_t *buf, size_t len,
				   uint64_t deadline_ns);

struct esdm_es_reader;

/*
 * Set up a reader for @op on @fd, which it owns from now on, closing it on
 * failure too: 0 or a negative errno
 */
int esdm_es_reader_alloc(struct esdm_es_reader **reader, int fd,
			 esdm_es_reader_op_t op, const char *name);

/*
 * Stop @reader and close its fd; a timed-out read still running is left to
 * its thread, which frees everything when it returns. @reader may be NULL.
 */
void esdm_es_reader_free(struct esdm_es_reader *reader);

/*
 * Read @len bytes (at most struct entropy_es.e) into @buf, waiting until
 * @deadline_ns (esdm_monotonic_wait_ns()) at most, also for another caller's
 * read if @wait. Returns 0, the read's error, -ETIMEDOUT for this read, or
 * -EBUSY without a turn: a timed-out read is pending, another read is in
 * progress and @wait is not set or the deadline passes waiting for it.
 */
int esdm_es_reader_read(struct esdm_es_reader *reader, uint8_t *buf, size_t len,
			uint64_t deadline_ns, bool wait);

/* Is a read that timed out still in progress? */
bool esdm_es_reader_stuck(struct esdm_es_reader *reader);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_ES_READER_H */
