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

/*
 * Events for the interrupt entropy source of the kernel add-on, for the tests
 * that need it to collect some.
 *
 * The add-on collects in add_interrupt_randomness(), which the kernel calls for
 * device interrupts only - not for the local timer interrupts that expiring
 * hrtimers and the scheduler tick raise. Sleeping arms timers, so it creates no
 * event for the add-on. What does is the completion of a request to a block
 * device: a read with O_DIRECT bypasses the page cache, so each one is a
 * request to the device, completed by an interrupt. The block read is written
 * and synced once before - a hole in the file would be read without a request.
 *
 * Reads rather than synchronous writes, which are completed by an interrupt as
 * well: the fdatasync() waiting for a write flushes the cache of the device
 * besides, which in a virtual machine syncs the disk image on the host - 6.6 ms
 * a write against 0.08 ms a read in the VM of the coverage run, each read one
 * interrupt.
 *
 * The file is created in the working directory - the build directory under
 * meson - rather than in /tmp, which may be a tmpfs without a device to read
 * from. It is unlinked at once.
 *
 * O_DIRECT needs _GNU_SOURCE, defined before the first header is included.
 */

#ifndef ES_IRQ_EVENTS_H
#define ES_IRQ_EVENTS_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_DIRECT
#error "es_irq_events.h needs _GNU_SOURCE defined before the first include"
#endif

/* The block read, of the logical block size of any device and aligned to it */
#define ES_IRQ_EVENTS_BLOCK 4096

/*
 * Read a block from the device @reads times. Returns 0, or a negative errno
 * when a read failed, or when there was no file to read from with O_DIRECT.
 */
static inline int es_irq_events(unsigned int reads)
{
	char name[] = "es_irq_events_XXXXXX";
	void *block = NULL;
	unsigned int i;
	int fd, ret = 0;
	ssize_t n;

	if (posix_memalign(&block, ES_IRQ_EVENTS_BLOCK, ES_IRQ_EVENTS_BLOCK))
		return -ENOMEM;

	fd = mkstemp(name);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	unlink(name);

	memset(block, 0x5a, ES_IRQ_EVENTS_BLOCK);
	n = pwrite(fd, block, ES_IRQ_EVENTS_BLOCK, 0);
	if (n != ES_IRQ_EVENTS_BLOCK) {
		ret = n < 0 ? -errno : -EIO;
		goto out;
	}
	if (fdatasync(fd) || fcntl(fd, F_SETFL, O_DIRECT)) {
		ret = -errno;
		goto out;
	}

	for (i = 0; i < reads; i++) {
		n = pread(fd, block, ES_IRQ_EVENTS_BLOCK, 0);
		if (n != ES_IRQ_EVENTS_BLOCK) {
			ret = n < 0 ? -errno : -EIO;
			break;
		}
	}

out:
	if (fd >= 0)
		close(fd);
	free(block);
	return ret;
}

#endif /* ES_IRQ_EVENTS_H */
