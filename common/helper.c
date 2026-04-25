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

#include "config.h"

#include "arch.h"

#ifdef ESDM_MEMORY_DEBUG
#include <malloc.h>
#include <mcheck.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "math_helper.h"

uint32_t esdm_online_nodes(void)
{
	static uint32_t cpus = UINT32_MAX;

	/* We do not need more DRNGs than we have CPUs */
	if (cpus == UINT32_MAX) {
#ifdef _GNU_SOURCE
		long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

		if (ncpus > 0) {
			/*
			 * We do not need more DRNGs than we have threads
			 * available - its counterpart is in function
			 * esdm_curr_node().
			 */
			cpus = min_uint32((uint32_t)ncpus,
					  THREADING_MAX_WORKER_THREADS);
		} else {
			cpus = 1;
		}
#else
		cpus = 1;
#endif
	}

	return cpus;
}

uint32_t esdm_curr_node(void)
{
	uint32_t cpu = esdm_arch_curr_node();

	/*
	 * Limit the CPU selection by number of available threads - this is the
	 * counterpart to esdm_config_online_nodes.
	 */
	return (cpu % esdm_online_nodes());
}

ssize_t esdm_safe_read(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t readlen;
	ssize_t bytes_read = 0;

	do {
		readlen = read(fd, buf, buflen);
		if (readlen > 0) {
			buflen -= (size_t)readlen;
			buf += (size_t)readlen;
			bytes_read += readlen;
		} else if (readlen == 0) {
			goto out;
		} else if (errno != EINTR) {
			bytes_read = -errno;
			goto out;
		}
	} while (buflen);

out:
	return bytes_read;
}

ssize_t esdm_safe_write(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t writelen;
	ssize_t bytes_written = 0;

	do {
		writelen = write(fd, buf, buflen);
		if (writelen > 0) {
			buflen -= (size_t)writelen;
			buf += (size_t)writelen;
			bytes_written += writelen;
		} else if (writelen == 0) {
			goto out;
		} else if (errno != EINTR) {
			bytes_written = -errno;
			goto out;
		}
	} while (buflen);

out:
	return bytes_written;
}

void may_enable_memory_debugging()
{
#ifdef ESDM_MEMORY_DEBUG
	/* perform consistency checks */
	mcheck_pedantic(NULL);

	/* release memory fast, in order to
	 * check total consumption externally */
	mallopt(M_TRIM_THRESHOLD, 0);
	mallopt(M_MMAP_THRESHOLD, 0);
	mallopt(M_MMAP_MAX, -1);

	/* set newly allocated and freed memory
	 * to this value */
	mallopt(M_PERTURB, 0xff);

	/* memory options should be called very early,
	 * logger is typically not set up*/
	fprintf(stderr,
		"WARNING: Memory debugging enabled. Don't use in production.\n");
#endif
}
