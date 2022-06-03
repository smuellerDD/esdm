/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include "arch.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "helper.h"

uint32_t esdm_online_nodes(void)
{
	static uint32_t cpus = 0xFFFFFFFF;

	/* We do not need more DRNGs than we have CPUs */
	if (cpus == 0xFFFFFFFF) {
#ifdef _POSIX_SOURCE
		long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

		if (ncpus > 0) {
			/*
			 * We do not need more DRNGs than we have threads
			 * available - its counterpart is in function
			 * esdm_curr_node().
			 */
			cpus = min_t(uint32_t, ncpus, THREADING_MAX_THREADS);
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
