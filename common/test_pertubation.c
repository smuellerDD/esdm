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

#include <stdint.h>
#include <unistd.h>

#include "helper.h"
#include "test_pertubation.h"

uint32_t seed_entropy[7];
atomic_t seed_entropy_ptr = ATOMIC_INIT(-1);

void esdm_test_seed_entropy(uint32_t ent)
{
	if (atomic_read(&seed_entropy_ptr) >= (int)ARRAY_SIZE(seed_entropy))
		return;

	seed_entropy[atomic_inc(&seed_entropy_ptr)] = ent;
}

/******************************************************************************/

static int disable_fallback = 0;

void esdm_test_disable_fallback(int disable)
{
	disable_fallback = disable;
}

int esdm_test_fallback_fd(int fd)
{
	if (fd < 0 || !disable_fallback)
		return fd;

	return -1;
}
