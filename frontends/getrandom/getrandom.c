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

#include <errno.h>
#include <limits.h>
#include <linux/random.h>
#include <sys/random.h>

#include "constructor.h"
#include "esdm_rpc_client.h"
#include "visibility.h"

ESDM_DEFINE_CONSTRUCTOR(esdm_getrandom_lib_init);
static void esdm_getrandom_lib_init(void)
{
	esdm_rpcc_set_max_online_nodes(1);
	/* Return code irrelevant due to fallback in functions below */
	esdm_rpcc_init_unpriv_service(NULL);
}

ESDM_DEFINE_DESTRUCTOR(esdm_getrandom_lib_exit);
static void esdm_getrandom_lib_exit(void)
{
	esdm_rpcc_fini_unpriv_service();
}

ssize_t __real_getrandom(void *__buffer, size_t __length, unsigned int __flags);
int __real_getentropy(void *__buffer, size_t __length);

DSO_PUBLIC
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags)
{
	ssize_t ret;

	if (flags & (unsigned int)(~(GRND_NONBLOCK|GRND_RANDOM|GRND_INSECURE)))
		return -EINVAL;

	/*
	 * Requesting insecure and blocking randomness at the same time makes
	 * no sense.
	 */
	if ((flags &
	     (GRND_INSECURE|GRND_RANDOM)) == (GRND_INSECURE|GRND_RANDOM))
		return -EINVAL;

	if (length > INT_MAX)
		length = INT_MAX;

	if (flags & GRND_INSECURE) {
		esdm_invoke(esdm_rpcc_get_random_bytes(buffer, length));
	} else {
		esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, length));
	}

	if (ret >= 0)
		return ret;

	return __real_getrandom(buffer, length, flags);
}

DSO_PUBLIC
ssize_t getrandom(void *buffer, size_t length, unsigned int flags)
{
	return __wrap_getrandom(buffer, length, flags);
}

DSO_PUBLIC
int __wrap_getentropy(void *buffer, size_t length)
{
	ssize_t ret = -EFAULT;

	if (length > 256)
		return -EIO;

	esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, length));
	if (ret < 0)
		return __real_getentropy(buffer, length);
	return 0;
}

DSO_PUBLIC
int getentropy(void *buffer, size_t length)
{
	return __wrap_getentropy(buffer, length);
}
