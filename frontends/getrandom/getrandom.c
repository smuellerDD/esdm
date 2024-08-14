/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "atomic_bool.h"
#include "bool.h"
#include "constructor.h"
#include "esdm_rpc_client.h"
#include "mutex.h"
#include "visibility.h"

/**
 * @brief GRND_SEED
 *
 * This flag requests to provide the data directly from the entropy sources.
 *
 * The behavior of the call is exactly as outlined for the function
 * esdm_get_seed in esdm.h.
 */
#define GRND_SEED 0x0010

/**
 * @brief GRND_FULLY_SEEDED
 *
 * This flag indicates whether the caller wants to reseed a DRNG that is already
 * fully seeded. See esdm_get_seed in esdm.h for details.
 */
#define GRND_FULLY_SEEDED 0x0020

static atomic_bool_t is_initialized = ATOMIC_BOOL_INIT(false);
static DEFINE_MUTEX_UNLOCKED(getrandom_mutex);

static void esdm_getrandom_lib_init(void)
{
	mutex_lock(&getrandom_mutex);

	/* Return code irrelevant due to fallback in functions below */
	esdm_rpcc_init_unpriv_service(NULL);

	atomic_bool_set_true(&is_initialized);
	mutex_unlock(&getrandom_mutex);
}

ESDM_DEFINE_DESTRUCTOR(esdm_getrandom_lib_exit);
static void esdm_getrandom_lib_exit(void)
{
	esdm_rpcc_fini_unpriv_service();
}

ssize_t __real_getrandom(void *__buffer, size_t __length, unsigned int __flags);
DSO_PUBLIC
ssize_t __real_getrandom(void *__buffer, size_t __length, unsigned int __flags)
{
	return syscall(__NR_getrandom, __buffer, __length, __flags);
}

static ssize_t getrandom_common(void *buffer, size_t length, unsigned int flags)
{
	ssize_t ret;

	if (flags &
	    (unsigned int)(~(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE |
			     GRND_SEED | GRND_FULLY_SEEDED)))
		return -EINVAL;

	/*
	 * Requesting insecure and blocking randomness at the same time makes
	 * no sense.
	 */
	if ((flags & (GRND_INSECURE | GRND_RANDOM)) ==
	    (GRND_INSECURE | GRND_RANDOM))
		return -EINVAL;
	if ((flags & (GRND_INSECURE | GRND_SEED)) ==
	    (GRND_INSECURE | GRND_SEED))
		return -EINVAL;
	if ((flags & (GRND_RANDOM | GRND_SEED)) == (GRND_RANDOM | GRND_SEED))
		return -EINVAL;

	if (length > INT_MAX)
		length = INT_MAX;

	if (!atomic_bool_read(&is_initialized)) {
		esdm_getrandom_lib_init();
	}

	if (flags & GRND_INSECURE) {
		esdm_invoke(esdm_rpcc_get_random_bytes(buffer, length));
	} else if (flags & GRND_RANDOM) {
		esdm_invoke(esdm_rpcc_get_random_bytes_pr(buffer, length));
	} else if (flags & GRND_SEED) {
		unsigned int seed_flags =
			(flags & GRND_NONBLOCK) ? ESDM_GET_SEED_NONBLOCK : 0;

		seed_flags |= (flags & GRND_FULLY_SEEDED) ?
				      ESDM_GET_SEED_FULLY_SEEDED :
				      0;
		esdm_invoke(esdm_rpcc_get_seed(buffer, length, seed_flags));
		if (ret < 0) {
			errno = (int)(-ret);
			ret = -1;
		}
		return ret;
	} else {
		esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, length));
	}

	if (ret >= 0)
		return ret;

	return syscall(__NR_getrandom, buffer, length, flags);
}

/* Declare the prototype even though libc declares it internally */
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags);
DSO_PUBLIC
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags)
{
	return getrandom_common(buffer, length, flags);
}

DSO_PUBLIC
ssize_t getrandom(void *buffer, size_t length, unsigned int flags)
{
	return getrandom_common(buffer, length, flags);
}

int __real_getentropy(void *__buffer, size_t __length);
DSO_PUBLIC
int __real_getentropy(void *__buffer, size_t __length)
{
	if (__length > 256)
		return -EIO;

	return (int)syscall(__NR_getrandom, __buffer, __length, 0);
}

static int getentropy_common(void *buffer, size_t length)
{
	ssize_t ret = -EFAULT;

	if (length > 256)
		return -EIO;

	if (!atomic_bool_read(&is_initialized)) {
		esdm_getrandom_lib_init();
	}

	esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, length));
	if (ret < 0) {
		ssize_t rc = syscall(__NR_getrandom, buffer, length, 0);

		/* Kernel returned an error */
		if (rc < 0) {
			/* errno is already set properly */
			return (int)rc;
		}

		/* We received insufficient data */
		if ((size_t)rc != length) {
			errno = -EFAULT;
			return -1;
		}
	}
	return 0;
}

/* Declare the prototype even though libc declares it internally */
int __wrap_getentropy(void *buffer, size_t length);
DSO_PUBLIC
int __wrap_getentropy(void *buffer, size_t length)
{
	return getentropy_common(buffer, length);
}

DSO_PUBLIC
int getentropy(void *buffer, size_t length)
{
	return getentropy_common(buffer, length);
}
