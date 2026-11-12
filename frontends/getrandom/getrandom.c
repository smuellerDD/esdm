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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdatomic.h>
#include <stdbool.h>
#include "config.h"
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

static atomic_bool is_initialized = false;
static atomic_bool use_esdm = false;
static DEFINE_MUTEX_UNLOCKED(getrandom_mutex);

/*
 * Present where the ESDM itself runs in this process - esdm-server links it.
 * Weak, so the library loads into every other process all the same.
 */
extern int esdm_init(void) __attribute__((weak));

/*
 * May this process ask the ESDM at all? Not as PID 1: preloaded via
 * /etc/ld.so.preload, the init would wait on a socket only it activates. Nor
 * where the ESDM runs in this process, which would ask itself for its seed.
 */
static bool esdm_getrandom_may_use_esdm(void)
{
	return getpid() != 1 && !esdm_init;
}

static void esdm_getrandom_lib_init(void)
{
	mutex_lock(&getrandom_mutex);

	// are we may already initialized from another thread?
	if (atomic_load(&is_initialized)) {
		goto out;
	}

	if (!esdm_getrandom_may_use_esdm())
		goto done;

#if ESDM_GETRANDOM_NUM_NODES > 0
	esdm_rpcc_set_max_online_nodes(ESDM_GETRANDOM_NUM_NODES);
#endif

	/* Return code irrelevant due to fallback in functions below */
	esdm_rpcc_init_unpriv_service(NULL);
	atomic_store(&use_esdm, true);

done:
	atomic_store(&is_initialized, true);

out:
	mutex_unlock(&getrandom_mutex);
}

ESDM_DEFINE_DESTRUCTOR(esdm_getrandom_lib_exit);
static void esdm_getrandom_lib_exit(void)
{
	if (atomic_load(&use_esdm))
		esdm_rpcc_fini_unpriv_service();
}

ssize_t __real_getrandom(void *__buffer, size_t __length, unsigned int __flags);
DSO_PUBLIC
ssize_t __real_getrandom(void *__buffer, size_t __length, unsigned int __flags)
{
	return syscall(__NR_getrandom, __buffer, __length, __flags);
}

/*
 * GRND_NONBLOCK: what the ESDM serves right away, nothing (EAGAIN) before it
 * is fully seeded - as the kernel's getrandom() before its CRNG is ready.
 */
static ssize_t getrandom_nonblock(uint8_t *buffer, size_t length,
				  ssize_t (*get)(uint8_t *buf, size_t buflen))
{
	size_t done = 0;
	ssize_t ret = 0;

	while (done < length) {
		esdm_invoke(get(buffer + done, length - done));
		if (ret <= 0)
			break;
		done += (size_t)ret;
	}

	return done ? (ssize_t)done : ret;
}

static ssize_t getrandom_common(void *buffer, size_t length, unsigned int flags)
{
	ssize_t ret;

	/* The system call's conventions: -1 and errno */
	if (flags &
	    (unsigned int)(~(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE |
			     GRND_SEED | GRND_FULLY_SEEDED)))
		goto einval;

	/*
	 * Requesting insecure and blocking randomness at the same time makes
	 * no sense.
	 */
	if ((flags & (GRND_INSECURE | GRND_RANDOM)) ==
	    (GRND_INSECURE | GRND_RANDOM))
		goto einval;
	if ((flags & (GRND_INSECURE | GRND_SEED)) ==
	    (GRND_INSECURE | GRND_SEED))
		goto einval;
	if ((flags & (GRND_RANDOM | GRND_SEED)) == (GRND_RANDOM | GRND_SEED))
		goto einval;

	/*
	 * Cap to INT_MAX to match the kernel getrandom() behavior which
	 * also limits the output to at most INT_MAX bytes per call.
	 */
	if (length > INT_MAX)
		length = INT_MAX;

	if (!atomic_load(&is_initialized)) {
		esdm_getrandom_lib_init();
	}

	if (!atomic_load(&use_esdm))
		goto kernel;

	if (flags & GRND_INSECURE) {
		esdm_invoke(esdm_rpcc_get_random_bytes(buffer, length));
	} else if ((flags & GRND_NONBLOCK) && !(flags & GRND_SEED)) {
		ret = getrandom_nonblock(
			buffer, length,
			(flags & GRND_RANDOM) ?
				esdm_rpcc_get_random_bytes_pr_noblock :
				esdm_rpcc_get_random_bytes_full_noblock);
		if (ret == -EAGAIN) {
			errno = EAGAIN;
			return -1;
		}
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

	/* Whatever kept the ESDM from answering, the kernel does */
kernel:
	/* The kernel knows nothing of a seed request */
	if (flags & GRND_SEED) {
		errno = EOPNOTSUPP;
		return -1;
	}
	return syscall(__NR_getrandom, buffer, length, flags);

einval:
	errno = EINVAL;
	return -1;
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
	ssize_t ret;

	/* getentropy(3) semantics: 0 on success, -1 with errno on error. */
	if (__length > 256) {
		errno = EIO;
		return -1;
	}

	ret = syscall(__NR_getrandom, __buffer, __length, 0);
	if (ret < 0)
		/* the syscall already set errno */
		return -1;
	if ((size_t)ret != __length) {
		/* getentropy must fill the whole buffer or fail */
		errno = EIO;
		return -1;
	}

	return 0;
}

static int getentropy_common(void *buffer, size_t length)
{
	ssize_t ret = -EFAULT;

	/* getentropy(3) semantics: 0 on success, -1 with errno on error. */
	if (length > 256) {
		errno = EIO;
		return -1;
	}

	if (!atomic_load(&is_initialized)) {
		esdm_getrandom_lib_init();
	}

	if (atomic_load(&use_esdm))
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
			errno = EFAULT;
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
