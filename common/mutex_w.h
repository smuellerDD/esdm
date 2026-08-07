/*
 * Copyright (C) 2018 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#ifndef _MUTEX_W_PTHREAD_H
#define _MUTEX_W_PTHREAD_H

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include <stdbool.h>
#include "ret_checkers.h"

/**
 * @brief Reader / Writer mutex based on pthread
 */
typedef struct {
	pthread_mutex_t lock;
	int ma_used;
	pthread_mutexattr_t ma;
	int robust;
} mutex_w_t;

#define MUTEX_W_UNLOCKED { .lock = PTHREAD_MUTEX_INITIALIZER, .ma_used = 0 }
#define DEFINE_MUTEX_W_UNLOCKED(name) mutex_w_t name = MUTEX_W_UNLOCKED

#define DEFINE_MUTEX_W_LOCKED(name) error "DEFINE_MUTEX_LOCKED not implemented"

/**
 * Mutual exclusion lock (covering also the reader lock use case).
 *
 * For a robust mutex, EOWNERDEAD is returned when the lock was taken but its
 * previous owner died while holding it. The lock is made consistent again
 * before returning, so the caller owns it in that case as well - but whatever
 * the lock protects was left behind mid-update and has to be recovered by the
 * caller. Callers that have no such state can ignore the distinction; those
 * that do must handle it (see the connection reset in esdm_client_invoke).
 *
 * @param [in] mutex lock variable to lock
 * @return 0 if the lock was taken, EOWNERDEAD if it was taken from a died
 *	   owner, the positive errno of the failure otherwise
 */
static inline int mutex_w_lock(mutex_w_t *mutex)
{
	int ret = pthread_mutex_lock(&mutex->lock);
	if (mutex->robust) {
		assert(ret == 0 || ret == EOWNERDEAD);
	} else {
		assert(ret == 0);
	}
	if (ret == EOWNERDEAD) {
		pthread_mutex_consistent(&mutex->lock);
	}
	return ret;
}

/**
 * Unlock the lock
 * @param [in] mutex lock variable to lock
 */
static inline int mutex_w_unlock(mutex_w_t *mutex)
{
	/*
	 * Sample the flag while the lock is still held: the unlock may be what
	 * another thread is waiting for to destroy and free the object holding
	 * this mutex (see the connection teardown in the RPC client), so the
	 * mutex must not be touched any more once it is released.
	 */
	int robust = mutex->robust;
	int ret = pthread_mutex_unlock(&mutex->lock);

	if (robust) {
		assert(ret == 0 || ret == EOWNERDEAD);
		if (ret == EOWNERDEAD)
			pthread_mutex_consistent(&mutex->lock);
	} else {
		assert(ret == 0);
	}
	return ret;
}

/**
 * @brief Initialize a mutex
 * @param [in] mutex Lock variable to initialize.
 * @param [in] locked Specify whether the lock shall already be locked (1)
 *		      or unlocked (0).
 * @param [in] robust initialize a robust mutex (1) or not (0)
 */
static inline int mutex_w_init(mutex_w_t *mutex, int locked, int robust)
{
	int ret = 0;

	/*
	 * pthread_* report errors as POSITIVE errno values, so the CKINT (which
	 * only branches on ret < 0) used here previously let every failure slip
	 * through and returned a partially/never-initialized mutex as success.
	 * Negate the returns so failures are detected and propagated as the
	 * negative-errno convention the callers expect.
	 */

	/* Always initialize robust so lock/unlock do not read an indeterminate
	 * value when the struct was not zeroed by the caller. */
	mutex->robust = 0;

	CKINT(-pthread_mutexattr_init(&mutex->ma));
	mutex->ma_used = 1;

	if (robust) {
		CKINT(-pthread_mutexattr_setrobust(&mutex->ma,
						   PTHREAD_MUTEX_ROBUST));
		mutex->robust = 1;
	}

	CKINT(-pthread_mutex_init(&mutex->lock, &mutex->ma));

	/*
	 * mutex_w_lock returns 0 (or, only for an already-contended robust
	 * mutex, EOWNERDEAD which it recovers); a freshly created mutex cannot
	 * yield EOWNERDEAD, so a non-zero result is a genuine error.
	 */
	if (locked) {
		ret = mutex_w_lock(mutex);
		if (ret) {
			ret = -ret;
			goto out;
		}
	}

out:
	return ret;
}

/**
 * @brief Destroy a mutex and the attribute it was created with
 *
 * Destroying a robust mutex fails with EBUSY while it is still held by a died
 * owner that nobody recovered. The attribute is released even then so it is
 * not leaked, and the failure is still reported.
 *
 * @param [in] mutex Lock variable to destroy.
 * @return 0 on success, < 0 on error
 */
static inline int mutex_w_destroy(mutex_w_t *mutex)
{
	/*
	 * pthread_* report errors as POSITIVE errno values, so the CKINT used
	 * here previously (it only branches on ret < 0) let every failure slip
	 * through and additionally returned a positive value where the callers
	 * expect a negative errno. Negate the returns instead.
	 */
	int ret = -pthread_mutex_destroy(&mutex->lock);

	if (mutex->ma_used) {
		int attr_ret = -pthread_mutexattr_destroy(&mutex->ma);

		if (!attr_ret)
			mutex->ma_used = 0;
		if (!ret)
			ret = attr_ret;
	}

	return ret;
}

/**
 * Mutual exclusion lock: Attempt to take the lock. The function will never
 * block but return whether the lock was successfully taken or not.
 *
 * For a robust mutex whose previous owner died while holding it, the lock is
 * recovered and reported as taken: the caller owns it either way, and
 * returning the raw EOWNERDEAD would make every "did I get it" test treat a
 * lock that is now held as not taken - never to be unlocked again.
 *
 * Use mutex_w_lock() where the death of the previous owner has to be observed
 * because the data behind the lock needs to be recovered as well.
 *
 * @param [in] mutex lock variable to lock
 * @return 0 if the lock was taken, EBUSY if it was not
 */
static inline int mutex_w_trylock(mutex_w_t *mutex)
{
	int ret = pthread_mutex_trylock(&mutex->lock);

	assert(ret == 0 || ret == EBUSY || ret == EOWNERDEAD);

	if (ret == EOWNERDEAD) {
		pthread_mutex_consistent(&mutex->lock);
		ret = 0;
	}

	return ret;
}

/*
 * both current glibc and musl libc implement a clock-based
 * timed locking, which can use a monotonic clock.
*/
extern int pthread_mutex_clocklock(pthread_mutex_t *mutex, clockid_t clockid,
				   const struct timespec *abstime);

/**
 * Mutual exclusion lock: take the lock, giving up at the absolute deadline.
 *
 * A robust mutex whose previous owner died is recovered and reported as taken -
 * see mutex_w_trylock() for why the raw EOWNERDEAD is not passed on.
 *
 * @param [in] mutex lock variable to lock
 * @param [in] abstime absolute CLOCK_MONOTONIC deadline
 * @return 0 if the lock was taken, ETIMEDOUT if the deadline passed first
 */
static inline int mutex_w_timedlock(mutex_w_t *mutex,
				    const struct timespec *abstime)
{
	int ret =
		pthread_mutex_clocklock(&mutex->lock, CLOCK_MONOTONIC, abstime);

	assert(ret == 0 || ret == ETIMEDOUT || ret == EOWNERDEAD);

	if (ret == EOWNERDEAD) {
		pthread_mutex_consistent(&mutex->lock);
		ret = 0;
	}

	return ret;
}

#endif /* _MUTEX_W_PTHREAD_H */
