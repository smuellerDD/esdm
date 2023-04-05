/*
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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

#include <pthread.h>

#include "bool.h"

/**
 * @brief Reader / Writer mutex based on pthread
 */
typedef struct {
	pthread_mutex_t lock;
	int ma_used;
	pthread_mutexattr_t ma;
} mutex_w_t;

#define MUTEX_W_UNLOCKED { .lock = PTHREAD_MUTEX_INITIALIZER, .ma_used = 0 }
#define DEFINE_MUTEX_W_UNLOCKED(name)	mutex_w_t name = MUTEX_W_UNLOCKED

#define DEFINE_MUTEX_W_LOCKED(name) error "DEFINE_MUTEX_LOCKED not implemented"

/**
 * Mutual exclusion lock (covering also the reader lock use case).
 * @param [in] mutex lock variable to lock
 */
static inline void mutex_w_lock(mutex_w_t *mutex)
{
	pthread_mutex_lock(&mutex->lock);
}

/**
 * Unlock the lock
 * @param [in] mutex lock variable to lock
 */
static inline void mutex_w_unlock(mutex_w_t *mutex)
{
	pthread_mutex_unlock(&mutex->lock);
}

/**
 * @brief Initialize a mutex
 * @param [in] mutex Lock variable to initialize.
 * @param [in] locked Specify whether the lock shall already be locked (1)
 *		      or unlocked (0).
 * @param [in] robust initialize a robust mutex (1) or not (0)
 */
static inline void mutex_w_init(mutex_w_t *mutex, int locked, int robust)
{
	pthread_mutexattr_init(&mutex->ma);
	mutex->ma_used = 1;

	if (robust)
		pthread_mutexattr_setrobust(&mutex->ma, PTHREAD_MUTEX_ROBUST);

	pthread_mutex_init(&mutex->lock, &mutex->ma);

	if (locked)
		mutex_w_lock(mutex);
}

static inline void mutex_w_destroy(mutex_w_t *mutex)
{
	pthread_mutex_destroy(&mutex->lock);
	if (mutex->ma_used)
		pthread_mutexattr_destroy(&mutex->ma);
}

/**
 * Mutual exclusion lock: Attempt to take the lock. The function will never
 * block but return whether the lock was successfully taken or not.
 *
 * @param [in] mutex lock variable to lock
 * @return true if lock was taken, false if lock was not taken
 */
static inline bool mutex_w_trylock(mutex_w_t *mutex)
{
	if (pthread_mutex_trylock(&mutex->lock))
		return false;
	return true;
}

#endif /* _MUTEX_W_PTHREAD_H */
