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

#ifndef QUEUE_H
#define QUEUE_H

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int pthread_cond_clockwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
				  clockid_t clockid,
				  const struct timespec *abstime);

struct thread_wait_queue {
	pthread_cond_t thread_wait_cv;
	pthread_mutex_t thread_wait_lock;
};

static inline void thread_wait_queue_unlock(void *lock)
{
	pthread_mutex_unlock((pthread_mutex_t *)lock);
}

/*
 * Wait on the queue unless @pred(@arg) holds - until @abstime (CLOCK_MONOTONIC)
 * if it is not NULL. Returns 0 if the predicate held or a wakeup arrived, the
 * (positive) pthread error code otherwise, ETIMEDOUT once @abstime passed. A
 * caller loops on 0 until its predicate holds, as a wakeup may be spurious.
 *
 * Unlike the macros below, the predicate is evaluated under thread_wait_lock,
 * right before the wait it decides on. A waker that makes it true before
 * calling thread_wake_all_locked() is therefore either seen by that check or
 * finds the waiter blocked already - its wakeup cannot fall in between the two
 * and be lost.
 *
 * The condition wait is a cancellation point which returns with
 * thread_wait_lock re-acquired, so a cancellation cleanup handler releases it.
 * This is a function and not a macro as pthread_cleanup_push() may be built on
 * setjmp(), which must not be expanded into the frames of the callers.
 */
static inline int thread_wait_queue_wait_pred(struct thread_wait_queue *queue,
					      const struct timespec *abstime,
					      bool (*pred)(void *arg),
					      void *arg)
{
	int ret;

	ret = pthread_mutex_lock(&queue->thread_wait_lock);
	assert(ret == 0);
	pthread_cleanup_push(thread_wait_queue_unlock,
			     &queue->thread_wait_lock);
	if (pred(arg)) {
		ret = 0;
	} else if (abstime) {
		ret = pthread_cond_clockwait(&queue->thread_wait_cv,
					     &queue->thread_wait_lock,
					     CLOCK_MONOTONIC, abstime);
	} else {
		ret = pthread_cond_wait(&queue->thread_wait_cv,
					&queue->thread_wait_lock);
	}
	pthread_cleanup_pop(1);

	return ret;
}

/*
 * Wake every waiter with thread_wait_lock held - the counterpart of
 * thread_wait_queue_wait_pred(): whatever the caller set before is seen by a
 * waiter that checks its predicate after this, and one that checked before is
 * blocked already and woken.
 */
static inline void thread_wake_all_locked(struct thread_wait_queue *queue)
{
	int ret __attribute__((unused));

	ret = pthread_mutex_lock(&queue->thread_wait_lock);
	assert(ret == 0);
	ret = pthread_cond_broadcast(&queue->thread_wait_cv);
	assert(ret == 0);
	ret = pthread_mutex_unlock(&queue->thread_wait_lock);
	assert(ret == 0);
}

#define DECLARE_WAIT_QUEUE(name)                                               \
	struct thread_wait_queue name = {                                      \
		.thread_wait_cv = PTHREAD_COND_INITIALIZER,                    \
		.thread_wait_lock = PTHREAD_MUTEX_INITIALIZER,                 \
	}

#define thread_wait_no_event(queue)                                            \
	do {                                                                   \
		int __mret __attribute__((unused));                            \
                                                                               \
		__mret = pthread_mutex_lock(&(queue)->thread_wait_lock);       \
		assert(__mret == 0);                                           \
		__mret = pthread_cond_wait(&(queue)->thread_wait_cv,           \
					   &(queue)->thread_wait_lock);        \
		assert(__mret == 0);                                           \
		__mret = pthread_mutex_unlock(&(queue)->thread_wait_lock);     \
		assert(__mret == 0);                                           \
	} while (0)

/*
 * Timed wait on event, reltime is the relative time to wait.
 * NOTE: Writes result into caller-supplied variable `ret` (must be int).
 */
#define thread_timedwait_no_event(queue, reltime)                              \
	do {                                                                   \
		struct timespec __ts;                                          \
		int __mret __attribute__((unused));                            \
                                                                               \
		__mret = pthread_mutex_lock(&(queue)->thread_wait_lock);       \
		assert(__mret == 0);                                           \
		clock_gettime(CLOCK_MONOTONIC, &__ts);                         \
		__ts.tv_sec += (reltime)->tv_sec;                              \
		__ts.tv_nsec += (reltime)->tv_nsec;                            \
		if (__ts.tv_nsec >= 1000000000) {                              \
			__ts.tv_sec += __ts.tv_nsec / 1000000000;              \
			__ts.tv_nsec = __ts.tv_nsec % 1000000000;              \
		}                                                              \
		ret = -pthread_cond_clockwait(&(queue)->thread_wait_cv,        \
					      &(queue)->thread_wait_lock,      \
					      CLOCK_MONOTONIC, &__ts);         \
		assert(ret == 0 || ret == -ETIMEDOUT);                         \
		__mret = -pthread_mutex_unlock(&(queue)->thread_wait_lock);    \
		assert(__mret == 0);                                           \
	} while (0)

/*
 * Wait until @condition becomes true.
 *
 * The predicate is evaluated WITHOUT holding thread_wait_lock, so a
 * thread_wake[_all] issued by another thread between the predicate check and
 * the blocking wait below would be lost. To avoid an indefinite hang on such a
 * missed wakeup, the wait is bounded: on timeout the loop simply re-checks the
 * predicate. The condition variable's clock is overridden to CLOCK_MONOTONIC
 * per-wait so a wall-clock step cannot stretch the bound.
 */
#define thread_wait_event(queue, condition)                                    \
	while (!(condition)) {                                                 \
		struct timespec __ts;                                          \
		int __mret __attribute__((unused));                            \
                                                                               \
		__mret = pthread_mutex_lock(&(queue)->thread_wait_lock);       \
		assert(__mret == 0);                                           \
		clock_gettime(CLOCK_MONOTONIC, &__ts);                         \
		__ts.tv_nsec += 100 * 1000 * 1000;                            \
		if (__ts.tv_nsec >= 1000000000L) {                            \
			__ts.tv_sec++;                                        \
			__ts.tv_nsec -= 1000000000L;                         \
		}                                                             \
		__mret = pthread_cond_clockwait(&(queue)->thread_wait_cv,     \
						&(queue)->thread_wait_lock,   \
						CLOCK_MONOTONIC, &__ts);      \
		assert(__mret == 0 || __mret == ETIMEDOUT);                   \
		__mret = pthread_mutex_unlock(&(queue)->thread_wait_lock);    \
		assert(__mret == 0);                                          \
	}

/*
 * NOTE: Caller must have `int ret = 0;` in scope before using this macro.
 */
#define thread_timedwait_event(queue, condition, reltime)                      \
	while (!(condition) && !ret) {                                         \
		thread_timedwait_no_event(queue, reltime);                     \
	}

#define thread_wake(queue)                                                     \
	do {                                                                   \
		int __cret __attribute__((unused));                            \
		__cret = pthread_cond_signal(&(queue)->thread_wait_cv);        \
		assert(__cret == 0);                                           \
	} while (0)

#define thread_wake_all(queue)                                                 \
	do {                                                                   \
		int __cret __attribute__((unused));                            \
		__cret = pthread_cond_broadcast(&(queue)->thread_wait_cv);     \
		assert(__cret == 0);                                           \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* QUEUE_H */
