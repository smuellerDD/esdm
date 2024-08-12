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

#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

struct thread_wait_queue {
	pthread_cond_t thread_wait_cv;
	pthread_mutex_t thread_wait_lock;
};

#define WAIT_QUEUE_INIT(name) {							\
	pthread_condattr_t attr;						\
										\
	pthread_mutex_init(&(name).thread_wait_lock, NULL); 			\
	pthread_condattr_init(&attr);						\
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);			\
	pthread_cond_init(&(name).thread_wait_cv, &attr);			\
	}

#define WAIT_QUEUE_FINI(name) 							\
	pthread_cond_destroy(&(name).thread_wait_cv);				\
	pthread_mutex_destroy(&(name).thread_wait_lock);


#define DECLARE_WAIT_QUEUE(name)                                               \
	struct thread_wait_queue name = {                                      \
		.thread_wait_lock = PTHREAD_MUTEX_INITIALIZER,                 \
	}

#define thread_wait_no_event(queue)                                            \
	pthread_mutex_lock(&(queue)->thread_wait_lock);                        \
	pthread_cond_wait(&(queue)->thread_wait_cv,                            \
			  &(queue)->thread_wait_lock);                         \
	pthread_mutex_unlock(&(queue)->thread_wait_lock)

/* Timed wait on event, reltime is the relative time to wait */
#define thread_timedwait_no_event(queue, reltime)                              \
	do {                                                                   \
		struct timespec __ts;                                          \
                                                                               \
		pthread_mutex_lock(&(queue)->thread_wait_lock);                \
		clock_gettime(CLOCK_MONOTONIC, &__ts);                         \
		__ts.tv_sec += (reltime)->tv_sec;                              \
		__ts.tv_nsec += (reltime)->tv_nsec;			       \
		if (__ts.tv_nsec > 1000000000) {			       \
			__ts.tv_sec += __ts.tv_nsec / 1000000000;	       \
			__ts.tv_nsec = __ts.tv_nsec % 1000000000;	       \
		}							       \
		ret = -pthread_cond_timedwait(&(queue)->thread_wait_cv,        \
					      &(queue)->thread_wait_lock, &__ts);\
		pthread_mutex_unlock(&(queue)->thread_wait_lock);              \
	} while (0)

#define thread_wait_event(queue, condition)                                    \
	while (!condition) {                                                   \
		thread_wait_no_event(queue);                                   \
	}

#define thread_timedwait_event(queue, condition, reltime)                      \
	while (!condition && !ret) {                                           \
		thread_timedwait_no_event(queue, reltime);                     \
	}

static inline bool thread_queue_sleeper(struct thread_wait_queue *queue)
{
	if (pthread_mutex_trylock(&queue->thread_wait_lock))
		return true;

	pthread_mutex_unlock(&(queue)->thread_wait_lock);
	return false;
}

#define thread_wake(queue)                                                     \
	do {                                                                   \
		pthread_cond_signal(&(queue)->thread_wait_cv);                 \
	} while (0);

#define thread_wake_all(queue)                                                 \
	do {                                                                   \
		pthread_cond_broadcast(&(queue)->thread_wait_cv);              \
	} while (0);

#ifdef __cplusplus
}
#endif

#endif /* QUEUE_H */
