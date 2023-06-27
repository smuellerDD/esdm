/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
extern "C"
{
#endif

struct thread_wait_queue {
	pthread_cond_t thread_wait_cv;
	pthread_mutex_t thread_wait_lock;
};

#define WAIT_QUEUE_INIT(name)						\
	pthread_mutex_init(&(name).thread_wait_lock, NULL)

#define WAIT_QUEUE_FINI(name)						\
	pthread_mutex_destroy(&(name).thread_wait_lock)

#define DECLARE_WAIT_QUEUE(name)					\
	struct thread_wait_queue name = {				\
		.thread_wait_lock = PTHREAD_MUTEX_INITIALIZER,		\
	}

#define thread_wait_no_event(queue)					\
	pthread_mutex_lock(&(queue)->thread_wait_lock);			\
	pthread_cond_wait(&(queue)->thread_wait_cv,			\
			  &(queue)->thread_wait_lock);			\
	pthread_mutex_unlock(&(queue)->thread_wait_lock)

#define thread_wait_event(queue, condition)				\
	while (!condition) {						\
		thread_wait_no_event(queue);				\
	}

static inline bool thread_queue_sleeper(struct thread_wait_queue *queue)
{
	if (pthread_mutex_trylock(&queue->thread_wait_lock))
		return true;

	pthread_mutex_unlock(&(queue)->thread_wait_lock);
	return false;
}

#define thread_wake(queue)						\
	do {								\
		pthread_cond_signal(&(queue)->thread_wait_cv);		\
	} while (0);


#define thread_wake_all(queue)						\
	do {								\
		pthread_cond_broadcast(&(queue)->thread_wait_cv);	\
	} while (0);


#ifdef __cplusplus
}
#endif

#endif /* QUEUE_H */
