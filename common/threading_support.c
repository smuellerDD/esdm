/* Threading support - implementation
 *
 * Copyright (C) 2018 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <stdatomic.h>
#include <stdbool.h>
#include "config.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"
#include "mutex_w.h"
#include "ret_checkers.h"
#include "threading_support.h"
#include "visibility.h"

/**
 * Threading Support
 * =================
 *
 * Threading support is provided by maintaining a pool of threads which
 * are spawned when they are needed. Once the thread completes its first job
 * it remains idle but alive and waits for the next job. The code first
 * tries to reuse existing idle threads before spawning new threads.
 *
 * It is permissible to spawn new threads from different mother threads. When
 * calling thread_wait, only the threads from the caller are waited for.
 */

/*
 * Structure for one thread
 */
struct thread_ctx {
	pthread_t thread_id; /* Thread ID from pthread_create */
	pthread_t parent; /* Parent thread ID */
	unsigned int thread_num; /* Current slot number */
	int ret_ancestor; /* Return code of ancestor code */

	int (*start_routine)(void *); /* Thread code to be executed */
	void *data; /* Parameters used by the thread code */

	atomic_bool thread_pending; /* Is thread associated with structure? */
	mutex_w_t inuse; /* Is thread data structure used? */
	atomic_bool shutdown; /* Shall the thread be shut down? */
	bool scheduled; /* Is/was a job executed and return code
					 * is ready for pickup? */

	pthread_cond_t worker_cv;
};

/*
 * Total number of all threads, including slaves and system threads.
 */
#define THREADING_REALLY_ALL_THREADS                                           \
	(THREADING_MAX_THREADS + ESDM_THREAD_MAX_SPECIAL_GROUPS)

/*
 * Array holding the thread state for all slaves and system threads.
 */
static struct thread_ctx threads[THREADING_REALLY_ALL_THREADS];
static uint32_t threads_groups = 0;
static uint32_t threads_per_threadgroup = 1;

static pthread_attr_t pthread_attr;

/* Stack size applied to newly created threads; 0 means the platform default. */
static size_t pthread_stacksize = 0;

/*
 * Indicator to prevent spawning of new threads while the cleanup / garbage
 * collector functions execute.
 */
static atomic_bool threads_in_cancel = false;

/*
 * Lock whether the cleanup / garbage collector for threads executes. As we
 * have two cleanup functions, we must ensure that they do not execute at the
 * same time.
 */
static DEFINE_MUTEX_W_UNLOCKED(threads_cleanup);

/* Waiting helper for the thread_schedule function */
static pthread_cond_t thread_schedule_cv;
static pthread_mutex_t thread_schedule_lock = PTHREAD_MUTEX_INITIALIZER;

/* Waiting helper for the thread_wait function */
static pthread_cond_t thread_wait_cv;
static pthread_mutex_t thread_wait_lock = PTHREAD_MUTEX_INITIALIZER;

static inline unsigned int thread_get_special_slot(unsigned int thread_group)
{
	/*
	 * Special groups are exactly (uint32_t)-1 .. -ESDM_THREAD_MAX_SPECIAL_GROUPS.
	 * Only those map to a special slot; any other large value (the gap
	 * between the normal groups and the specials) is NOT special and must
	 * return 0 so thread_schedule()/thread_send_signal() reject it via the
	 * validity check rather than indexing threads[] out of bounds with a
	 * wrapped slot number.
	 */
	if (thread_group <= UINT_MAX - ESDM_THREAD_MAX_SPECIAL_GROUPS)
		return 0;

	return (THREADING_MAX_THREADS + (UINT_MAX - thread_group));
}

static inline bool thread_is_special(struct thread_ctx *tctx)
{
	return (tctx->thread_num >= THREADING_MAX_THREADS) ? true : false;
}

static inline void thread_block(pthread_cond_t *cv, pthread_mutex_t *lock)
{
	struct timespec ts;

	/*
	 * Callers evaluate their wake-up predicate without holding @lock, so a
	 * completion broadcast can fire between the predicate check and the
	 * wait below and be lost. Bound the sleep so the caller re-checks its
	 * predicate instead of sleeping indefinitely on a missed wake-up.
	 */
	pthread_mutex_lock(lock);
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_nsec += 100 * 1000 * 1000;
	if (ts.tv_nsec >= 1000000000L) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000L;
	}
	pthread_cond_timedwait(cv, lock, &ts);
	pthread_mutex_unlock(lock);
}

static inline bool thread_dirty(unsigned int slot)
{
	return (atomic_load(&threads[slot].thread_pending));
}

/* Thread structure cleanup after execution when thread is kept alive. */
static inline void thread_cleanup(struct thread_ctx *tctx)
{
	tctx->data = NULL;
	tctx->start_routine = NULL;
	pthread_cond_broadcast(&thread_schedule_cv);
	pthread_cond_broadcast(&thread_wait_cv);

	/* Return values of special threads is irrelevant */
	if (thread_is_special(tctx))
		tctx->scheduled = false;
}

/* Thread structure cleanup when thread is terminated. */
static inline void thread_cleanup_full(struct thread_ctx *tctx)
{
	thread_cleanup(tctx);
	tctx->thread_num = 0;
	atomic_store(&tctx->thread_pending, false);
	tctx->scheduled = false;
	tctx->ret_ancestor = 0;
	/*
	 * Deliberately do NOT destroy tctx->inuse here: the mutex lives in
	 * the static threads[] array and is initialized exactly once in
	 * thread_init(). This function runs both in the exiting worker and
	 * again in thread_wait_all/thread_cancel after the join (double
	 * destroy), thread_schedule trylocks the mutex when reusing the slot
	 * without any re-initialization, and a self-destroying worker races
	 * with concurrent trylocks. The pool is restartable after
	 * thread_wait_all, so the mutex must stay valid for the process
	 * lifetime.
	 */
}

void thread_set_default_stacksize(size_t stacksize)
{
	pthread_stacksize = stacksize;
}

int thread_init(uint32_t groups)
{
	static uint32_t thread_initialized = 0;
	pthread_condattr_t cattr;
	unsigned int i;
	int ret;

	if (groups > (THREADING_MAX_THREADS)) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_THREADING,
			"Number of threads (%u) is less than the number of requested thread groups (%u)\n",
			THREADING_MAX_THREADS, groups);
		return -EINVAL;
	}

	if (groups == 0)
		groups = 1;

	if (thread_initialized)
		goto out;
	thread_initialized = 1;

	mutex_w_init(&threads_cleanup, 0, 0);

	CKINT(pthread_attr_init(&pthread_attr));

	/*
	 * Optionally reduce the per-thread stack size to keep the memory
	 * footprint of the worker pool small. This must be configured before
	 * the pool is initialized as the attribute is applied to every thread
	 * spawned from it.
	 */
	if (pthread_stacksize) {
		int rc = pthread_attr_setstacksize(&pthread_attr,
						   pthread_stacksize);

		if (rc) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_THREADING,
				"Cannot set thread stack size to %zu bytes: %s\n",
				pthread_stacksize, strerror(rc));
			return -rc;
		}
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
			    "Thread stack size limited to %zu bytes\n",
			    pthread_stacksize);
	}

	memset(threads, 0, sizeof(threads));

	/*
	 * Arm the condition variables used with thread_block()'s timed wait
	 * against CLOCK_MONOTONIC. thread_block() computes the absolute deadline
	 * from clock_gettime() + a relative offset, so a wall-clock step (NTP /
	 * settimeofday) must not be able to stretch the bound into a long hang.
	 */
	CKINT(pthread_condattr_init(&cattr));
	CKINT(pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC));
	pthread_cond_init(&thread_schedule_cv, &cattr);
	pthread_cond_init(&thread_wait_cv, &cattr);

	for (i = 0; i < THREADING_REALLY_ALL_THREADS; i++) {
		atomic_store(&threads[i].thread_pending, false);
		mutex_w_init(&threads[i].inuse, false, 0);
		atomic_store(&threads[i].shutdown, false);
		pthread_cond_init(&threads[i].worker_cv, &cattr);
	}
	pthread_condattr_destroy(&cattr);

	threads_groups = groups;
	threads_per_threadgroup = THREADING_MAX_THREADS / threads_groups;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
		    "Initialized threading support for %u threads\n",
		    THREADING_MAX_THREADS);
	if (threads_per_threadgroup * threads_groups < THREADING_MAX_THREADS) {
		esdm_logger(LOGGER_WARN, LOGGER_C_THREADING,
			    "%u thread slots will never be used\n",
			    THREADING_MAX_THREADS -
				    (threads_per_threadgroup * threads_groups));
	}

out:
	return 0;
}

/* Worker loop of a thread */
static void *thread_worker(void *arg)
{
	struct thread_ctx *tctx = (struct thread_ctx *)arg;

	/*
	 * pthread_setcanceltype() only affects the calling thread, so it must
	 * be invoked here in the worker and not in thread_create() (where it
	 * would mark the creator async-cancelable instead).
	 */
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	if (!thread_is_special(tctx)) {
		sigset_t block, old;
		int ret;

		/*
		 * Block all but terminating signals from being processed by
		 * thread.
		 */
		sigfillset(&block);
		sigdelset(&block, SIGHUP);
		sigdelset(&block, SIGINT);
		sigdelset(&block, SIGQUIT);
		sigdelset(&block, SIGTERM);
		ret = -pthread_sigmask(SIG_BLOCK, &block, &old);
		if (ret)
			return NULL;
	}

	while (1) {
		mutex_w_lock(&tctx->inuse);

	locked:
		if (atomic_load(&tctx->shutdown)) {
			/* Request for termination */
			mutex_w_unlock(&tctx->inuse);
			/*
			 * As the while loop terminates, the thread will
			 * terminate as well - clean up our structure in case
			 * the signal handler wants to cancel all threads.
			 * In this case, it has to identify that this thread
			 * does not exist any more.
			 */
			thread_cleanup_full(tctx);
			pthread_exit(NULL);
			break;
		} else if (tctx->start_routine) {
			/* Work to do, execute */
			tctx->ret_ancestor = tctx->start_routine(tctx->data);
			thread_cleanup(tctx);
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
				    "Thread %u completed\n", tctx->thread_num);
			mutex_w_unlock(&tctx->inuse);
			pthread_cond_broadcast(&thread_wait_cv);
		} else {
			/* Idle */
			/* inuse.lock is locked */
			pthread_cond_wait(&tctx->worker_cv, &tctx->inuse.lock);
			/* inuse.lock is locked */
			goto locked;
		}
	}

	return NULL;
}

/* Spawn a thread */
static int thread_create(struct thread_ctx *tctx, unsigned int slot)
{
	int ret;

	tctx->thread_num = slot;
	tctx->data = NULL;

	ret = -pthread_create(&tctx->thread_id, &pthread_attr, &thread_worker,
			      tctx);
	if (ret)
		goto err;

	/*
	 * Publish thread_pending only after pthread_create has written a valid
	 * thread_id. thread_dirty() readers (thread_wait_all / thread_cancel)
	 * gate their pthread_join/pthread_cancel solely on this flag, so setting
	 * it before the create let them operate on an uninitialized/stale
	 * thread_id when a create was still in flight.
	 */
	atomic_store(&tctx->thread_pending, true);

	return 0;

err:
	thread_cleanup_full(tctx);
	return ret;
}

void thread_send_signal(uint32_t thread_group, int signal)
{
	pthread_t self = pthread_self();
	unsigned int i, upper;
	unsigned int special_slot = thread_get_special_slot(thread_group);

	/*
	 * Reject an out-of-range thread group instead of indexing threads[]
	 * past its end (mirrors thread_schedule()). Special slots live at the
	 * top of the array and are addressed directly.
	 */
	if (thread_group >= threads_groups && !special_slot)
		return;

	/* Get the range of slots of the thread_group */
	if (special_slot) {
		i = special_slot;
		upper = special_slot + 1;
	} else {
		i = thread_group * threads_per_threadgroup;
		upper = (thread_group + 1) * threads_per_threadgroup;
	}

	for (; i < upper; i++) {
		/*
		 * Only signal a slot that still holds a live, working thread,
		 * and never ourselves. thread_dirty() reads thread_pending
		 * atomically; it stays true until thread_wait_all() joins the
		 * thread, so gating on it avoids pthread_kill()ing a stale
		 * thread_id whose thread was already joined (and whose id may
		 * since have been recycled). A mutex cannot be taken here as
		 * this may run from a signal-handling context.
		 */
		if (thread_dirty(i) && threads[i].start_routine &&
		    !pthread_equal(threads[i].parent, self))
			pthread_kill(threads[i].thread_id, signal);
	}
}

/* Find free pthread slot and schedule the job */
static int thread_schedule(int (*start_routine)(void *), void *tdata,
			   uint32_t thread_group, int *ret_ancestor)
{
	pthread_t self = pthread_self();
	unsigned int lower, upper;
	unsigned int special_slot = thread_get_special_slot(thread_group);
	unsigned int num_elements, j, k;

	if (thread_group >= threads_groups && !special_slot) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_THREADING,
			"undefined thread group requested (%u, max thread group is %u)\n",
			thread_group, threads_groups);
		return -EINVAL;
	}

	/* Get the range of slots of the thread_group */
	if (special_slot) {
		lower = special_slot;
		upper = special_slot + 1;
	} else {
		lower = thread_group * threads_per_threadgroup;
		upper = (thread_group + 1) * threads_per_threadgroup;
	}

	num_elements = upper - lower;

	for (k = 0; k < num_elements; ++k) {
		if (atomic_load(&threads_in_cancel))
			return -ESHUTDOWN;

		j = lower + k % num_elements;

		if (mutex_w_trylock(&threads[j].inuse) == 0) {
			/*
			 * The thread is currently executing a body of code -
			 * kick the worker.
			 */
			if (threads[j].start_routine ||
			    atomic_load(&threads[j].shutdown)) {
				mutex_w_unlock(&threads[j].inuse);
				pthread_cond_broadcast(&threads[j].worker_cv);
				continue;
			}

			/*
			 * Thread is not being picked up by thread_block of the
			 * mother thread - kick the worker.
			 */
			if (threads[j].scheduled &&
			    !pthread_equal(threads[j].parent, self)) {
				mutex_w_unlock(&threads[j].inuse);
				pthread_cond_broadcast(&threads[j].worker_cv);
				continue;
			}

			/*
			 * Create thread as we have a clean slot and all
			 * existing threads are busy.
			 */
			if (!thread_dirty(j)) {
				int ret = thread_create(&threads[j], j);

				if (ret) {
					/*
					 * thread_create() failed with the slot's
					 * inuse lock held - release it, otherwise
					 * the slot is wedged forever and the pool
					 * shrinks on every transient failure.
					 */
					mutex_w_unlock(&threads[j].inuse);
					return ret;
				}

				esdm_logger(
					LOGGER_VERBOSE, LOGGER_C_THREADING,
					"Thread %u for thread group %u allocated\n",
					j, thread_group);
			}

			/* Catch the return code of the ancestor thread */
			if (ret_ancestor)
				*ret_ancestor = threads[j].ret_ancestor;

			/*
			 * Use the thread from the thread pool and schedule
			 * job.
			 */
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
				    "Thread %u for thread group %u assigned\n",
				    j, thread_group);
			threads[j].data = tdata;
			threads[j].start_routine = start_routine;
			threads[j].parent = pthread_self();
			threads[j].scheduled = true;
			pthread_cond_broadcast(&threads[j].worker_cv);
			mutex_w_unlock(&threads[j].inuse);
			pthread_cond_broadcast(&thread_wait_cv);

			return 0;
		}
	}

	return -EAGAIN;
}

/*
 * Wait for all threads in spawned by calling thread and fetch the return code.
 */
int thread_wait(bool ignore_shutdown)
{
	unsigned int i;
	pthread_t self = pthread_self();
	int ret = 0;
	bool wait = true;

	while (wait) {
		wait = false;

		/* Only wait for our children */
		for (i = 0; i < THREADING_MAX_THREADS; i++) {
			if (!ignore_shutdown &&
			    atomic_load(&threads[i].shutdown))
				return -ESHUTDOWN;

			/* Thread is not initialized, skip */
			if (!thread_dirty(i))
				continue;

			/* Thread is not one of our children, skip */
			if (!pthread_equal(threads[i].parent, self))
				continue;

			/* If the thread executes a job, skip but wait. */
			if (mutex_w_trylock(&threads[i].inuse) != 0) {
				wait = true;
				continue;
			}

			/*
			 * If there is a start routine, a job is pending and we
			 * wait for it to finish.
			 */
			if (threads[i].start_routine) {
				wait = true;
			} else {
				/* Collect return code of our threads */
				ret |= threads[i].ret_ancestor;
				threads[i].scheduled = false;
			}

			mutex_w_unlock(&threads[i].inuse);
		}

		if (wait)
			thread_block(&thread_wait_cv, &thread_wait_lock);
	}

	return ret;
}

DSO_PUBLIC
int thread_set_name(enum esdm_request_type type, uint32_t id)
{
	char name[ESDM_THREAD_MAX_NAMELEN];

	switch (type) {
	case es_monitor:
		snprintf(name, sizeof(name), "ESDM es_monitor");
		break;
	case rpc_unpriv_server:
		snprintf(name, sizeof(name), "ESDM unpriv_rpc");
		break;
	case rpc_priv_server:
		snprintf(name, sizeof(name), "ESDM priv_rpc");
		break;
	case rpc_handler_priv:
		snprintf(name, sizeof(name), "ESDM rpc_p%03u", id);
		break;
	case rpc_handler_unpriv:
		snprintf(name, sizeof(name), "ESDM rpc_up%03u", id);
		break;
	case cuse_poll:
		snprintf(name, sizeof(name), "ESDM cuse_poll");
		break;
	case es_kernel_feeder:
		snprintf(name, sizeof(name), "ESDM krnl_feed");
		break;
	default:
		snprintf(name, sizeof(name), "ESDM %u", id);
		break;
	}

	return -pthread_setname_np(pthread_self(), name);
}

DSO_PUBLIC
int thread_get_name(char *name, size_t len)
{
	return -pthread_getname_np(pthread_self(), name, len);
}

/* Wait for all threads */
DSO_PUBLIC
int thread_wait_all(bool system_threads)
{
	unsigned int i, upper = system_threads ? THREADING_REALLY_ALL_THREADS :
						 THREADING_MAX_THREADS;
	bool join_me[THREADING_REALLY_ALL_THREADS];
	int ret = 0;

	mutex_w_lock(&threads_cleanup);

	/* Ensure that no new thread is spawned. */
	for (i = 0; i < upper; i++) {
		/*
		 * Publish the shutdown flag under the worker's inuse lock:
		 * an idle worker checks the flag and enters its condvar wait
		 * while holding inuse, so setting + broadcasting without the
		 * lock can fire in that window and the wake-up is lost,
		 * hanging the pthread_join below.
		 */
		mutex_w_lock(&threads[i].inuse);
		/*
		 * Snapshot which slots have a live thread *before* requesting
		 * shutdown. A worker that observes the flag self-terminates and
		 * runs thread_cleanup_full(), clearing thread_pending; if that
		 * wins the race against the join loop below, thread_dirty(i)
		 * would read false there and the join would be skipped, leaking
		 * the joinable thread. Deciding here, while still holding inuse
		 * and before the flag is set, avoids that window.
		 */
		join_me[i] = thread_dirty(i);
		atomic_store(&threads[i].shutdown, true);
		pthread_cond_broadcast(&threads[i].worker_cv);
		mutex_w_unlock(&threads[i].inuse);
	}
	pthread_cond_broadcast(&thread_wait_cv);

	/* Wait for all worker threads. */
	for (i = 0; i < upper; i++) {
		if (atomic_load(&threads_in_cancel)) {
			ret = -ESHUTDOWN;
			goto out;
		}
		if (join_me[i]) {
			pthread_join(threads[i].thread_id, NULL);
			ret |= threads[i].ret_ancestor;
			thread_cleanup_full(&threads[i]);
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
				    "Thread %u terminated\n", i);
		}
	}

	/* Allow new threads being spawned */
	for (i = 0; i < upper; i++)
		atomic_store(&threads[i].shutdown, false);

out:
	mutex_w_unlock(&threads_cleanup);
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
		    "Exiting thread_wait_all with status %i\n", ret);
	return ret;
}

/* Kill all threads */
static void thread_cancel(bool system_threads)
{
	unsigned int i, upper = system_threads ? THREADING_REALLY_ALL_THREADS :
						 THREADING_MAX_THREADS;

	atomic_store(&threads_in_cancel, true);
	mutex_w_lock(&threads_cleanup);
	/*
	 * Ensure that no new thread is spawned.
	 *
	 * Do not clear threads[i].start_routine here: it is protected by the
	 * per-slot inuse lock (which we intentionally do not take on this kill
	 * path), and a running worker dereferences it under that lock. An
	 * unlocked write races that dereference and can crash the worker. The
	 * shutdown flag plus the pthread_cancel below already terminate every
	 * worker, so the write is redundant as well as unsafe.
	 */
	for (i = 0; i < upper; i++) {
		atomic_store(&threads[i].shutdown, true);
		pthread_cond_broadcast(&threads[i].worker_cv);
	}
	pthread_cond_broadcast(&thread_wait_cv);

	/* Kill all worker threads. */
	for (i = 0; i < upper; i++) {
		if (thread_dirty(i)) {
			pthread_cancel(threads[i].thread_id);
			pthread_join(threads[i].thread_id, NULL);
			thread_cleanup_full(&threads[i]);
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
				    "Thread %u killed\n", i);
		}
	}

	/*
	 * Do not set threads[i].shutdown to false any more as no new
	 * thread shall be spawned. We are in the process of dying.
	 */

	mutex_w_unlock(&threads_cleanup);
}

DSO_PUBLIC
int thread_start(int (*start_routine)(void *), void *tdata,
		 uint32_t thread_group, int *ret_ancestor)
{
	int ret;

	while (1) {
		ret = thread_schedule(start_routine, tdata, thread_group,
				      ret_ancestor);
		if (ret == -EAGAIN)
			thread_block(&thread_schedule_cv,
				     &thread_schedule_lock);
		else
			return ret;
	}

	return 0;
}

void thread_stop_spawning(void)
{
	atomic_store(&threads_in_cancel, true);
}

void thread_fork_join(void *(*start_routine)(void *), void *args,
		      size_t arg_stride, size_t num)
{
	if (num == 0)
		return;

	/*
	 * Run inline during teardown: threads spawned here are invisible to
	 * thread_cancel, so a forced cancellation of the caller would orphan
	 * them while they still write into the caller's stack frame.
	 */
	bool have_parallelism = num > 1 && esdm_online_nodes() > 1 &&
				!atomic_load(&threads_in_cancel);
	pthread_t tids[num];
	bool spawned[num];
	char *arg_base = args;
	pthread_attr_t fj_attr;
	pthread_attr_t *fj_attrp = NULL;
	int oldstate;
	size_t i;

	/*
	 * Honor the configured reduced stack size for these transient threads
	 * too, falling back to the platform default if the attribute cannot be
	 * prepared.
	 */
	if (pthread_stacksize && pthread_attr_init(&fj_attr) == 0) {
		if (pthread_attr_setstacksize(&fj_attr, pthread_stacksize) == 0)
			fj_attrp = &fj_attr;
		else
			pthread_attr_destroy(&fj_attr);
	}

	/*
	 * The caller must outlive its batch: the tasks write through pointers
	 * into the caller's stack frame, and pthread_join is a cancellation
	 * point. A thread_cancel hitting the caller mid-join would reclaim
	 * that frame while children invisible to thread_cancel still use it.
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

	for (i = 0; i < num; i++) {
		void *arg = arg_base + i * arg_stride;

		if (have_parallelism &&
		    pthread_create(&tids[i], fj_attrp, start_routine, arg) ==
			    0) {
			spawned[i] = true;

			/*
			 * Give the worker a recognizable name in ps/top/htop.
			 * Cosmetic and best effort, so ignore errors. Only the
			 * genuinely spawned threads are named: the inline
			 * fallback below runs on the caller's own thread, which
			 * must keep its name.
			 */
			{
				char name[ESDM_THREAD_MAX_NAMELEN];

				snprintf(name, sizeof(name), "ESDM fj_%03u",
					 (unsigned int)(i % 1000));
				pthread_setname_np(tids[i], name);
			}
		} else {
			spawned[i] = false;
			start_routine(arg);
		}
	}

	for (i = 0; i < num; i++) {
		if (spawned[i])
			pthread_join(tids[i], NULL);
	}

	pthread_setcancelstate(oldstate, NULL);

	if (fj_attrp)
		pthread_attr_destroy(fj_attrp);
}

DSO_PUBLIC
int thread_release(bool force, bool system_threads)
{
	int ret = 0;

	/*
	 * In case someone intends to wait and we are in cancel mode, force
	 * cancellation.
	 */
	if (atomic_load(&threads_in_cancel))
		force = true;

	if (force)
		thread_cancel(system_threads);
	else
		ret = thread_wait_all(system_threads);

	/* do not handle return code as we are terminating anyway */
	pthread_attr_destroy(&pthread_attr);
	return ret;
}
