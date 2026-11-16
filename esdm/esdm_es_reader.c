/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "esdm_es_mgr_cb.h"
#include "esdm_es_reader.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"

/*
 * The thread sanitizer misses the locking of a thread cancelled in a blocking
 * call - the unwinding skips the cleanup of its interceptor - so it is told.
 */
#if defined(__SANITIZE_THREAD__)
#define ESDM_ES_READER_TSAN
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define ESDM_ES_READER_TSAN
#endif
#endif
#ifdef ESDM_ES_READER_TSAN
void __tsan_acquire(void *addr);
void __tsan_release(void *addr);
#define esdm_es_reader_tsan_acquire(addr) __tsan_acquire(addr)
#define esdm_es_reader_tsan_release(addr) __tsan_release(addr)
#else
#define esdm_es_reader_tsan_acquire(addr) (void)(addr)
#define esdm_es_reader_tsan_release(addr) (void)(addr)
#endif

/* The op needs little: a TPM command buffer at most */
#define ESDM_ES_READER_STACK (256 * 1024)

struct esdm_es_reader {
	/* Guards busy, abandoned and freed */
	pthread_mutex_t lock;
	/* Broadcast when a read thread ends */
	pthread_cond_t cond;

	/* The device read and its fd, which the release closes */
	esdm_es_reader_op_t op;
	int fd;
	/* Name of the read threads */
	char name[16];

	/* A read thread runs: one at a time */
	bool busy;
	/* Its caller timed out, it is torn down */
	bool abandoned;
	/* esdm_es_reader_free() was called: the read thread releases */
	bool freed;
};

/* What the caller of a read waits for, on its stack */
struct esdm_es_read_wait {
	uint8_t *buf;
	int result;
	bool done;
};

/* One read, owned by its thread */
struct esdm_es_read {
	struct esdm_es_reader *reader;
	/* The caller, NULL once it timed out: under reader->lock */
	struct esdm_es_read_wait *waiter;
	size_t len;
	uint64_t deadline_ns;
	uint8_t buf[sizeof(((struct entropy_es *)0)->e)];
};

static void esdm_es_reader_release(struct esdm_es_reader *reader)
{
	if (reader->fd >= 0)
		close(reader->fd);
	pthread_cond_destroy(&reader->cond);
	pthread_mutex_destroy(&reader->lock);
	memset_secure(reader, 0, sizeof(*reader));
	free(reader);
}

/* End of a read thread: hand the result to a caller still waiting */
static void esdm_es_read_end(struct esdm_es_read *r, int ret)
{
	struct esdm_es_reader *reader = r->reader;
	bool release;

	pthread_mutex_lock(&reader->lock);
	esdm_es_reader_tsan_acquire(&reader->lock);
	if (r->waiter) {
		if (!ret)
			memcpy(r->waiter->buf, r->buf, r->len);
		r->waiter->result = ret;
		r->waiter->done = true;
	}
	reader->busy = false;
	reader->abandoned = false;
	release = reader->freed;
	pthread_cond_broadcast(&reader->cond);
	esdm_es_reader_tsan_release(&reader->lock);
	pthread_mutex_unlock(&reader->lock);

	memset_secure(r, 0, sizeof(*r));
	free(r);
	if (release)
		esdm_es_reader_release(reader);
}

static void esdm_es_read_cancelled(void *arg)
{
	esdm_es_read_end(arg, -ECANCELED);
}

static void *esdm_es_read_thread(void *arg)
{
	struct esdm_es_read *r = arg;
	int ret;

	pthread_setname_np(pthread_self(), r->reader->name);

	pthread_cleanup_push(esdm_es_read_cancelled, r);
	ret = r->reader->op(r->reader->fd, r->buf, r->len, r->deadline_ns);
	pthread_cleanup_pop(0);

	/* The end is reached once, not cut short by close() of a release */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	esdm_es_read_end(r, ret);

	return NULL;
}

/* Start the thread of @r, detached: it frees @r */
static int esdm_es_read_start(struct esdm_es_read *r, pthread_t *thread)
{
	pthread_attr_t attr;
	sigset_t all, old;
	int ret;

	ret = -pthread_attr_init(&attr);
	if (ret)
		return ret;
	(void)pthread_attr_setstacksize(&attr, ESDM_ES_READER_STACK);
	(void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	/*
	 * Block all signals in the thread (it inherits the mask): they would
	 * only interrupt the device read and belong to the other threads. The
	 * cancellation tearing it down is not blocked by that.
	 */
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &old);
	ret = -pthread_create(thread, &attr, esdm_es_read_thread, r);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	pthread_attr_destroy(&attr);

	return ret;
}

int esdm_es_reader_alloc(struct esdm_es_reader **reader, int fd,
			 esdm_es_reader_op_t op, const char *name)
{
	struct esdm_es_reader *r = calloc(1, sizeof(*r));
	pthread_condattr_t cattr;
	int ret;

	if (!r) {
		close(fd);
		return -ENOMEM;
	}
	r->fd = fd;
	r->op = op;
	snprintf(r->name, sizeof(r->name), "ESDM rd %s", name ? name : "es");

	/* Deadlines are on CLOCK_MONOTONIC, see esdm_monotonic_wait_ns() */
	ret = -pthread_condattr_init(&cattr);
	if (ret)
		goto err_free;
	ret = -pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	if (!ret)
		ret = -pthread_cond_init(&r->cond, &cattr);
	pthread_condattr_destroy(&cattr);
	if (ret)
		goto err_free;
	ret = -pthread_mutex_init(&r->lock, NULL);
	if (ret) {
		pthread_cond_destroy(&r->cond);
		goto err_free;
	}

	*reader = r;
	return 0;

err_free:
	close(fd);
	free(r);
	esdm_logger(LOGGER_ERR, LOGGER_C_ES,
		    "Cannot set up the reader of %s: %s\n",
		    name ? name : "an entropy source", strerror(-ret));
	return ret;
}

void esdm_es_reader_free(struct esdm_es_reader *reader)
{
	bool busy;

	if (!reader)
		return;

	/*
	 * No caller is left, so a read thread still running is one torn down
	 * and waiting for the device: it releases the reader when it ends.
	 */
	pthread_mutex_lock(&reader->lock);
	reader->freed = true;
	busy = reader->busy;
	pthread_mutex_unlock(&reader->lock);

	if (!busy)
		esdm_es_reader_release(reader);
}

/* Wait on @reader until @deadline_ns: ETIMEDOUT once it passed */
static int esdm_es_reader_wait(struct esdm_es_reader *reader,
			       uint64_t deadline_ns)
{
	struct timespec ts = {
		.tv_sec = (time_t)(deadline_ns / 1000000000ULL),
		.tv_nsec = (long)(deadline_ns % 1000000000ULL),
	};

	return pthread_cond_timedwait(&reader->cond, &reader->lock, &ts);
}

int esdm_es_reader_read(struct esdm_es_reader *reader, uint8_t *buf, size_t len,
			uint64_t deadline_ns, bool wait)
{
	struct esdm_es_read_wait w = { .buf = buf };
	struct esdm_es_read *r;
	pthread_t thread;
	int ret;

	if (!len || len > sizeof(r->buf))
		return -EINVAL;

	pthread_mutex_lock(&reader->lock);

	/*
	 * A read of another caller: its turn ends by its own deadline. Missing
	 * a turn says nothing about the device: -EBUSY.
	 */
	while (reader->busy) {
		if (reader->abandoned || !wait ||
		    (esdm_es_reader_wait(reader, deadline_ns) == ETIMEDOUT &&
		     reader->busy)) {
			ret = -EBUSY;
			goto out;
		}
	}
	if (esdm_monotonic_wait_ns() >= deadline_ns) {
		ret = -EBUSY;
		goto out;
	}

	/* Without a thread, nothing is said about the device either */
	r = calloc(1, sizeof(*r));
	if (!r) {
		ret = -EBUSY;
		goto out;
	}
	r->reader = reader;
	r->waiter = &w;
	r->len = len;
	r->deadline_ns = deadline_ns;
	if (esdm_es_read_start(r, &thread)) {
		free(r);
		ret = -EBUSY;
		goto out;
	}
	reader->busy = true;

	while (!w.done) {
		if (esdm_es_reader_wait(reader, deadline_ns) == ETIMEDOUT &&
		    !w.done) {
			/*
			 * Tear the thread down: it is still there, as it ends
			 * under the lock held here. It leaves at its next
			 * cancellation point, or once the device returns from
			 * an uninterruptible wait - until then every caller
			 * gets -EBUSY.
			 */
			r->waiter = NULL;
			reader->abandoned = true;
			pthread_cancel(thread);
			/* The callers waiting for a turn get -EBUSY at once */
			pthread_cond_broadcast(&reader->cond);
			ret = -ETIMEDOUT;
			goto out;
		}
	}
	ret = w.result;

out:
	pthread_mutex_unlock(&reader->lock);
	return ret;
}

bool esdm_es_reader_stuck(struct esdm_es_reader *reader)
{
	bool ret;

	pthread_mutex_lock(&reader->lock);
	ret = reader->busy && reader->abandoned;
	pthread_mutex_unlock(&reader->lock);

	return ret;
}
