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

/*
 * The bounded device read of the hwrng and TPM 2.0 sources: a device that
 * blocks a read for good - a pipe nobody writes to, here - must cost a caller
 * its deadline once, and nothing after, until the read returns.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

#include "common_test.h"
#include "esdm_es_reader.h"
#include "helper.h"

#define MS 1000000ULL

/* A blocking read of @len bytes from the pipe @fd */
static int test_op(int fd, uint8_t *buf, size_t len, uint64_t deadline_ns)
{
	(void)deadline_ns;
	return esdm_safe_read(fd, buf, len) == (ssize_t)len ? 0 : -EIO;
}

/* The same, not to be cancelled: a device the kernel holds the read in */
static int test_op_held(int fd, uint8_t *buf, size_t len, uint64_t deadline_ns)
{
	int state, ret;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	ret = test_op(fd, buf, len, deadline_ns);
	pthread_setcancelstate(state, NULL);

	return ret;
}

static uint64_t test_ms_since(uint64_t start)
{
	return (esdm_monotonic_now_ns() - start) / MS;
}

struct test_caller {
	struct esdm_es_reader *reader;
	int ret;
	uint8_t buf[8];
};

static void *test_caller_run(void *arg)
{
	struct test_caller *c = arg;

	c->ret = esdm_es_reader_read(c->reader, c->buf, sizeof(c->buf),
				     esdm_monotonic_wait_ns() + 2000 * MS, true);
	return NULL;
}

/* Timeout, -EBUSY while stuck, recovery once the read returns */
static void test_stuck(void)
{
	static const uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	struct esdm_es_reader *reader = NULL;
	struct test_caller c[2];
	pthread_t thread[2];
	uint8_t buf[8];
	uint64_t start;
	int p[2], i;

	CHECK_EQ(pipe(p), 0);
	CHECK_EQ(esdm_es_reader_alloc(&reader, p[0], test_op_held, "test"), 0);
	if (!reader)
		return;

	CHECK_EQ(esdm_es_reader_read(reader, buf, 0, UINT64_MAX, true),
		 -EINVAL);

	start = esdm_monotonic_now_ns();
	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 200 * MS, true),
		 -ETIMEDOUT);
	CHECK(test_ms_since(start) < 1000, "the deadline was not kept: %llu ms",
	      (unsigned long long)test_ms_since(start));
	CHECK(esdm_es_reader_stuck(reader), "a read timed out, yet not stuck");

	/* Not waited for again */
	start = esdm_monotonic_now_ns();
	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 2000 * MS, true),
		 -EBUSY);
	CHECK(test_ms_since(start) < 100,
	      "a stuck read was waited for: %llu ms",
	      (unsigned long long)test_ms_since(start));

	/* The read returns, its data is not handed to anybody */
	CHECK_EQ(write(p[1], data, sizeof(data)), sizeof(data));
	for (i = 0; i < 200 && esdm_es_reader_stuck(reader); i++)
		usleep(5000);
	CHECK(!esdm_es_reader_stuck(reader), "the read returned, yet stuck");

	CHECK_EQ(write(p[1], data, sizeof(data)), sizeof(data));
	memset(buf, 0, sizeof(buf));
	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 2000 * MS, true),
		 0);
	CHECK_MEM_EQ(buf, data, sizeof(data));

	/* Two callers at once are served one after the other */
	for (i = 0; i < 2; i++) {
		c[i].reader = reader;
		c[i].ret = -1;
		CHECK_EQ(pthread_create(&thread[i], NULL, test_caller_run,
					&c[i]),
			 0);
	}
	usleep(50000);

	/* One not to wait leaves at once */
	start = esdm_monotonic_now_ns();
	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 2000 * MS,
				     false),
		 -EBUSY);
	CHECK(test_ms_since(start) < 100,
	      "a read in progress was waited for: %llu ms",
	      (unsigned long long)test_ms_since(start));

	CHECK_EQ(write(p[1], data, sizeof(data)), sizeof(data));
	CHECK_EQ(write(p[1], data, sizeof(data)), sizeof(data));
	for (i = 0; i < 2; i++) {
		pthread_join(thread[i], NULL);
		CHECK_EQ(c[i].ret, 0);
		CHECK_MEM_EQ(c[i].buf, data, sizeof(data));
	}

	esdm_es_reader_free(reader);
	close(p[1]);
}

/*
 * Freed with a read stuck, the reader does not wait for it: its thread closes
 * the fd once the read returns
 */
static void test_free_stuck(void)
{
	struct esdm_es_reader *reader = NULL;
	uint8_t buf[8];
	uint64_t start;
	int p[2], i;

	CHECK_EQ(pipe(p), 0);
	CHECK_EQ(esdm_es_reader_alloc(&reader, p[0], test_op_held, "test"), 0);
	if (!reader)
		return;

	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 50 * MS, true),
		 -ETIMEDOUT);

	start = esdm_monotonic_now_ns();
	esdm_es_reader_free(reader);
	CHECK(test_ms_since(start) < 100, "free waited for a stuck read");

	/* The read returns, and the read end goes: a write fails then */
	errno = 0;
	if (write(p[1], buf, sizeof(buf)) == sizeof(buf)) {
		for (i = 0; i < 400; i++) {
			if (write(p[1], buf, 1) < 0)
				break;
			usleep(5000);
		}
	}
	CHECK_EQ(errno, EPIPE);
	close(p[1]);
}

/* A read of 300 ms at most */
static void *test_caller_short(void *arg)
{
	struct test_caller *c = arg;

	c->ret = esdm_es_reader_read(c->reader, c->buf, sizeof(c->buf),
				     esdm_monotonic_wait_ns() + 300 * MS, true);
	return NULL;
}

/*
 * A caller waiting for its turn behind a read that cannot be cancelled hears
 * of it being given up on at once, not at its own deadline
 */
static void test_queued_abandon(void)
{
	static const uint8_t data[8] = { 1 };
	struct esdm_es_reader *reader = NULL;
	struct test_caller c = { .ret = -1 };
	pthread_t thread;
	uint8_t buf[8];
	uint64_t start;
	int p[2], i;

	CHECK_EQ(pipe(p), 0);
	CHECK_EQ(esdm_es_reader_alloc(&reader, p[0], test_op_held, "test"), 0);
	if (!reader)
		return;
	c.reader = reader;

	CHECK_EQ(pthread_create(&thread, NULL, test_caller_short, &c), 0);
	/* Queued behind its read */
	usleep(50000);
	start = esdm_monotonic_wait_ns();
	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 2000 * MS, true),
		 -EBUSY);
	CHECK((esdm_monotonic_wait_ns() - start) / MS < 1000,
	      "the queued caller waited until its deadline");
	pthread_join(thread, NULL);
	CHECK_EQ(c.ret, -ETIMEDOUT);

	CHECK_EQ(write(p[1], data, sizeof(data)), sizeof(data));
	for (i = 0; i < 200 && esdm_es_reader_stuck(reader); i++)
		usleep(5000);
	esdm_es_reader_free(reader);
	close(p[1]);
}

/*
 * A read that can be cancelled is torn down at the timeout: it holds up no
 * later read, and takes no data that arrives after it
 */
static void test_teardown(void)
{
	static const uint8_t data[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
	struct esdm_es_reader *reader = NULL;
	uint8_t buf[8];
	int p[2], i;

	CHECK_EQ(pipe(p), 0);
	CHECK_EQ(esdm_es_reader_alloc(&reader, p[0], test_op, "test"), 0);
	if (!reader)
		return;

	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 50 * MS, true),
		 -ETIMEDOUT);
	for (i = 0; i < 200 && esdm_es_reader_stuck(reader); i++)
		usleep(5000);
	CHECK(!esdm_es_reader_stuck(reader), "a cancelled read stays stuck");

	CHECK_EQ(write(p[1], data, sizeof(data)), sizeof(data));
	memset(buf, 0, sizeof(buf));
	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 2000 * MS, true),
		 0);
	CHECK_MEM_EQ(buf, data, sizeof(data));

	esdm_es_reader_free(reader);
	close(p[1]);
}

/* A read of the thread that returns an error hands that on */
static int test_op_fail(int fd, uint8_t *buf, size_t len, uint64_t deadline_ns)
{
	(void)fd;
	(void)buf;
	(void)len;
	(void)deadline_ns;
	return -ENODEV;
}

static void test_error(void)
{
	struct esdm_es_reader *reader = NULL;
	uint8_t buf[8];
	int p[2];

	CHECK_EQ(pipe(p), 0);
	CHECK_EQ(esdm_es_reader_alloc(&reader, p[0], test_op_fail, NULL), 0);
	if (!reader)
		return;
	CHECK_EQ(esdm_es_reader_read(reader, buf, sizeof(buf),
				     esdm_monotonic_wait_ns() + 2000 * MS, true),
		 -ENODEV);
	CHECK(!esdm_es_reader_stuck(reader), "a failed read left it stuck");
	esdm_es_reader_free(reader);
	close(p[1]);
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);

	test_stuck();
	test_free_stuck();
	test_teardown();
	test_queued_abandon();
	test_error();

	return common_test_result("es_reader");
}
