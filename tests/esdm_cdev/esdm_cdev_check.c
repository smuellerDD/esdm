/*
 * Checks of the esdm_cdev kernel module
 *
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
 * The checks of kernel/esdm_cdev: /dev/esdm_random, /dev/esdm_urandom and
 * /proc/esdm, served by the ESDM over its EGD socket. One subcommand per
 * check, which prints what it found and exits with 0 when that is what the
 * module promises, with a FAIL line and 1 when it is not:
 *
 *	esdm-cdev-check <subcommand> [args]
 *
 * The NixOS VM test of the flake (checks.<system>.esdm_cdev) drives every one
 * of them - with the ESDM running, frozen, restarted and stopped, as root, as
 * nobody and as root without CAP_SYS_ADMIN, and against the fake EGD server
 * of the fake-egd subcommand for what the ESDM cannot be made to do. The ones
 * that hold next to the ESDM of an ordinary machine are meson tests as well,
 * see meson.build.
 *
 * Where the module is not loaded, a check skips (77), as it does where it
 * needs CAP_SYS_ADMIN and does not have it. The VM test asserts success, so a
 * skip fails there as anything else does.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/random.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>

#include "config.h"
#include "esdm_egd_protocol.h"

#define CDEV_RANDOM "/dev/esdm_random"
#define CDEV_URANDOM "/dev/esdm_urandom"
#define CDEV_PROC "/proc/esdm"

static const char *const cdev_devs[] = { CDEV_RANDOM, CDEV_URANDOM };
#define CDEV_NUM_DEVS (sizeof(cdev_devs) / sizeof(cdev_devs[0]))

/* What meson takes for a skipped test */
#define CHECK_SKIP 77

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static void __attribute__((noreturn, format(printf, 1, 2)))
fail(const char *fmt, ...)
{
	va_list ap;

	printf("FAIL: ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");

	exit(1);
}

static void __attribute__((noreturn, format(printf, 1, 2)))
skip(const char *fmt, ...)
{
	va_list ap;

	printf("SKIP: ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");

	exit(CHECK_SKIP);
}

static void *xmalloc(size_t size)
{
	void *p = malloc(size ? size : 1);

	if (!p)
		fail("out of memory for %zu bytes", size);

	return p;
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void sleep_seconds(double seconds)
{
	struct timespec ts = { .tv_sec = (time_t)seconds };

	ts.tv_nsec = (long)((seconds - (double)ts.tv_sec) * 1e9);
	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

static double parse_seconds(const char *arg)
{
	char *end;
	double seconds = strtod(arg, &end);

	if (end == arg || *end || !(seconds > 0))
		fail("%s is no number of seconds", arg);

	return seconds;
}

/*
 * Data of the kernel's RNG to write and to insert - getentropy() rather than
 * <sys/random.h>, whose GRND_* clash with the ones of <linux/random.h>
 */
static void get_random(void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len) {
		size_t chunk = len < 256 ? len : 256;

		if (getentropy(p, chunk))
			fail("getentropy: %s", strerror(errno));
		p += chunk;
		len -= chunk;
	}
}

/*
 * @s for a message, its control characters escaped and cut at 120 characters.
 * Four buffers in turn, so that a message can quote more than one string.
 */
static const char *quote(const char *s)
{
	static char bufs[4][128 * 4 + 8];
	static unsigned int next;
	char *buf = bufs[next++ % ARRAY_SIZE(bufs)];
	size_t i, out = 0;

	buf[out++] = '"';
	for (i = 0; s[i] && i < 120; i++) {
		unsigned char c = (unsigned char)s[i];

		if (c == '\n') {
			buf[out++] = '\\';
			buf[out++] = 'n';
		} else if (c < 0x20 || c == 0x7f) {
			out += (size_t)snprintf(buf + out, 5, "\\x%02x", c);
		} else {
			buf[out++] = (char)c;
		}
	}
	if (s[i]) {
		memcpy(buf + out, "...", 3);
		out += 3;
	}
	buf[out++] = '"';
	buf[out] = '\0';

	return buf;
}

/*
 * The whole content of @path, NUL terminated, to be freed. NULL with errno
 * set when it cannot be read.
 */
static char *read_file(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	size_t len = 0, size = 4096;
	char *buf;

	if (fd < 0)
		return NULL;

	buf = xmalloc(size + 1);
	for (;;) {
		ssize_t rc;

		if (len == size) {
			char *more;

			size *= 2;
			more = realloc(buf, size + 1);
			if (!more)
				fail("out of memory for %zu bytes", size + 1);
			buf = more;
		}

		rc = read(fd, buf + len, size - len);
		if (rc < 0) {
			int err = errno;

			if (err == EINTR)
				continue;
			free(buf);
			close(fd);
			errno = err;
			return NULL;
		}
		if (!rc)
			break;
		len += (size_t)rc;
	}

	close(fd);
	buf[len] = '\0';

	return buf;
}

/******************************************************************************
 * Preconditions
 ******************************************************************************/

static void need_module(void)
{
	if (access(CDEV_RANDOM, F_OK))
		skip("%s: %s - the esdm_cdev module is not loaded", CDEV_RANDOM,
		     strerror(errno));
}

static void
cap_get(struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3])
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};

	if (syscall(SYS_capget, &hdr, data))
		fail("capget: %s", strerror(errno));
}

static bool cap_effective(unsigned int cap)
{
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

	cap_get(data);

	return data[CAP_TO_INDEX(cap)].effective & CAP_TO_MASK(cap);
}

/* Give up @cap for good: effective, permitted and inheritable */
static void cap_drop(unsigned int cap)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

	cap_get(data);
	data[CAP_TO_INDEX(cap)].effective &= ~CAP_TO_MASK(cap);
	data[CAP_TO_INDEX(cap)].permitted &= ~CAP_TO_MASK(cap);
	data[CAP_TO_INDEX(cap)].inheritable &= ~CAP_TO_MASK(cap);
	if (syscall(SYS_capset, &hdr, data))
		fail("capset: %s", strerror(errno));
	if (cap_effective(cap))
		fail("capability %u still effective after dropping it", cap);
}

/* The identity map of the initial user namespace, which capable() looks at */
static bool in_init_user_ns(void)
{
	char *map = read_file("/proc/self/uid_map");
	unsigned long inside, outside, count;
	bool init =
		map &&
		sscanf(map, "%lu %lu %lu", &inside, &outside, &count) == 3 &&
		!inside && !outside && count == 4294967295UL;

	free(map);

	return init;
}

/*
 * The module checks CAP_SYS_ADMIN for whatever changes something in the ESDM,
 * as random.c does - in the initial user namespace, so root of another one is
 * refused like anybody else. Without it such a check has nothing to check.
 */
static void need_cap_sys_admin(void)
{
	if (!cap_effective(CAP_SYS_ADMIN) || !in_init_user_ns())
		skip("this check needs CAP_SYS_ADMIN, as root");
}

/******************************************************************************
 * Reading and judging what was read
 ******************************************************************************/

/*
 * Read @size bytes from a fresh open of @path, as a reader of the device
 * does. Returns 0, or the errno of the open or the read that failed. An end of
 * file fails the check: no device of the module has one.
 */
static int read_exact(const char *path, uint8_t *buf, size_t size, int flags)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC | flags);
	size_t got = 0;
	int err = 0;

	if (fd < 0)
		return errno;

	while (got < size) {
		ssize_t rc = read(fd, buf + got, size - got);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			err = errno;
			break;
		}
		if (!rc)
			fail("%s: end of file after %zu of %zu bytes", path,
			     got, size);
		got += (size_t)rc;
	}

	close(fd);

	return err;
}

static void read_exact_or_fail(const char *path, uint8_t *buf, size_t size,
			       int flags)
{
	int err = read_exact(path, buf, size, flags);

	if (err)
		fail("%s: read of %zu bytes: %s", path, size, strerror(err));
}

/*
 * What random data cannot be: from 32 bytes on, all zeros or one byte value
 * throughout. From 1 MiB on, each byte value is expected 4096 times per MiB,
 * with a standard deviation of 64 - so a value seen 20% less or more often
 * than that, 12 standard deviations off, is a distribution that is not
 * uniform rather than chance.
 */
static void check_random(const uint8_t *data, size_t len, const char *what)
{
	size_t counts[256] = { 0 }, min, max, i;
	double expect;

	if (len >= 32) {
		for (i = 0; i < len && !data[i]; i++)
			;
		if (i == len)
			fail("%s: all zeros", what);
		for (i = 1; i < len && data[i] == data[0]; i++)
			;
		if (i == len)
			fail("%s: constant byte", what);
	}

	if (len < (1 << 20))
		return;

	for (i = 0; i < len; i++)
		counts[data[i]]++;
	min = max = counts[0];
	for (i = 1; i < ARRAY_SIZE(counts); i++) {
		if (counts[i] < min)
			min = counts[i];
		if (counts[i] > max)
			max = counts[i];
	}

	expect = (double)len / 256;
	if ((double)min < expect * 0.8 || (double)max > expect * 1.2)
		fail("%s: byte distribution off (%zu..%zu)", what, min, max);
}

static char *proc_read(const char *name)
{
	char path[128];
	char *content;

	snprintf(path, sizeof(path), CDEV_PROC "/%s", name);
	content = read_file(path);
	if (!content)
		fail("%s: %s", path, strerror(errno));

	return content;
}

/* Write @val to /proc/esdm/@name in one write. Returns 0 or the errno. */
static int proc_write(const char *name, const char *val)
{
	size_t len = strlen(val);
	char path[128];
	ssize_t rc;
	int fd, err = 0;

	snprintf(path, sizeof(path), CDEV_PROC "/%s", name);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return errno;

	rc = write(fd, val, len);
	if (rc < 0)
		err = errno;
	else if ((size_t)rc != len)
		err = EIO;
	if (close(fd) && !err)
		err = errno;

	return err;
}

/******************************************************************************
 * ioctls of random.c
 ******************************************************************************/

/* 0 or the errno of the ioctl */
static int rnd_ioctl(int fd, unsigned long request, void *arg)
{
	return ioctl(fd, request, arg) ? errno : 0;
}

static int rnd_add_entropy(int fd, int bits, int size, const void *data,
			   size_t len)
{
	struct rand_pool_info *info = xmalloc(sizeof(*info) + len);
	int err;

	info->entropy_count = bits;
	info->buf_size = size;
	if (len)
		memcpy(info->buf, data, len);
	err = rnd_ioctl(fd, RNDADDENTROPY, info);
	free(info);

	return err;
}

static void ok_or_fail(int err, const char *dev, const char *what)
{
	if (err)
		fail("%s: %s: %s", dev, what, strerror(err));
}

static int entcnt_or_fail(int fd, const char *dev)
{
	int cnt;

	ok_or_fail(rnd_ioctl(fd, RNDGETENTCNT, &cnt), dev, "RNDGETENTCNT");

	return cnt;
}

static int open_or_fail(const char *path, int flags)
{
	int fd = open(path, flags | O_CLOEXEC);

	if (fd < 0)
		fail("%s: open: %s", path, strerror(errno));

	return fd;
}

/******************************************************************************
 * The devices
 ******************************************************************************/

/*
 * reads [sync]: reads of 1 byte to 1 MiB from both devices, or with O_SYNC of
 * the prediction resistance DRNG, which hands out little at a time, of up to
 * 64 bytes. Every read is random, no two reads are equal, and single bytes
 * take more than a few values.
 */
static void cmd_reads(int argc, char *argv[])
{
	static const size_t sizes[] = { 1, 32, 4096, 1 << 20 };
	static const size_t sizes_sync[] = { 1, 32, 64 };
	bool o_sync = argc == 1;
	const size_t *size = o_sync ? sizes_sync : sizes;
	size_t nsizes = o_sync ? ARRAY_SIZE(sizes_sync) : ARRAY_SIZE(sizes);
	int flags = o_sync ? O_SYNC : 0;
	uint8_t *first = xmalloc(1 << 20), *second = xmalloc(1 << 20);
	unsigned int d;
	size_t i;

	if (o_sync && strcmp(argv[0], "sync"))
		fail("reads takes sync or nothing, not %s", argv[0]);

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];
		bool seen[256] = { false };
		unsigned int values = 0;
		char what[64];

		for (i = 0; i < nsizes; i++) {
			read_exact_or_fail(dev, first, size[i], flags);
			read_exact_or_fail(dev, second, size[i], flags);
			snprintf(what, sizeof(what), "%s %zu", dev, size[i]);
			check_random(first, size[i], what);
			check_random(second, size[i], what);
			if (size[i] >= 32 && !memcmp(first, second, size[i]))
				fail("%s: two reads of %zu bytes are equal",
				     dev, size[i]);
			printf("%s: %zu bytes ok\n", dev, size[i]);
		}

		/* 1 byte reads must not all be equal */
		for (i = 0; i < 64; i++) {
			read_exact_or_fail(dev, first, 1, flags);
			if (!seen[first[0]]) {
				seen[first[0]] = true;
				values++;
			}
		}
		if (values < 8)
			fail("%s: 64 single bytes take %u values only", dev,
			     values);
	}

	free(first);
	free(second);
	printf("reads ok\n");
}

/* nonblock: a read with O_NONBLOCK of an operational ESDM gets random data */
static void cmd_nonblock(int argc, char *argv[])
{
	unsigned int d;

	(void)argc;
	(void)argv;

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];
		int fd = open_or_fail(dev, O_RDONLY | O_NONBLOCK);
		uint8_t data[64];
		char what[64];
		ssize_t rc = read(fd, data, sizeof(data));
		int err = errno;

		close(fd);
		if (rc < 0)
			fail("%s: O_NONBLOCK read: %s", dev, strerror(err));
		if (rc != (ssize_t)sizeof(data))
			fail("%s: O_NONBLOCK read gave %zd bytes", dev, rc);
		snprintf(what, sizeof(what), "%s O_NONBLOCK", dev);
		check_random(data, sizeof(data), what);
	}

	printf("nonblock ok\n");
}

/*
 * poll: /dev/esdm_random is readable once the ESDM is operational, which only
 * that is waited for. /dev/esdm_urandom has no poll(), so it is readable and
 * writable as any file without one.
 */
static void cmd_poll(int argc, char *argv[])
{
	static const short want[CDEV_NUM_DEVS] = { POLLIN | POLLRDNORM,
						   POLLIN | POLLOUT };
	unsigned int d;

	(void)argc;
	(void)argv;

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];
		struct pollfd pfd = { .fd = open_or_fail(dev, O_RDWR),
				      .events = want[d] };
		int rc = poll(&pfd, 1, 10000);
		int err = errno;

		close(pfd.fd);
		if (rc < 0)
			fail("%s: poll: %s", dev, strerror(err));
		if (!rc)
			fail("%s: poll timed out", dev);
		if ((pfd.revents & want[d]) != want[d])
			fail("%s: poll mask %#x, want %#x", dev,
			     (unsigned int)(unsigned short)pfd.revents,
			     (unsigned int)want[d]);
		printf("%s: poll mask %#x\n", dev,
		       (unsigned int)(unsigned short)pfd.revents);
	}

	printf("poll ok\n");
}

/*
 * writes: writes of nothing up to 300 KiB - more than the module inserts with
 * one request - are taken in full, each in one write().
 */
static void cmd_writes(int argc, char *argv[])
{
	static const size_t sizes[] = { 0, 1, 255, 256, 1000, 300 * 1024 };
	uint8_t *data = xmalloc(300 * 1024);
	unsigned int d;
	size_t i;

	(void)argc;
	(void)argv;

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];
		int fd = open_or_fail(dev, O_WRONLY);

		for (i = 0; i < ARRAY_SIZE(sizes); i++) {
			ssize_t rc;

			get_random(data, sizes[i]);
			rc = write(fd, data, sizes[i]);
			if (rc < 0)
				fail("%s: write of %zu: %s", dev, sizes[i],
				     strerror(errno));
			if ((size_t)rc != sizes[i])
				fail("%s: write of %zu returned %zd", dev,
				     sizes[i], rc);
		}
		close(fd);
		printf("%s: writes ok\n", dev);
	}

	free(data);
	printf("writes ok\n");
}

/******************************************************************************
 * The ioctls
 ******************************************************************************/

/*
 * ioctl-priv: as root, every ioctl does what it does to the kernel's pool,
 * and is refused with the arguments random.c refuses - and with a negative
 * size of RNDADDENTROPY, where random.c fails with EFAULT.
 */
static void cmd_ioctl_priv(int argc, char *argv[])
{
	uint8_t data[1000];
	unsigned int d;

	(void)argc;
	(void)argv;

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];
		int fd = open_or_fail(dev, O_RDWR);
		int bits, cnt;

		/*
		 * Credited entropy makes the ESDM reseed at once, which takes
		 * it from the pool again: what is left is at most what was
		 * credited. A clear pool stays clear.
		 */
		ok_or_fail(rnd_ioctl(fd, RNDCLEARPOOL, NULL), dev,
			   "RNDCLEARPOOL");
		cnt = entcnt_or_fail(fd, dev);
		if (cnt)
			fail("%s: entropy count %d after RNDCLEARPOOL", dev,
			     cnt);

		bits = 64;
		ok_or_fail(rnd_ioctl(fd, RNDADDTOENTCNT, &bits), dev,
			   "RNDADDTOENTCNT");
		cnt = entcnt_or_fail(fd, dev);
		if (cnt < 0 || cnt > 64)
			fail("%s: entropy count %d after crediting 64 bits",
			     dev, cnt);

		ok_or_fail(rnd_ioctl(fd, RNDZAPENTCNT, NULL), dev,
			   "RNDZAPENTCNT");
		if (entcnt_or_fail(fd, dev))
			fail("%s: entropy count not 0 after RNDZAPENTCNT", dev);

		get_random(data, 32);
		ok_or_fail(rnd_add_entropy(fd, 128, 32, data, 32), dev,
			   "RNDADDENTROPY");
		cnt = entcnt_or_fail(fd, dev);
		if (cnt < 0 || cnt > 128)
			fail("%s: entropy count %d after RNDADDENTROPY of 128 bits",
			     dev, cnt);

		/* More than the data has bits is credited as the bits it has */
		ok_or_fail(rnd_ioctl(fd, RNDZAPENTCNT, NULL), dev,
			   "RNDZAPENTCNT");
		get_random(data, 4);
		ok_or_fail(rnd_add_entropy(fd, 4096, 4, data, 4), dev,
			   "RNDADDENTROPY");
		cnt = entcnt_or_fail(fd, dev);
		if (cnt < 0 || cnt > 32)
			fail("%s: entropy count %d after crediting 4096 bits to 4 bytes",
			     dev, cnt);

		/* A larger buffer than one EGD transfer */
		ok_or_fail(rnd_ioctl(fd, RNDCLEARPOOL, NULL), dev,
			   "RNDCLEARPOOL");
		get_random(data, sizeof(data));
		ok_or_fail(rnd_add_entropy(fd, 8000, (int)sizeof(data), data,
					   sizeof(data)),
			   dev, "RNDADDENTROPY");

		ok_or_fail(rnd_ioctl(fd, RNDRESEEDCRNG, NULL), dev,
			   "RNDRESEEDCRNG");

		/*
		 * Argument checks: those of random.c, and the stricter one of
		 * the module for the size of RNDADDENTROPY - random.c reads
		 * what it can of a negative size and fails with EFAULT.
		 */
		bits = -1;
		if (rnd_ioctl(fd, RNDADDTOENTCNT, &bits) != EINVAL)
			fail("%s: negative RNDADDTOENTCNT not refused", dev);
		if (rnd_add_entropy(fd, -1, 1, "x", 1) != EINVAL)
			fail("%s: negative RNDADDENTROPY count not refused",
			     dev);
		if (rnd_add_entropy(fd, 8, -1, NULL, 0) != EINVAL)
			fail("%s: negative RNDADDENTROPY size not refused with EINVAL",
			     dev);
		/* A command of the type of random.c that it does not have */
		if (rnd_ioctl(fd, _IO('R', 0x99), NULL) != EINVAL)
			fail("%s: unknown ioctl not answered with EINVAL", dev);

		close(fd);
		printf("%s: privileged ioctls ok\n", dev);
	}

	printf("ioctl-priv ok\n");
}

static void want_eperm(int err, const char *dev, const char *what)
{
	if (err != EPERM)
		fail("%s: %s gave errno %d, want EPERM", dev, what, err);
}

/*
 * ioctl-unpriv: without CAP_SYS_ADMIN, the entropy count can be read and
 * nothing else is done. A caller that has the capability gives it up first,
 * so that this checks the same as root as it does as anybody else.
 */
static void cmd_ioctl_unpriv(int argc, char *argv[])
{
	unsigned int d;
	int err;

	(void)argc;
	(void)argv;

	if (cap_effective(CAP_SYS_ADMIN)) {
		cap_drop(CAP_SYS_ADMIN);
		printf("CAP_SYS_ADMIN dropped\n");
	}

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];
		int fd = open_or_fail(dev, O_RDWR);
		int bits = 8;

		printf("%s: RNDGETENTCNT %d\n", dev, entcnt_or_fail(fd, dev));
		want_eperm(rnd_ioctl(fd, RNDADDTOENTCNT, &bits), dev,
			   "RNDADDTOENTCNT");
		want_eperm(rnd_add_entropy(fd, 8, 1, "x", 1), dev,
			   "RNDADDENTROPY");
		want_eperm(rnd_ioctl(fd, RNDZAPENTCNT, NULL), dev,
			   "RNDZAPENTCNT");
		want_eperm(rnd_ioctl(fd, RNDCLEARPOOL, NULL), dev,
			   "RNDCLEARPOOL");
		want_eperm(rnd_ioctl(fd, RNDRESEEDCRNG, NULL), dev,
			   "RNDRESEEDCRNG");
		if (entcnt_or_fail(fd, dev) < 0)
			fail("%s: entropy count negative", dev);

		close(fd);
		printf("%s: unprivileged ioctls ok\n", dev);
	}

	/* The writable proc files are the ESDM's to change, with CAP_SYS_ADMIN */
	err = proc_write("write_wakeup_threshold", "512\n");
	if (!err)
		fail("write_wakeup_threshold writable without CAP_SYS_ADMIN");
	if (err != EPERM && err != EACCES)
		fail("write_wakeup_threshold: errno %d", err);

	printf("ioctl-unpriv ok\n");
}

/******************************************************************************
 * /proc/esdm
 ******************************************************************************/

static const char *const proc_files[] = {
	"entropy_avail",
	"poolsize",
	"write_wakeup_threshold",
	"urandom_min_reseed_secs",
	"status",
	"status.json",
};

static bool is_number(const char *s)
{
	size_t i;

	for (i = 0; s[i] >= '0' && s[i] <= '9'; i++)
		;

	return i && !strcmp(s + i, "\n");
}

static int strcmp_ptr(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/*
 * The values the proc check changes, written back when it ends, also when it
 * fails: they are the settings of the ESDM of the machine.
 */
static char *proc_saved_wakeup, *proc_saved_reseed;

static void proc_restore(void)
{
	if (proc_saved_wakeup)
		proc_write("write_wakeup_threshold", proc_saved_wakeup);
	if (proc_saved_reseed)
		proc_write("urandom_min_reseed_secs", proc_saved_reseed);
}

static void proc_restore_or_fail(const char *name, char **saved)
{
	int err = proc_write(name, *saved);

	if (err)
		fail("%s: restoring %s: %s", name, quote(*saved),
		     strerror(err));
	free(*saved);
	*saved = NULL;
}

/* The files of /proc/esdm are those of proc_files and nothing else */
static void proc_check_listing(void)
{
	const char *want[ARRAY_SIZE(proc_files)];
	char *names[64], listing[64 * 32] = "";
	DIR *dir = opendir(CDEV_PROC);
	size_t n = 0, i;
	struct dirent *de;
	bool same;

	if (!dir)
		fail("%s: %s", CDEV_PROC, strerror(errno));
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (n == ARRAY_SIZE(names))
			fail("%s holds more than %zu files", CDEV_PROC, n);
		names[n] = strdup(de->d_name);
		if (!names[n])
			fail("out of memory");
		n++;
	}
	closedir(dir);

	memcpy(want, proc_files, sizeof(want));
	qsort(want, ARRAY_SIZE(want), sizeof(want[0]), strcmp_ptr);
	qsort(names, n, sizeof(names[0]), strcmp_ptr);

	same = n == ARRAY_SIZE(want);
	for (i = 0; i < n; i++) {
		if (same && strcmp(names[i], want[i]))
			same = false;
		snprintf(listing + strlen(listing),
			 sizeof(listing) - strlen(listing), "%s%s",
			 i ? ", " : "", names[i]);
	}
	if (!same)
		fail("%s holds [%s]", CDEV_PROC, listing);

	for (i = 0; i < n; i++)
		free(names[i]);
}

/* status.json is a JSON object with the members every status has */
static void proc_check_json(void)
{
	static const char *const keys[] = { "library_version",
					    "entropy_sources", "drngs" };
	char *doc = proc_read("status.json");
	size_t len = strlen(doc), end, i;
	struct json_tokener *tok = json_tokener_new();
	struct json_object *obj;

	if (!tok)
		fail("out of memory");
	if (len > ESDM_EGD_MAX_STATUS)
		fail("status.json: %zu bytes, more than the protocol carries",
		     len);
	obj = json_tokener_parse_ex(tok, doc, (int)len);
	if (!obj)
		fail("status.json is no JSON document: %s",
		     json_tokener_error_desc(json_tokener_get_error(tok)));
	for (end = json_tokener_get_parse_end(tok);
	     end < len && strchr(" \t\r\n", doc[end]); end++)
		;
	if (end != len)
		fail("status.json: trailing data after the document: %s",
		     quote(doc + end));
	if (!json_object_is_type(obj, json_type_object))
		fail("status.json is no JSON object");
	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		if (!json_object_object_get_ex(obj, keys[i], NULL))
			fail("status.json lacks \"%s\"", keys[i]);
	}

	json_object_put(obj);
	json_tokener_free(tok);
	free(doc);
}

/*
 * proc: the files of /proc/esdm with the ESDM reachable - their content, the
 * two that can be written, and what is refused there.
 */
static void cmd_proc(int argc, char *argv[])
{
	static const char *const numbers[] = { "entropy_avail", "poolsize",
					       "write_wakeup_threshold",
					       "urandom_min_reseed_secs" };
	static const char *const bad[] = { "abc", "-1", "4294967295", "1 2" };
	static const char *const sections[] = { "ESDM library version",
						"Entropy Source",
						"DRNG instance" };
	char *val;
	size_t i;
	int err;

	(void)argc;
	(void)argv;

	proc_check_listing();

	for (i = 0; i < ARRAY_SIZE(numbers); i++) {
		val = proc_read(numbers[i]);
		if (!is_number(val))
			fail("%s: %s", numbers[i], quote(val));
		printf("%s: %.*s\n", numbers[i], (int)strlen(val) - 1, val);
		free(val);
	}

	atexit(proc_restore);

	proc_saved_wakeup = proc_read("write_wakeup_threshold");
	err = proc_write("write_wakeup_threshold", "1234\n");
	if (err)
		fail("write_wakeup_threshold: writing 1234: %s", strerror(err));
	val = proc_read("write_wakeup_threshold");
	if (strcmp(val, "1234\n"))
		fail("write_wakeup_threshold not set: %s", quote(val));
	free(val);

	proc_saved_reseed = proc_read("urandom_min_reseed_secs");
	err = proc_write("urandom_min_reseed_secs", "77");
	if (err)
		fail("urandom_min_reseed_secs: writing 77: %s", strerror(err));
	val = proc_read("urandom_min_reseed_secs");
	if (strcmp(val, "77\n"))
		fail("urandom_min_reseed_secs not set: %s", quote(val));
	free(val);
	proc_restore_or_fail("urandom_min_reseed_secs", &proc_saved_reseed);

	for (i = 0; i < ARRAY_SIZE(bad); i++) {
		err = proc_write("write_wakeup_threshold", bad[i]);
		if (!err)
			fail("write_wakeup_threshold took %s", quote(bad[i]));
		if (err != EINVAL && err != ERANGE)
			fail("write_wakeup_threshold %s: errno %d",
			     quote(bad[i]), err);
	}
	proc_restore_or_fail("write_wakeup_threshold", &proc_saved_wakeup);

	if (!proc_write("poolsize", "1"))
		fail("poolsize writable");

	val = proc_read("status");
	for (i = 0; i < ARRAY_SIZE(sections); i++) {
		if (!strstr(val, sections[i]))
			fail("status lacks \"%s\":\n%s", sections[i], val);
	}
	free(val);

	proc_check_json();

	printf("proc ok\n");
}

/******************************************************************************
 * Readers in the background, and speed
 ******************************************************************************/

/*
 * loop <dev> <seconds>: reads of 4096 bytes for that long, across a restart
 * of the ESDM, get random data and no error. The line "loop reads=...
 * errors=..." is what the VM test waits for.
 */
static void cmd_loop(int argc, char *argv[])
{
	const char *dev = argv[0];
	double end = now() + parse_seconds(argv[1]);
	unsigned long reads = 0, errors = 0;
	uint8_t data[4096];

	(void)argc;

	while (now() < end) {
		int err = read_exact(dev, data, sizeof(data), 0);

		if (err) {
			errors++;
			printf("read error %s\n", strerror(err));
			continue;
		}
		check_random(data, sizeof(data), dev);
		reads++;
	}

	printf("loop reads=%lu errors=%lu\n", reads, errors);
	if (errors || !reads)
		fail("loop");
}

/*
 * block <dev>: a reader that stays in read() until it is killed, or reads on
 * when a read returns. "blocking" once the device is open: from then on, the
 * module cannot be unloaded.
 */
static void __attribute__((noreturn)) cmd_block(int argc, char *argv[])
{
	const char *dev = argv[0];
	int fd = open_or_fail(dev, O_RDONLY);
	uint8_t *buf = xmalloc(1 << 20);

	(void)argc;

	printf("blocking\n");
	fflush(stdout);
	for (;;) {
		if (read(fd, buf, 1 << 20) < 0 && errno != EINTR)
			fail("%s: read: %s", dev, strerror(errno));
	}
}

static int unix_connect(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	if (strlen(path) >= sizeof(addr.sun_path))
		fail("%s: path too long for a Unix socket", path);
	memcpy(addr.sun_path, path, strlen(path));

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		fail("socket: %s", strerror(errno));
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
		fail("%s: connect: %s", path, strerror(errno));

	return fd;
}

/* 0, or -1 for an error or the end of the connection */
static int recv_exact(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len) {
		ssize_t rc = recv(fd, p, len, 0);

		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0)
			return -1;
		p += rc;
		len -= (size_t)rc;
	}

	return 0;
}

static int send_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len) {
		ssize_t rc = send(fd, p, len, MSG_NOSIGNAL);

		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0)
			return -1;
		p += rc;
		len -= (size_t)rc;
	}

	return 0;
}

/* Runs per figure of the throughput, and how long each one reads */
#define THROUGHPUT_RUNS 5
#define THROUGHPUT_RUN_SEC 0.25

static int cmp_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

/*
 * Nanoseconds one reading of @clock takes, the median of several runs. The
 * figures of the throughput depend on it: the ESDM reads the clock along the
 * way, which costs a trap to the hypervisor on a clocksource without a vDSO,
 * such as the acpi_pm the NixOS test framework boots its VMs with.
 */
static double clock_cost_ns(clockid_t clock)
{
	double runs[THROUGHPUT_RUNS];
	unsigned int r, i;

	for (r = 0; r < THROUGHPUT_RUNS; r++) {
		struct timespec ts;
		double t = now();

		for (i = 0; i < 1000; i++)
			clock_gettime(clock, &ts);
		runs[r] = (now() - t) / 1000 * 1e9;
	}
	qsort(runs, THROUGHPUT_RUNS, sizeof(runs[0]), cmp_double);

	return runs[THROUGHPUT_RUNS / 2];
}

/* The clocksource of the kernel, and what reading the clocks costs */
static void throughput_clocks(void)
{
	char source[64] = "unknown";
	FILE *f = fopen("/sys/devices/system/clocksource/clocksource0/current_clocksource",
			"r");

	if (f) {
		if (fgets(source, sizeof(source), f))
			source[strcspn(source, "\n")] = '\0';
		fclose(f);
	}

	printf("clocksource %s: CLOCK_MONOTONIC %.0f ns, CLOCK_MONOTONIC_COARSE %.0f ns\n",
	       source, clock_cost_ns(CLOCK_MONOTONIC),
	       clock_cost_ns(CLOCK_MONOTONIC_COARSE));
}

/*
 * One read of up to @size bytes into @buf: the number of bytes read, or a
 * negative errno
 */
typedef ssize_t (*throughput_fn)(void *ctx, uint8_t *buf, size_t size);

/*
 * Answers of the EGD socket shorter than asked for. An unseeded read is
 * answered short when the DRNG serving it reaches the most it may generate
 * without a full reseed on the way - 2^17 bits in a build for SP800-90C, which
 * a reader at full speed runs into every 16 KiB -, and empty while every DRNG
 * waits for its reseed. Counted, not failed: it says the reseeds set the pace.
 */
static unsigned long throughput_short;

/*
 * Reads of @size bytes by @fn for THROUGHPUT_RUN_SEC each of THROUGHPUT_RUNS
 * runs: the median in MB/s and reads per second, and the slowest and fastest
 * run - the VM shares its host with whatever else runs there.
 */
static void throughput_one(const char *what, throughput_fn fn, void *ctx,
			   uint8_t *buf, size_t size)
{
	double mbs[THROUGHPUT_RUNS];
	unsigned int r;

	for (r = 0; r < THROUGHPUT_RUNS; r++) {
		double t = now(), end = t + THROUGHPUT_RUN_SEC, dt;
		size_t total = 0;

		do {
			ssize_t got = fn(ctx, buf, size);

			if (got < 0)
				fail("%s: read of %zu bytes: %s", what, size,
				     strerror((int)-got));
			total += (size_t)got;
		} while (now() < end);
		dt = now() - t;
		mbs[r] = (double)total / dt / 1e6;
	}
	qsort(mbs, THROUGHPUT_RUNS, sizeof(mbs[0]), cmp_double);

	printf("%-34s %6zu B: %8.2f MB/s %8.0f reads/s (%.2f .. %.2f)", what,
	       size, mbs[THROUGHPUT_RUNS / 2],
	       mbs[THROUGHPUT_RUNS / 2] * 1e6 / (double)size, mbs[0],
	       mbs[THROUGHPUT_RUNS - 1]);
	if (throughput_short)
		printf(", %lu answers short", throughput_short);
	printf("\n");
	throughput_short = 0;
}

/* A read of a device, on the descriptor @ctx points to */
static ssize_t throughput_dev(void *ctx, uint8_t *buf, size_t size)
{
	int fd = *(int *)ctx;
	size_t done = 0;

	while (done < size) {
		ssize_t n = read(fd, buf + done, size - done);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (!n)
			return -EIO;
		done += (size_t)n;
	}

	return (ssize_t)done;
}

/*
 * A read on the EGD socket at the descriptor @ctx points to: the unseeded read
 * of /dev/esdm_urandom, all commands of it sent at once and the answers
 * collected after, as the module sends them.
 */
static ssize_t throughput_egd(void *ctx, uint8_t *buf, size_t size)
{
	int fd = *(int *)ctx;
	size_t num = (size + ESDM_EGD_MAX_TRANSFER - 1) / ESDM_EGD_MAX_TRANSFER;
	size_t i, done = 0;
	uint8_t *req = xmalloc(2 * num);
	ssize_t ret;

	for (i = 0; i < num; i++) {
		size_t chunk = size - i * ESDM_EGD_MAX_TRANSFER;

		req[2 * i] = ESDM_EGD_CMD_ESDM_READ_UNSEEDED;
		req[2 * i + 1] = (uint8_t)(chunk > ESDM_EGD_MAX_TRANSFER ?
						   ESDM_EGD_MAX_TRANSFER :
						   chunk);
	}

	if (send_all(fd, req, 2 * num)) {
		ret = errno ? -errno : -EIO;
		goto out;
	}
	for (i = 0; i < num; i++) {
		uint8_t n;

		if (recv_exact(fd, &n, 1)) {
			ret = -EPIPE;
			goto out;
		}
		/*
		 * An operational ESDM serves, if short at times, see above -
		 * with nothing even, while all of its DRNGs wait for their
		 * reseed
		 */
		if (n > req[2 * i + 1] || recv_exact(fd, buf + done, n)) {
			ret = -EIO;
			goto out;
		}
		if (n < req[2 * i + 1])
			throughput_short++;
		done += n;
	}
	ret = (ssize_t)done;

out:
	free(req);
	return ret;
}

/*
 * throughput [socket]: informational - reads of 32 bytes, of the 255 bytes of
 * one EGD transfer, of a page and of 64 KiB through each device, and through
 * the EGD socket of the ESDM from user space, for comparison: the commands of a
 * read sent at once, the way the module sends them. With the clocksource and
 * the cost of reading the clocks, which the figures depend on.
 */
static void cmd_throughput(int argc, char *argv[])
{
	static const size_t sizes[] = { 32, ESDM_EGD_MAX_TRANSFER, 4096,
					65536 };
	const char *path = argc ? argv[0] : ESDM_SERVER_EGD_SOCKET_PATH;
	uint8_t *buf = xmalloc(65536);
	unsigned int d, i;
	int fd;

	throughput_clocks();

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		fd = open_or_fail(cdev_devs[d], O_RDONLY);
		for (i = 0; i < ARRAY_SIZE(sizes); i++)
			throughput_one(cdev_devs[d], throughput_dev, &fd, buf,
				       sizes[i]);
		close(fd);
	}

	fd = unix_connect(path);
	for (i = 0; i < ARRAY_SIZE(sizes); i++)
		throughput_one("EGD socket", throughput_egd, &fd, buf,
			       sizes[i]);
	close(fd);

	memset(buf, 0, 65536);
	free(buf);
}

/******************************************************************************
 * Writers whose data does not come
 ******************************************************************************/

#define STALLED_WRITERS 16
#define STALLED_REGION (1 << 20)

struct stalled_writer {
	pthread_t thread;
	const char *dev;
	void *region;
};

static atomic_uint stalled_writers_back;

static void *stalled_writer(void *arg)
{
	struct stalled_writer *w = arg;
	int fd = open(w->dev, O_WRONLY | O_CLOEXEC);

	if (fd >= 0) {
		ssize_t rc = write(fd, w->region, STALLED_REGION);

		(void)rc;
	}
	atomic_fetch_add(&stalled_writers_back, 1);

	return NULL;
}

static void bounded_done(const char *what, double start)
{
	double took = now() - start;

	printf("%s: %.2f s\n", what, took);
	if (took > 2)
		fail("%s took %.1f s next to stalled writers", what, took);
}

/*
 * stalled-writers: writers whose data does not come - their buffer is in a
 * userfaultfd range nobody serves, so the module's copy from it waits for
 * good. More of them than the module has connections must not keep anybody
 * else from the ESDM. A userfaultfd catching the faults of the kernel, not of
 * user space only, takes CAP_SYS_PTRACE or vm.unprivileged_userfaultfd=1.
 */
static void __attribute__((noreturn))
cmd_stalled_writers(int argc, char *argv[])
{
	struct stalled_writer writers[STALLED_WRITERS];
	struct uffdio_api api = { .api = UFFD_API };
	struct uffdio_register reg = { .mode = UFFDIO_REGISTER_MODE_MISSING };
	uint8_t data[4096];
	char what[64];
	unsigned int i, d;
	void *region;
	double start;
	int uffd;

	(void)argc;
	(void)argv;

	uffd = (int)syscall(SYS_userfaultfd, O_CLOEXEC);
	if (uffd < 0 && errno == EPERM)
		skip("userfaultfd: %s - this check needs CAP_SYS_PTRACE, as root",
		     strerror(errno));
	if (uffd < 0)
		fail("userfaultfd: %s", strerror(errno));
	if (ioctl(uffd, UFFDIO_API, &api))
		fail("UFFDIO_API: %s", strerror(errno));

	region = mmap(NULL, STALLED_REGION, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		fail("mmap: %s", strerror(errno));
	reg.range.start = (uintptr_t)region;
	reg.range.len = STALLED_REGION;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg))
		fail("UFFDIO_REGISTER: %s", strerror(errno));

	for (i = 0; i < STALLED_WRITERS; i++) {
		writers[i].dev = cdev_devs[i % CDEV_NUM_DEVS];
		writers[i].region = region;
		if (pthread_create(&writers[i].thread, NULL, stalled_writer,
				   &writers[i]))
			fail("cannot start writer %u", i);
	}
	sleep_seconds(2);
	if (atomic_load(&stalled_writers_back))
		fail("the writers did not stall in the copy of their data");

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];
		int fd;

		snprintf(what, sizeof(what), "%s read", dev);
		start = now();
		read_exact_or_fail(dev, data, sizeof(data), 0);
		bounded_done(what, start);

		fd = open_or_fail(dev, O_RDONLY);
		snprintf(what, sizeof(what), "%s RNDGETENTCNT", dev);
		start = now();
		entcnt_or_fail(fd, dev);
		bounded_done(what, start);
		close(fd);
	}
	start = now();
	free(proc_read("status"));
	bounded_done(CDEV_PROC "/status", start);

	printf("stalled-writers ok\n");
	fflush(stdout);

	/* The writers are stuck in the page fault until the process goes */
	_exit(0);
}

/******************************************************************************
 * A fake EGD server, and the checks against it
 ******************************************************************************/

static const char *fake_log_path;
static pthread_mutex_t fake_log_lock = PTHREAD_MUTEX_INITIALIZER;

/* A line in the log of the fake EGD, opened anew for every line */
static void __attribute__((format(printf, 1, 2)))
fake_note(const char *fmt, ...)
{
	char line[64];
	va_list ap;
	int fd, len;
	bool ok;

	va_start(ap, fmt);
	len = vsnprintf(line, sizeof(line) - 1, fmt, ap);
	va_end(ap);
	if (len < 0 || (size_t)len >= sizeof(line) - 1)
		fail("log line too long");
	line[len++] = '\n';

	pthread_mutex_lock(&fake_log_lock);
	fd = open(fake_log_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
		  0644);
	ok = fd >= 0 && write(fd, line, (size_t)len) == len;
	if (fd >= 0)
		close(fd);
	pthread_mutex_unlock(&fake_log_lock);

	if (!ok)
		fail("%s: cannot log: %s", fake_log_path, strerror(errno));
}

static void put_be32(uint8_t *p, uint32_t val)
{
	p[0] = (uint8_t)(val >> 24);
	p[1] = (uint8_t)(val >> 16);
	p[2] = (uint8_t)(val >> 8);
	p[3] = (uint8_t)val;
}

static uint32_t get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/*
 * Answer @cmd as an ESDM that is not operational, with nothing in its pool.
 * Returns 0 to go on, -1 to close the connection.
 */
static int fake_egd_cmd(int fd, uint8_t cmd)
{
	static const uint8_t none[4];
	uint8_t state[1 + 4 * ESDM_EGD_STATE_NUM_FIELDS];
	uint8_t data[4096];
	uint32_t len;

	switch (cmd) {
	case ESDM_EGD_CMD_ESDM_BULK_READ:
		/* Nothing before the ESDM is operational */
		if (recv_exact(fd, data, 5))
			return -1;
		fake_note("read %02x", (unsigned int)data[0]);
		return send_all(fd, none, 4);

	case ESDM_EGD_CMD_ESDM_BULK_INSERT:
		if (recv_exact(fd, data, 4))
			return -1;
		len = get_be32(data);
		if (len > ESDM_EGD_MAX_BULK)
			return -1;
		fake_note("insert %u", len);
		while (len) {
			uint32_t n = len < sizeof(data) ? len : sizeof(data);

			if (recv_exact(fd, data, n))
				return -1;
			len -= n;
		}
		return send_all(fd, none, 4);

	case ESDM_EGD_CMD_ESDM_GET_STATE:
		/* Not operational, nothing in the pool */
		state[0] = ESDM_EGD_STATE_NUM_FIELDS;
		put_be32(state + 1 + 4 * ESDM_EGD_STATE_FLAGS, 0);
		put_be32(state + 1 + 4 * ESDM_EGD_STATE_ENT_CNT, 0);
		put_be32(state + 1 + 4 * ESDM_EGD_STATE_POOLSIZE, 256);
		put_be32(state + 1 + 4 * ESDM_EGD_STATE_WRITE_WAKEUP, 64);
		put_be32(state + 1 + 4 * ESDM_EGD_STATE_MIN_RESEED_SECS, 60);
		return send_all(fd, state, sizeof(state));

	case ESDM_EGD_CMD_ESDM_STATUS:
	case ESDM_EGD_CMD_ESDM_STATUS_JSON:
		/* A report of no length */
		return send_all(fd, none, 4);

	case ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT:
	case ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP:
	case ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS:
		if (recv_exact(fd, data, 4))
			return -1;
		fake_note("%02x %u", (unsigned int)cmd, get_be32(data));
		/* Time for a signal to arrive while the answer is due */
		if (cmd == ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT)
			sleep_seconds(1);
		return send_all(fd, none, 4);

	case ESDM_EGD_CMD_ESDM_CLEAR_POOL:
	case ESDM_EGD_CMD_ESDM_RESEED:
		fake_note("%02x", (unsigned int)cmd);
		return send_all(fd, none, 4);

	default:
		/*
		 * The commands the module does not send, and anything else:
		 * the connection goes, as with an EGD that does not know the
		 * command.
		 */
		return -1;
	}
}

static void *fake_egd_serve(void *arg)
{
	int fd = (int)(intptr_t)arg;
	uint8_t cmd;

	while (!recv_exact(fd, &cmd, 1) && !fake_egd_cmd(fd, cmd))
		;
	close(fd);

	return NULL;
}

/*
 * fake-egd <socket> <log> <notop|mute>: an EGD server in place of the ESDM,
 * for what the real one cannot be made to do: answer like an ESDM that is not
 * operational yet (notop), or accept connections and never answer (mute). It
 * logs "listening" once it does, every connection, every read and every
 * command that changes something to <log> - what the checks below look at.
 */
static void __attribute__((noreturn)) cmd_fake_egd(int argc, char *argv[])
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	const char *path = argv[0], *mode = argv[2];
	pthread_attr_t attr;
	bool mute;
	int srv;

	(void)argc;

	fake_log_path = argv[1];
	if (!strcmp(mode, "mute"))
		mute = true;
	else if (!strcmp(mode, "notop"))
		mute = false;
	else
		fail("fake-egd mode %s is neither notop nor mute", mode);

	if (strlen(path) >= sizeof(addr.sun_path))
		fail("%s: path too long for a Unix socket", path);
	memcpy(addr.sun_path, path, strlen(path));

	/* An answer to a connection the module closed is no reason to go */
	signal(SIGPIPE, SIG_IGN);

	if (unlink(path) && errno != ENOENT)
		fail("%s: unlink: %s", path, strerror(errno));
	srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (srv < 0)
		fail("socket: %s", strerror(errno));
	if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)))
		fail("%s: bind: %s", path, strerror(errno));
	if (listen(srv, 64))
		fail("%s: listen: %s", path, strerror(errno));

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	fake_note("listening");
	for (;;) {
		int c = accept4(srv, NULL, NULL, SOCK_CLOEXEC);
		pthread_t thread;

		if (c < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			fail("%s: accept: %s", path, strerror(errno));
		}

		fake_note("connect");
		/* Held open and never answered */
		if (mute)
			continue;
		if (pthread_create(&thread, &attr, fake_egd_serve,
				   (void *)(intptr_t)c))
			fail("cannot start a thread for a connection");
	}
}

/* A line of the log of the fake EGD, split into its words */
struct fake_log_entry {
	char word[3][16];
	unsigned int words;
};

static struct fake_log_entry *fake_log(const char *path, size_t *num)
{
	char *content = read_file(path), *line, *save_line;
	struct fake_log_entry *entries;
	size_t n = 0, lines = 1;
	const char *p;

	if (!content)
		fail("%s: %s", path, strerror(errno));
	for (p = content; *p; p++)
		lines += *p == '\n';
	entries = xmalloc(lines * sizeof(*entries));

	for (line = strtok_r(content, "\n", &save_line); line;
	     line = strtok_r(NULL, "\n", &save_line)) {
		struct fake_log_entry *e = &entries[n++];
		char *word, *save_word;

		memset(e, 0, sizeof(*e));
		for (word = strtok_r(line, " \t", &save_word); word;
		     word = strtok_r(NULL, " \t", &save_word)) {
			if (e->words == ARRAY_SIZE(e->word) ||
			    strlen(word) >= sizeof(e->word[0]))
				fail("%s: unexpected line", path);
			strcpy(e->word[e->words++], word);
		}
	}

	free(content);
	*num = n;

	return entries;
}

static bool fake_log_is(const struct fake_log_entry *e, const char *w0,
			const char *w1)
{
	if (strcmp(e->word[0], w0))
		return false;
	if (!w1)
		return e->words == 1;
	return e->words == 2 && !strcmp(e->word[1], w1);
}

static size_t fake_log_count(const char *path, const char *w0)
{
	size_t n, i, count = 0;
	struct fake_log_entry *entries = fake_log(path, &n);

	for (i = 0; i < n; i++)
		count += fake_log_is(&entries[i], w0, NULL);
	free(entries);

	return count;
}

static void fake_log_print(const struct fake_log_entry *e)
{
	unsigned int w;

	printf(" [");
	for (w = 0; w < e->words; w++)
		printf("%s%s", w ? " " : "", e->word[w]);
	printf("]");
}

/*
 * Fails the check when the fake EGD at @path logged anything but connections
 * from its entry @before on
 */
static void fake_log_nothing_since(const char *path, size_t before,
				   const char *what)
{
	struct fake_log_entry *entries;
	size_t n, i;

	entries = fake_log(path, &n);
	for (i = before; i < n; i++) {
		if (fake_log_is(&entries[i], "connect", NULL))
			continue;
		printf("%s:", what);
		fake_log_print(&entries[i]);
		printf("\n");
		fail("%s sent something to the ESDM", what);
	}
	free(entries);
}

/*
 * addentropy <log>: against a notop fake-egd - RNDADDENTROPY inserts all of
 * the data, which carries no entropy claim, and credits it after that in one
 * go, with no more than the data has bits. A negative entropy count or size is refused, a size
 * of 0 taken, without anything sent to the ESDM.
 */
static void cmd_addentropy(int argc, char *argv[])
{
	static const struct {
		int bits, size, credit;
	} cases[] = { { 256, 1000, 256 }, { 4096, 4, 32 }, { 0, 300, 0 } };
	static const struct {
		int bits, size, err;
	} refused[] = { { -1, 16, EINVAL },
			{ INT32_MIN, 16, EINVAL },
			{ 64, -1, EINVAL },
			{ 64, INT32_MIN, EINVAL },
			{ 64, 0, 0 } };
	const char *path = argv[0];
	int fd = open_or_fail(CDEV_RANDOM, O_RDWR);
	uint8_t data[1000];
	size_t c;

	(void)argc;

	for (c = 0; c < ARRAY_SIZE(refused); c++) {
		char what[64];
		size_t before;
		int err;

		snprintf(what, sizeof(what),
			 "RNDADDENTROPY of %d bits on %d bytes",
			 refused[c].bits, refused[c].size);
		free(fake_log(path, &before));
		get_random(data, 16);
		err = rnd_add_entropy(fd, refused[c].bits, refused[c].size,
				      data, 16);
		if (err != refused[c].err)
			fail("%s: errno %d, want %d", what, err,
			     refused[c].err);
		fake_log_nothing_since(path, before, what);
		printf("%s: %s, nothing sent\n", what,
		       err ? strerror(err) : "taken");
	}

	for (c = 0; c < ARRAY_SIZE(cases); c++) {
		struct fake_log_entry *entries, *last = NULL;
		size_t before, n, i, credits = 0, credits_ok = 0;
		unsigned long inserted = 0;
		char credit[16];
		int err;

		free(fake_log(path, &before));
		get_random(data, (size_t)cases[c].size);
		err = rnd_add_entropy(fd, cases[c].bits, cases[c].size, data,
				      (size_t)cases[c].size);
		if (err)
			fail("RNDADDENTROPY of %d bits on %d bytes: %s",
			     cases[c].bits, cases[c].size, strerror(err));

		snprintf(credit, sizeof(credit), "%d", cases[c].credit);
		entries = fake_log(path, &n);
		printf("RNDADDENTROPY of %d bits on %d bytes:", cases[c].bits,
		       cases[c].size);
		for (i = before; i < n; i++) {
			struct fake_log_entry *e = &entries[i];

			if (fake_log_is(e, "connect", NULL))
				continue;
			fake_log_print(e);
			last = e;

			if (!strcmp(e->word[0], "insert")) {
				inserted += strtoul(e->word[1], NULL, 10);
			} else if (!strcmp(e->word[0], "e6")) {
				credits++;
				credits_ok += fake_log_is(e, "e6", credit);
			}
		}
		printf("\n");

		if (inserted != (unsigned long)cases[c].size)
			fail("not all of the data inserted");
		if (cases[c].credit ? (credits != 1 || credits_ok != 1 ||
				       !fake_log_is(last, "e6", credit)) :
				      credits != 0)
			fail("not credited with %d bits after the data",
			     cases[c].credit);
		free(entries);
	}

	close(fd);
	printf("addentropy ok\n");
}

/*
 * write-notop <log>: against a notop fake-egd - write() of either device, by
 * root, inserts all of the data and sends nothing else: no credit, which the
 * module, root towards the ESDM, would have honoured.
 */
static void cmd_write_notop(int argc, char *argv[])
{
	static const size_t sizes[] = { 1, 255, 256, 1000, 300 * 1024 };
	const char *path = argv[0];
	uint8_t *data = xmalloc(300 * 1024);
	unsigned int d;
	size_t i;

	(void)argc;

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];
		int fd = open_or_fail(dev, O_WRONLY);

		for (i = 0; i < ARRAY_SIZE(sizes); i++) {
			struct fake_log_entry *entries;
			unsigned long inserted = 0, insertions = 0;
			size_t before, n, e;
			ssize_t rc;

			free(fake_log(path, &before));
			get_random(data, sizes[i]);
			rc = write(fd, data, sizes[i]);
			if (rc < 0)
				fail("%s: write of %zu: %s", dev, sizes[i],
				     strerror(errno));
			if ((size_t)rc != sizes[i])
				fail("%s: write of %zu returned %zd", dev,
				     sizes[i], rc);

			/* Answered, so logged */
			entries = fake_log(path, &n);
			for (e = before; e < n; e++) {
				const struct fake_log_entry *l = &entries[e];

				if (fake_log_is(l, "connect", NULL))
					continue;
				if (strcmp(l->word[0], "insert") ||
				    l->words != 2) {
					printf("%s: write of %zu:", dev,
					       sizes[i]);
					fake_log_print(l);
					printf("\n");
					fail("%s: write of %zu sent more than insertions",
					     dev, sizes[i]);
				}
				inserted += strtoul(l->word[1], NULL, 10);
				insertions++;
			}
			free(entries);

			if (inserted != sizes[i])
				fail("%s: write of %zu inserted %lu bytes", dev,
				     sizes[i], inserted);
			printf("%s: write of %zu: %lu insertions\n", dev,
			       sizes[i], insertions);
		}
		close(fd);
	}

	free(data);
	printf("write-notop ok\n");
}

static volatile sig_atomic_t alarm_came;

static void on_alarm(int sig)
{
	(void)sig;
	alarm_came = 1;
}

/*
 * addtoentcnt-signal <log>: against a notop fake-egd, which answers 0xe6 after
 * a second - a signal while the module waits for that answer must not have
 * the ioctl restarted, with the command carried out once more.
 */
static void cmd_addtoentcnt_signal(int argc, char *argv[])
{
	struct sigaction sa = {
		.sa_handler = on_alarm,
		/* the kernel restarts what returns ERESTARTSYS */
		.sa_flags = SA_RESTART
	};
	struct itimerval timer = { .it_value = { .tv_usec = 300000 } };
	const char *path = argv[0];
	struct fake_log_entry *entries;
	size_t before, n, i, credits = 0, credits_ok = 0;
	int fd, bits = 64, err;

	(void)argc;

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL))
		fail("sigaction: %s", strerror(errno));

	fd = open_or_fail(CDEV_RANDOM, O_RDWR);
	free(fake_log(path, &before));
	if (setitimer(ITIMER_REAL, &timer, NULL))
		fail("setitimer: %s", strerror(errno));
	err = rnd_ioctl(fd, RNDADDTOENTCNT, &bits);
	close(fd);
	if (err)
		fail("RNDADDTOENTCNT: %s", strerror(err));
	if (!alarm_came)
		fail("the signal did not come while the answer was due");

	entries = fake_log(path, &n);
	printf("RNDADDTOENTCNT with a signal:");
	for (i = before; i < n; i++) {
		if (strcmp(entries[i].word[0], "e6"))
			continue;
		fake_log_print(&entries[i]);
		credits++;
		credits_ok += fake_log_is(&entries[i], "e6", "64");
	}
	printf("\n");
	free(entries);

	if (credits != 1 || credits_ok != 1)
		fail("RNDADDTOENTCNT carried out %zu times", credits);

	printf("addtoentcnt-signal ok\n");
}

/*
 * poll() of /dev/esdm_random at @fd, at once: writable and not readable, as
 * random_poll() has the kernel's /dev/random before its RNG is initialized
 */
static void poll_writable_only(int fd, const char *when)
{
	static const short want = POLLOUT | POLLWRNORM;
	struct pollfd pfd = {
		.fd = fd, .events = POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM
	};
	int ret = poll(&pfd, 1, 0);

	if (ret < 0)
		fail("poll %s: %s", when, strerror(errno));
	if (pfd.revents != want)
		fail("poll %s: mask %#x, want %#x - writable, not readable",
		     when, (unsigned int)(unsigned short)pfd.revents,
		     (unsigned int)want);
}

/*
 * poll-notop: against a notop fake-egd - poll() of /dev/esdm_random reports
 * it readable only when a read with O_NONBLOCK gets data, that is not at all,
 * as an ESDM that is not operational serves nothing. Writable it is, before
 * and after.
 */
static void cmd_poll_notop(int argc, char *argv[])
{
	uint8_t data[64];
	unsigned int polls = 0;
	double end;
	ssize_t rc;
	int fd;

	(void)argc;
	(void)argv;

	fd = open_or_fail(CDEV_RANDOM, O_RDWR | O_NONBLOCK);
	poll_writable_only(fd, "before the reads");
	end = now() + 3;
	while (now() < end) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int ret;

		polls++;
		ret = poll(&pfd, 1, 200);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			fail("poll: %s", strerror(errno));
		}
		if (!ret)
			continue;

		rc = read(fd, data, sizeof(data));
		if (rc < 0 && errno == EAGAIN)
			fail("poll %u: readable, the read gives EAGAIN", polls);
		if (rc < 0)
			fail("poll %u: readable, the read: %s", polls,
			     strerror(errno));
		fail("poll %u: readable, an ESDM that is not operational served",
		     polls);
	}

	rc = read(fd, data, sizeof(data));
	if (rc >= 0)
		fail("an ESDM that is not operational served");
	if (errno != EAGAIN)
		fail("read: %s, want EAGAIN", strerror(errno));
	poll_writable_only(fd, "after the reads");
	close(fd);

	printf("poll-notop: %u polls, none readable, writable throughout\n",
	       polls);
	printf("poll-notop ok\n");
}

static volatile sig_atomic_t sig_restart_came, sig_intr_came;

static void on_sig_restart(int sig)
{
	(void)sig;
	sig_restart_came = 1;
}

static void on_sig_intr(int sig)
{
	(void)sig;
	sig_intr_came = 1;
}

/* The signals the thread of read_blocks() sends the reader */
struct signal_plan {
	pthread_t reader;
	/* Seconds after the start, restart_s 0 for none */
	double restart_s, intr_s;
};

static void *signal_sender(void *arg)
{
	const struct signal_plan *plan = arg;
	double start = now(), left;

	if (plan->restart_s > 0) {
		sleep_seconds(plan->restart_s);
		pthread_kill(plan->reader, SIGUSR1);
	}
	left = plan->intr_s - (now() - start);
	if (left > 0)
		sleep_seconds(left);
	pthread_kill(plan->reader, SIGALRM);

	return NULL;
}

/*
 * One read() of @dev opened with @flags, while signals come: SIGUSR1 after
 * @restart_s seconds, unless 0, with SA_RESTART, for which the kernel
 * restarts the read, and SIGALRM after @intr_s without, which ends it. The
 * read has to wait for an ESDM that cannot serve it: until the SIGALRM, then
 * failing with EINTR and no data - not ended by the SIGUSR1.
 */
static void read_blocks(const char *dev, int flags, const char *what,
			double restart_s, double intr_s)
{
	struct sigaction restart = { .sa_handler = on_sig_restart,
				     .sa_flags = SA_RESTART };
	struct sigaction intr = { .sa_handler = on_sig_intr };
	struct signal_plan plan = { .reader = pthread_self(),
				    .restart_s = restart_s,
				    .intr_s = intr_s };
	uint8_t buf[64], canary[64];
	pthread_t sender;
	double start, took;
	ssize_t rc;
	int fd, err;

	sigemptyset(&restart.sa_mask);
	sigemptyset(&intr.sa_mask);
	if (sigaction(SIGUSR1, &restart, NULL) ||
	    sigaction(SIGALRM, &intr, NULL))
		fail("sigaction: %s", strerror(errno));
	sig_restart_came = 0;
	sig_intr_came = 0;

	memset(canary, 0xa5, sizeof(canary));
	memcpy(buf, canary, sizeof(buf));
	fd = open_or_fail(dev, O_RDONLY | flags);

	start = now();
	if (pthread_create(&sender, NULL, signal_sender, &plan))
		fail("cannot start the thread sending the signals");
	rc = read(fd, buf, sizeof(buf));
	err = errno;
	took = now() - start;
	pthread_join(sender, NULL);
	close(fd);

	if (rc >= 0)
		fail("%s: %zd bytes served after %.2f s by an ESDM that cannot",
		     what, rc, took);
	if (err != EINTR)
		fail("%s: read gave %s after %.2f s, want EINTR", what,
		     strerror(err), took);
	if (!sig_intr_came || (restart_s > 0 && !sig_restart_came))
		fail("%s: the signals did not come", what);
	if (took < intr_s * 0.9)
		fail("%s: read ended after %.2f s, before the signal without SA_RESTART",
		     what, took);
	if (memcmp(buf, canary, sizeof(buf)))
		fail("%s: a read that failed left data behind", what);

	printf("%s: waited %.2f s for the signal without SA_RESTART%s\n", what,
	       took, restart_s > 0 ? ", restarted for the one with" : "");
}

/* A read with O_NONBLOCK and @flags of an ESDM that cannot serve: EAGAIN */
static void read_eagain(const char *dev, int flags, const char *what)
{
	int fd = open_or_fail(dev, O_RDONLY | O_NONBLOCK | flags);
	uint8_t buf[64];
	ssize_t rc = read(fd, buf, sizeof(buf));
	int err = errno;

	close(fd);
	if (rc >= 0)
		fail("%s O_NONBLOCK: %zd bytes served by an ESDM that cannot",
		     what, rc);
	if (err != EAGAIN)
		fail("%s O_NONBLOCK: read gave %s, want EAGAIN", what,
		     strerror(err));

	printf("%s O_NONBLOCK: EAGAIN\n", what);
}

/*
 * block-notop <log>: against a notop fake-egd - the reads of either device,
 * also with O_SYNC, wait for the ESDM to be operational. A signal with
 * SA_RESTART has such a read restarted, waiting on, one without ends it with
 * EINTR and no data. With O_NONBLOCK, they give EAGAIN. Each asks for the
 * read of its device, the prediction resistant one with O_SYNC - and O_DSYNC
 * alone is no O_SYNC.
 */
static void cmd_block_notop(int argc, char *argv[])
{
	static const struct {
		const char *dev;
		int flags;
		const char *what, *read;
	} waiting[] = {
		{ CDEV_RANDOM, 0, CDEV_RANDOM, "01" },
		{ CDEV_RANDOM, O_SYNC, CDEV_RANDOM " O_SYNC", "e0" },
		{ CDEV_URANDOM, 0, CDEV_URANDOM, "e2" },
		{ CDEV_URANDOM, O_SYNC, CDEV_URANDOM " O_SYNC", "e0" },
		{ CDEV_URANDOM, O_DSYNC, CDEV_URANDOM " O_DSYNC", "e2" },
	};
	const char *path = argv[0];
	size_t i;

	(void)argc;

	for (i = 0; i < ARRAY_SIZE(waiting); i++) {
		struct fake_log_entry *entries;
		size_t before, n, e, reads = 0;

		free(fake_log(path, &before));
		read_blocks(waiting[i].dev, waiting[i].flags, waiting[i].what,
			    0, 1);
		read_blocks(waiting[i].dev, waiting[i].flags, waiting[i].what,
			    0.5, 1.5);
		read_eagain(waiting[i].dev, waiting[i].flags, waiting[i].what);

		entries = fake_log(path, &n);
		for (e = before; e < n; e++) {
			if (strcmp(entries[e].word[0], "read"))
				continue;
			if (!fake_log_is(&entries[e], "read", waiting[i].read))
				fail("%s: asked with the read %s, want %s",
				     waiting[i].what, entries[e].word[1],
				     waiting[i].read);
			reads++;
		}
		free(entries);
		if (!reads)
			fail("%s: asked the ESDM nothing", waiting[i].what);
	}

	printf("block-notop ok\n");
}

/*
 * proc-notop: against a notop fake-egd - the files hold what the ESDM
 * reports: the state fake_egd_cmd() makes up, and its status reports of no
 * length.
 */
static void cmd_proc_notop(int argc, char *argv[])
{
	static const struct {
		const char *name, *want;
	} files[] = {
		{ "entropy_avail", "0\n" },
		{ "poolsize", "256\n" },
		{ "write_wakeup_threshold", "64\n" },
		{ "urandom_min_reseed_secs", "60\n" },
		{ "status", "" },
		{ "status.json", "" },
	};
	size_t i;

	(void)argc;
	(void)argv;

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		char *val = proc_read(files[i].name);

		if (strcmp(val, files[i].want))
			fail("%s: %s, want %s", files[i].name, quote(val),
			     quote(files[i].want));
		free(val);
	}

	printf("proc-notop ok\n");
}

/*
 * backoff <log> <seconds>: against a mute fake-egd - the reads fail, with
 * ETIMEDOUT once a connection is made, with ENOTCONN while the module waits
 * before it makes the next, up to 2 s.
 */
static void cmd_backoff(int argc, char *argv[])
{
	const char *path = argv[0];
	double seconds = parse_seconds(argv[1]), end;
	size_t before = fake_log_count(path, "connect"), connects;
	unsigned long timeouts = 0, refused = 0;
	uint8_t data[64];

	(void)argc;

	end = now() + seconds;
	while (now() < end) {
		int err = read_exact(CDEV_URANDOM, data, sizeof(data), 0);

		if (err == ETIMEDOUT)
			timeouts++;
		else if (err == ENOTCONN)
			refused++;
		else
			fail("%s: read: %s, want ETIMEDOUT or ENOTCONN",
			     CDEV_URANDOM, err ? strerror(err) : "served");
	}
	connects = fake_log_count(path, "connect") - before;

	printf("backoff: %lu timeouts, %lu reads backed off, %zu connects in %g s\n",
	       timeouts, refused, connects, seconds);
	/* Timeout and backoff from 50 ms to 2 s: about one connect per second */
	if ((double)connects > seconds * 1.5 + 2)
		fail("%zu connects to an ESDM that does not answer", connects);
	if (!timeouts || !refused)
		fail("no timeout or no backoff");

	printf("backoff ok\n");
}

/******************************************************************************
 * The ESDM unreachable
 ******************************************************************************/

/*
 * unreachable: with the ESDM not reachable, nothing is served from elsewhere.
 * /dev/esdm_urandom fails with ENOTCONN, as the module cannot connect, and
 * /dev/esdm_random waits - with O_NONBLOCK, EAGAIN - and is not readable for
 * poll(). Writes, the ioctls and the files of /proc/esdm fail with ENOTCONN.
 */
static void cmd_unreachable(int argc, char *argv[])
{
	static const int flags[] = { 0, O_SYNC, O_NONBLOCK };
	uint8_t data[64];
	unsigned int d;
	size_t i;
	char *val;
	int fd, err, cnt;

	(void)argc;
	(void)argv;

	for (i = 0; i < ARRAY_SIZE(flags); i++) {
		err = read_exact(CDEV_URANDOM, data, sizeof(data), flags[i]);
		if (err != ENOTCONN)
			fail("%s with flags %#x: read gave %s, want ENOTCONN",
			     CDEV_URANDOM, (unsigned int)flags[i],
			     err ? strerror(err) : "data");
	}

	read_eagain(CDEV_RANDOM, 0, CDEV_RANDOM);
	read_blocks(CDEV_RANDOM, 0, CDEV_RANDOM, 0, 1);
	fd = open_or_fail(CDEV_RANDOM, O_RDWR);
	poll_writable_only(fd, "with the ESDM unreachable");
	close(fd);

	for (d = 0; d < CDEV_NUM_DEVS; d++) {
		const char *dev = cdev_devs[d];

		fd = open_or_fail(dev, O_RDWR);
		err = write(fd, data, sizeof(data)) < 0 ? errno : 0;
		if (err != ENOTCONN)
			fail("%s: write gave %s, want ENOTCONN", dev,
			     err ? strerror(err) : "success");
		err = rnd_ioctl(fd, RNDGETENTCNT, &cnt);
		if (err != ENOTCONN)
			fail("%s: RNDGETENTCNT gave errno %d, want ENOTCONN",
			     dev, err);
		err = rnd_ioctl(fd, RNDCLEARPOOL, NULL);
		if (err != ENOTCONN)
			fail("%s: RNDCLEARPOOL gave errno %d, want ENOTCONN",
			     dev, err);
		close(fd);
	}

	for (i = 0; i < ARRAY_SIZE(proc_files); i++) {
		char path[128];

		snprintf(path, sizeof(path), CDEV_PROC "/%s", proc_files[i]);
		val = read_file(path);
		if (val || errno != ENOTCONN)
			fail("%s: %s, want ENOTCONN", path,
			     val ? quote(val) : strerror(errno));
	}

	printf("unreachable ok\n");
}

/******************************************************************************
 * Dispatch
 ******************************************************************************/

/* What a check needs, or it skips */
#define NEED_MODULE (1U << 0)
#define NEED_CAP_SYS_ADMIN (1U << 1)

static const struct check {
	const char *name;
	const char *usage;
	int min_args, max_args;
	unsigned int needs;
	void (*fn)(int argc, char *argv[]);
} checks[] = {
	{ "reads", "[sync]", 0, 1, NEED_MODULE, cmd_reads },
	{ "nonblock", "", 0, 0, NEED_MODULE, cmd_nonblock },
	{ "poll", "", 0, 0, NEED_MODULE, cmd_poll },
	{ "writes", "", 0, 0, NEED_MODULE, cmd_writes },
	{ "ioctl-priv", "", 0, 0, NEED_MODULE | NEED_CAP_SYS_ADMIN,
	  cmd_ioctl_priv },
	{ "ioctl-unpriv", "", 0, 0, NEED_MODULE, cmd_ioctl_unpriv },
	{ "proc", "", 0, 0, NEED_MODULE | NEED_CAP_SYS_ADMIN, cmd_proc },
	{ "loop", "<dev> <seconds>", 2, 2, NEED_MODULE, cmd_loop },
	{ "block", "<dev>", 1, 1, NEED_MODULE, cmd_block },
	{ "throughput", "[egd socket]", 0, 1, NEED_MODULE, cmd_throughput },
	{ "stalled-writers", "", 0, 0, NEED_MODULE, cmd_stalled_writers },
	{ "fake-egd", "<socket> <log> <notop|mute>", 3, 3, 0, cmd_fake_egd },
	{ "addentropy", "<log>", 1, 1, NEED_MODULE | NEED_CAP_SYS_ADMIN,
	  cmd_addentropy },
	{ "write-notop", "<log>", 1, 1, NEED_MODULE, cmd_write_notop },
	{ "addtoentcnt-signal", "<log>", 1, 1, NEED_MODULE | NEED_CAP_SYS_ADMIN,
	  cmd_addtoentcnt_signal },
	{ "poll-notop", "", 0, 0, NEED_MODULE, cmd_poll_notop },
	{ "block-notop", "<log>", 1, 1, NEED_MODULE, cmd_block_notop },
	{ "proc-notop", "", 0, 0, NEED_MODULE, cmd_proc_notop },
	{ "backoff", "<log> <seconds>", 2, 2, NEED_MODULE, cmd_backoff },
	{ "unreachable", "", 0, 0, NEED_MODULE, cmd_unreachable },
};

static void __attribute__((noreturn)) usage(const char *prog)
{
	size_t i;

	fprintf(stderr, "usage: %s <check> [args]\n", prog);
	for (i = 0; i < ARRAY_SIZE(checks); i++)
		fprintf(stderr, "\t%s%s%s\n", checks[i].name,
			*checks[i].usage ? " " : "", checks[i].usage);

	exit(2);
}

int main(int argc, char *argv[])
{
	const struct check *check = NULL;
	size_t i;

	/* The VM test waits for lines in the logs of checks it runs behind */
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (argc < 2)
		usage(argv[0]);
	for (i = 0; i < ARRAY_SIZE(checks); i++) {
		if (!strcmp(argv[1], checks[i].name))
			check = &checks[i];
	}
	if (!check || argc - 2 < check->min_args || argc - 2 > check->max_args)
		usage(argv[0]);

	if (check->needs & NEED_MODULE)
		need_module();
	if (check->needs & NEED_CAP_SYS_ADMIN)
		need_cap_sys_admin();

	check->fn(argc - 2, argv + 2);

	return 0;
}
