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
 * Tests for the CUSE device handlers.
 *
 * The tests next to this one bring up the real /dev/random and /dev/urandom
 * frontends, which needs root, /dev/fuse and a running ESDM - so they cover
 * what the handlers do when everything is in place, and nothing else. What is
 * left over is the larger part of every handler: the request that arrives
 * malformed, the caller that is not allowed to make it, and the ESDM that does
 * not answer.
 *
 * All of it is decided inside the handlers, which are ordinary functions of a
 * request and its arguments - so the translation unit is compiled into the test
 * and they are called directly. What a handler "returns" is the reply it sends,
 * so the libfuse reply functions are provided here and record it; that is also
 * what makes the caller's identity controllable, since fuse_req_ctx() is one of
 * them and the privilege decisions are made from its uid.
 *
 * The ESDM is deliberately absent. Every RPC below therefore fails, which is
 * the only way to reach the fallback to the kernel device that keeps
 * /dev/random working when the daemon is not running.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common_test.h"

/* The unit under test */
#include "cuse_device.c"

/*
 * What the last handler call replied. Exactly one of these is sent per
 * request, which is what the reply stubs below record.
 */
enum reply_kind {
	REPLY_NONE,
	REPLY_ERR,
	REPLY_IOCTL,
	REPLY_IOCTL_RETRY,
	REPLY_BUF,
	REPLY_WRITE,
	REPLY_OPEN,
	REPLY_POLL,
};

static struct {
	enum reply_kind kind;
	int err;
	size_t size;
	unsigned int revents;
	uint8_t buf[4096];
} reply;

/* The caller every handler below sees */
static struct fuse_ctx test_ctx;

static unsigned int notify_calls;
static unsigned int destroy_calls;
static unsigned int raise_calls;
static unsigned int drop_calls;

static void reply_reset(void)
{
	memset(&reply, 0, sizeof(reply));
	notify_calls = 0;
	destroy_calls = 0;
	raise_calls = 0;
	drop_calls = 0;
}

/******************************************************************************
 * The libfuse side, replaced so a handler can be called without a session
 ******************************************************************************/

int fuse_reply_err(fuse_req_t req, int err)
{
	(void)req;
	reply.kind = REPLY_ERR;
	reply.err = err;

	return 0;
}

int fuse_reply_ioctl(fuse_req_t req, int result, const void *buf, size_t size)
{
	(void)req;
	reply.kind = REPLY_IOCTL;
	reply.err = result;
	reply.size = size;
	if (buf && size <= sizeof(reply.buf))
		memcpy(reply.buf, buf, size);

	return 0;
}

int fuse_reply_ioctl_retry(fuse_req_t req, const struct iovec *in_iov,
			   size_t in_count, const struct iovec *out_iov,
			   size_t out_count)
{
	(void)req;
	(void)in_iov;
	(void)out_iov;
	reply.kind = REPLY_IOCTL_RETRY;
	reply.size = in_count + out_count;

	return 0;
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
	(void)req;
	reply.kind = REPLY_BUF;
	reply.size = size;
	if (buf && size <= sizeof(reply.buf))
		memcpy(reply.buf, buf, size);

	return 0;
}

int fuse_reply_write(fuse_req_t req, size_t count)
{
	(void)req;
	reply.kind = REPLY_WRITE;
	reply.size = count;

	return 0;
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *fi)
{
	(void)req;
	(void)fi;
	reply.kind = REPLY_OPEN;

	return 0;
}

int fuse_reply_poll(fuse_req_t req, unsigned revents)
{
	(void)req;
	reply.kind = REPLY_POLL;
	reply.revents = revents;

	return 0;
}

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req)
{
	(void)req;

	return &test_ctx;
}

int fuse_req_interrupted(fuse_req_t req)
{
	(void)req;

	return 0;
}

int fuse_notify_poll(struct fuse_pollhandle *ph)
{
	(void)ph;
	notify_calls++;

	return 0;
}

void fuse_pollhandle_destroy(struct fuse_pollhandle *ph)
{
	(void)ph;
	destroy_calls++;
}

void fuse_session_exit(struct fuse_session *se)
{
	(void)se;
}

/******************************************************************************
 * The privilege helpers, replaced so the handlers can be driven in process
 *
 * The privileged ioctls raise to root around the request and drop to "nobody"
 * afterwards. Performing that here would leave the rest of the test - and, in a
 * root run, everything the harness does with the process afterwards - running
 * as nobody, and what is under test is the handler's decision rather than the
 * credential syscalls (frontends/cuse/privileges.c is covered by tests/proc).
 * Counting the calls instead also makes the pairing checkable: a raise without
 * its drop would leave a real daemon running as root.
 ******************************************************************************/

int raise_privilege_transient(uid_t uid, gid_t gid)
{
	(void)uid;
	(void)gid;
	raise_calls++;

	return 0;
}

int drop_privileges_transient(const char *user)
{
	(void)user;
	drop_calls++;

	return 0;
}

int drop_supplemental_groups(void)
{
	return 0;
}

/******************************************************************************
 * The device helpers of cuse_helper.c
 *
 * Reached only from main_common(), esdm_cuse_init_done() and esdm_cuse_term(),
 * none of which this test drives - it calls the handlers directly. Left
 * undefined they are still references of the translation unit, and whether the
 * link succeeds then comes down to whether the linker manages to drop the
 * functions holding them: with -ffunction-sections and --gc-sections it does,
 * under LTO, where they end up in one merged .text, it does not.
 *
 * Stubbed rather than linked from cuse_helper.c, which mounts and consults the
 * SELinux policy - neither of which belongs in a test that needs neither root
 * nor /dev/fuse.
 ******************************************************************************/

int esdm_cuse_file_name(char *outfile, size_t outfilelen, const char *name)
{
	snprintf(outfile, outfilelen, "tst-%s", name);

	return 0;
}

int esdm_cuse_bind_mount(const char *mount_src, const char *mount_dst)
{
	(void)mount_src;
	(void)mount_dst;

	return 0;
}

int esdm_cuse_bind_unmount(char **mount_src, char **mount_dst)
{
	(void)mount_src;
	(void)mount_dst;

	return 0;
}

/* Any pointer will do - the handlers only hand it back to the stubs above */
#define TEST_REQ ((fuse_req_t)&reply)
#define TEST_PH ((struct fuse_pollhandle *)&notify_calls)

/* The caller of the requests that follow */
static void caller_is_root(bool root)
{
	memset(&test_ctx, 0, sizeof(test_ctx));
	test_ctx.uid = root ? 0 : 1000;
	test_ctx.gid = root ? 0 : 1000;
	test_ctx.pid = getpid();
}

static void ioctl_call(unsigned long cmd, const void *in_buf, size_t in_bufsz,
		       size_t out_bufsz, int backend_fd)
{
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_ioctl(backend_fd, TEST_REQ, cmd, (void *)0x1000, &fi, 0,
			in_buf, in_bufsz, out_bufsz);
}

static void test_open(void)
{
	struct fuse_file_info fi;
	uint64_t first;

	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_open(TEST_REQ, &fi);
	CHECK_EQ(reply.kind, REPLY_OPEN);
	CHECK(fi.fh != 0, "the opened file got no handle");
	first = fi.fh;

	/*
	 * Every open gets a handle of its own: the poll registrations are keyed
	 * by it, so two descriptors sharing one would be woken for each other.
	 */
	esdm_cuse_open(TEST_REQ, &fi);
	CHECK(fi.fh != first, "two opens got the same file handle");
}

/*
 * A 32 bit ioctl into a 64 bit daemon. The structures do not match, so the
 * request is refused rather than misread.
 */
static void test_ioctl_compat(void)
{
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_ioctl(-1, TEST_REQ, RNDGETENTCNT, (void *)0x1000, &fi,
			FUSE_IOCTL_COMPAT, NULL, 0, 0);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, ENOSYS);
}

/*
 * Every ioctl that carries data is answered twice: once to tell the kernel how
 * much to transfer, and once with the result. The first answer is what the
 * handler produces when the buffer has not been transferred yet.
 */
static void test_ioctl_retries(void)
{
	struct rand_pool_info rpi;

	/* Reading the entropy count: nothing to transfer out yet */
	ioctl_call(RNDGETENTCNT, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_IOCTL_RETRY);

	/* Adding to it: nothing transferred in yet */
	ioctl_call(RNDADDTOENTCNT, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_IOCTL_RETRY);

	/* Adding entropy: the header has not arrived yet */
	ioctl_call(RNDADDENTROPY, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_IOCTL_RETRY);

	/*
	 * The header has arrived and says how much data follows, so the next
	 * transfer has to be asked for with that size.
	 */
	memset(&rpi, 0, sizeof(rpi));
	rpi.buf_size = 32;
	rpi.entropy_count = 8;
	ioctl_call(RNDADDENTROPY, &rpi, sizeof(rpi), 0, -1);
	CHECK_EQ(reply.kind, REPLY_IOCTL_RETRY);
}

/*
 * What the kernel's own RNDADDENTROPY rejects, this one has to reject as well:
 * a negative buffer size, and a claim of more entropy than the buffer can hold.
 * A caller getting either past this check would move the ESDM's entropy
 * estimate with data that does not carry the entropy.
 */
static void test_ioctl_addentropy_rejected(void)
{
	/*
	 * The kernel structure ends in a flexible array, so the request is
	 * built in a buffer sized for it plus its payload rather than by
	 * embedding it in another structure.
	 */
	uint8_t raw[sizeof(struct rand_pool_info) + 32] = { 0 };
	struct rand_pool_info *rpi = (struct rand_pool_info *)raw;
	const size_t datalen = 32;

	rpi->buf_size = -1;
	rpi->entropy_count = 8;
	ioctl_call(RNDADDENTROPY, raw, sizeof(raw), 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EINVAL);

	rpi->buf_size = (int)datalen;
	rpi->entropy_count = -1;
	ioctl_call(RNDADDENTROPY, raw, sizeof(raw), 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EINVAL);

	/* More bits than the buffer holds */
	rpi->buf_size = (int)datalen;
	rpi->entropy_count = (int)datalen * 8 + 1;
	ioctl_call(RNDADDENTROPY, raw, sizeof(raw), 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EINVAL);
}

/*
 * The commands that change the ESDM's state are for root. This is the check
 * that stands between any user of /dev/random and the entropy accounting, so
 * each command is asked for as an ordinary user and has to be refused.
 */
static void test_ioctl_privileged_refused(void)
{
	/*
	 * The kernel structure ends in a flexible array, so the request is
	 * built in a buffer sized for it plus its payload rather than by
	 * embedding it in another structure.
	 */
	uint8_t raw[sizeof(struct rand_pool_info) + 32] = { 0 };
	struct rand_pool_info *rpi = (struct rand_pool_info *)raw;
	const size_t datalen = 32;
	uint32_t bits = 8;

	caller_is_root(false);

	rpi->buf_size = (int)datalen;
	rpi->entropy_count = 8;

	ioctl_call(RNDADDTOENTCNT, &bits, sizeof(bits), 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EPERM);

	ioctl_call(RNDADDENTROPY, raw, sizeof(raw), 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EPERM);

	ioctl_call(RNDCLEARPOOL, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EPERM);

	ioctl_call(RNDZAPENTCNT, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EPERM);

	ioctl_call(RNDRESEEDCRNG, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EPERM);

	/* The two ESDM specific ones that reach the kernel directly */
	ioctl_call(43, raw, sizeof(raw), 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EPERM);

	ioctl_call(44, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EPERM);
}

/*
 * The ESDM specific status ioctl before the status segment is attached, and a
 * command that is none of the above.
 */
static void test_ioctl_status_and_unknown(void)
{
	CHECK(esdm_cuse_shm_status == NULL,
	      "the status segment is attached, which this test does not expect");

	ioctl_call(42, NULL, 0, 4096, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EAGAIN);

	ioctl_call(0xdead, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EINVAL);
}

/*
 * Reading with no ESDM to ask. The fallback descriptor is what a running
 * /dev/random has for exactly this case, and the request has to be served from
 * it rather than failing - that is what keeps the device working while the
 * daemon is down.
 */
static void test_read_fallback(void)
{
	struct fuse_file_info fi;
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		CHECK(0, "cannot open /dev/urandom: %s", strerror(errno));
		return;
	}

	/* Small enough for the on-stack buffer */
	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_read_internal(TEST_REQ, 32, 0, &fi,
				esdm_rpcc_get_random_bytes_full_int, fd);
	CHECK_EQ(reply.kind, REPLY_BUF);
	CHECK_EQ(reply.size, 32);

	/* Larger than it, so the heap path is taken */
	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_read_internal(TEST_REQ, 1024, 0, &fi,
				esdm_rpcc_get_random_bytes_full_int, fd);
	CHECK_EQ(reply.kind, REPLY_BUF);
	CHECK_EQ(reply.size, 1024);

	/*
	 * O_SYNC asks for prediction resistance, which the fallback cannot
	 * provide either - but the request is still served from it.
	 */
	memset(&fi, 0, sizeof(fi));
	fi.flags = O_SYNC;
	reply_reset();
	esdm_cuse_read_internal(TEST_REQ, 32, 0, &fi,
				esdm_rpcc_get_random_bytes_full_int, fd);
	CHECK_EQ(reply.kind, REPLY_BUF);

	/* With neither an ESDM nor a fallback there is nothing to serve */
	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_read_internal(TEST_REQ, 32, 0, &fi,
				esdm_rpcc_get_random_bytes_full_int, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK(reply.err != 0, "a read with nothing behind it reported success");

	close(fd);
}

/*
 * Writing with no ESDM to take the data. It goes to the fallback whole or not
 * at all - a write split between the ESDM and the kernel would leave neither
 * with what the caller sent.
 */
static void test_write_fallback(void)
{
	char path[] = "/tmp/esdm-cuse-write-XXXXXX";
	uint8_t buf[128];
	struct fuse_file_info fi;
	struct stat sb;
	int fd = mkstemp(path);

	if (fd < 0) {
		CHECK(0, "cannot create a temporary file: %s", strerror(errno));
		return;
	}
	unlink(path);
	memset(buf, 0x5a, sizeof(buf));

	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_write_internal(TEST_REQ, (const char *)buf, sizeof(buf), 0,
				 &fi, fd);
	CHECK_EQ(reply.kind, REPLY_WRITE);
	CHECK_EQ(reply.size, sizeof(buf));
	CHECK(!fstat(fd, &sb) && sb.st_size == (off_t)sizeof(buf),
	      "the fallback did not receive the whole write");

	/* Nothing to write is a successful write of nothing */
	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_write_internal(TEST_REQ, (const char *)buf, 0, 0, &fi, fd);
	CHECK_EQ(reply.kind, REPLY_WRITE);
	CHECK_EQ(reply.size, 0);

	/* And with nowhere to put it, the caller is told */
	memset(&fi, 0, sizeof(fi));
	reply_reset();
	esdm_cuse_write_internal(TEST_REQ, (const char *)buf, sizeof(buf), 0,
				 &fi, -1);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK(reply.err != 0, "a write with nothing behind it reported success");

	close(fd);
}

/*
 * poll() with no status segment attached: nothing can be reported as ready, so
 * the handle is registered and the caller waits. Closing the descriptor has to
 * take the registration with it - a stale one would later be notified through
 * a handle that no longer exists.
 */
static void test_poll_registration(void)
{
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = 4711;

	/* A poll for nothing cannot be answered */
	reply_reset();
	fi.poll_events = 0;
	esdm_cuse_poll(TEST_REQ, &fi, TEST_PH);
	CHECK_EQ(reply.kind, REPLY_ERR);
	CHECK_EQ(reply.err, EINVAL);

	reply_reset();
	fi.poll_events = POLLIN;
	esdm_cuse_poll(TEST_REQ, &fi, TEST_PH);
	CHECK_EQ(reply.kind, REPLY_POLL);
	CHECK_EQ(reply.revents, 0);
	CHECK(esdm_cuse_poll_list != NULL,
	      "the poll handle was not registered");
	CHECK_EQ(destroy_calls, 0);

	/*
	 * A second poll on the same descriptor replaces the first
	 * registration rather than adding to it.
	 */
	reply_reset();
	esdm_cuse_poll(TEST_REQ, &fi, TEST_PH);
	CHECK_EQ(destroy_calls, 1);
	CHECK(esdm_cuse_poll_list && !esdm_cuse_poll_list->next,
	      "the stale registration was kept alongside the new one");

	/* The release takes it with it */
	reply_reset();
	esdm_cuse_release(TEST_REQ, &fi);
	CHECK(esdm_cuse_poll_list == NULL,
	      "closing the descriptor left its poll registration behind");
	CHECK_EQ(destroy_calls, 1);
}

/*
 * The mask a poller is answered with. Without a status segment nothing is
 * ready, and what is ready is filtered by what the caller asked for - a poller
 * waiting to write must not be woken because reading became possible.
 */
static void test_pollmask(void)
{
	unsigned int mask = 0xffffffff;

	esdm_cuse_get_pollmask(&mask);
	CHECK_EQ(mask, 0);

	mask = POLLIN | POLLOUT;
	esdm_cuse_set_pollmask(POLLIN, &mask);
	CHECK_EQ(mask, POLLIN);
}

/*
 * The privileged half of the ioctl handler. With no ESDM answering, each of
 * these falls back to the kernel device, which is the path a privileged ioctl
 * takes while the daemon is down - and every one of them has to leave the
 * privilege level where it found it.
 */
static void test_privileged_ioctls(void)
{
	/*
	 * The kernel structure ends in a flexible array, so the request is
	 * built in a buffer sized for it plus its payload rather than by
	 * embedding it in another structure.
	 */
	uint8_t raw[sizeof(struct rand_pool_info) + 32] = { 0 };
	struct rand_pool_info *rpi = (struct rand_pool_info *)raw;
	const size_t datalen = 32;
	uint32_t bits = 8;
	int fd = open("/dev/random", O_RDONLY | O_CLOEXEC);

	caller_is_root(true);

	rpi->buf_size = (int)datalen;
	rpi->entropy_count = 8;

	/*
	 * What the kernel makes of the fallback ioctl depends on who runs the
	 * test - an unprivileged one does not get to perform it, a root one
	 * does. Either way the request is answered rather than left hanging,
	 * and the privilege level is put back.
	 */
	ioctl_call(RNDADDTOENTCNT, &bits, sizeof(bits), 0, fd);
	CHECK(reply.kind == REPLY_ERR || reply.kind == REPLY_IOCTL,
	      "RNDADDTOENTCNT was not answered");
	CHECK_EQ(raise_calls, 1);
	CHECK_EQ(drop_calls, 1);

	ioctl_call(RNDADDENTROPY, raw, sizeof(raw), 0, fd);
	CHECK(reply.kind == REPLY_ERR || reply.kind == REPLY_IOCTL,
	      "RNDADDENTROPY was not answered");
	CHECK_EQ(raise_calls, 1);
	CHECK_EQ(drop_calls, 1);

	ioctl_call(RNDCLEARPOOL, NULL, 0, 0, fd);
	CHECK(reply.kind == REPLY_ERR || reply.kind == REPLY_IOCTL,
	      "RNDCLEARPOOL was not answered");
	CHECK_EQ(raise_calls, 1);
	CHECK_EQ(drop_calls, 1);

	ioctl_call(RNDZAPENTCNT, NULL, 0, 0, fd);
	CHECK(reply.kind == REPLY_ERR || reply.kind == REPLY_IOCTL,
	      "RNDZAPENTCNT was not answered");

	ioctl_call(RNDRESEEDCRNG, NULL, 0, 0, fd);
	CHECK(reply.kind == REPLY_ERR || reply.kind == REPLY_IOCTL,
	      "RNDRESEEDCRNG was not answered");
	CHECK_EQ(raise_calls, 1);
	CHECK_EQ(drop_calls, 1);

	/* The two that go to the kernel without asking the ESDM at all */
	ioctl_call(43, raw, sizeof(raw), 0, fd);
	CHECK(reply.kind == REPLY_ERR || reply.kind == REPLY_IOCTL,
	      "the direct kernel entropy insertion was not answered");
	CHECK_EQ(raise_calls, 1);
	CHECK_EQ(drop_calls, 1);

	ioctl_call(44, NULL, 0, 0, fd);
	CHECK(reply.kind == REPLY_ERR || reply.kind == REPLY_IOCTL,
	      "the direct kernel CRNG reseed was not answered");
	CHECK_EQ(raise_calls, 1);
	CHECK_EQ(drop_calls, 1);

	/* And with no kernel device either, the answer is still an answer */
	ioctl_call(RNDRESEEDCRNG, NULL, 0, 0, -1);
	CHECK(reply.kind == REPLY_ERR || reply.kind == REPLY_IOCTL,
	      "RNDRESEEDCRNG without a fallback was not answered");

	if (fd >= 0)
		close(fd);

	caller_is_root(false);
}

/*
 * The status segment and the semaphore that go with it.
 *
 * Both are machine-global names, so this test has an IPC namespace of its own
 * (see tests/test_ipc_ns.c) and creates them there. What matters about the
 * attach is that a segment nobody is attached to any more is treated as a
 * leftover and replaced rather than trusted: it is what a crashed server leaves
 * behind, and its contents would otherwise be reported as the current state.
 */
static void test_shm_status(void)
{
	unsigned int mask;

	CHECK_EQ(esdm_cuse_shm_status_create_shm(), 0);
	CHECK(esdm_cuse_shm_status != NULL,
	      "the status segment was not attached");

	/* A segment without the version this build speaks is not usable */
	CHECK_EQ(esdm_cuse_shm_status_avail(), 0);
	esdm_cuse_shm_status->version = ESDM_SHM_STATUS_VERSION;
	CHECK(esdm_cuse_shm_status_avail() != 0,
	      "an attached status segment is not reported as available");

	/* Detaching and attaching again finds it as the leftover it now is */
	esdm_cuse_shm_status_close_shm();
	CHECK(esdm_cuse_shm_status == NULL,
	      "the status segment was not detached");
	CHECK_EQ(esdm_cuse_shm_status_create_shm(), 0);
	CHECK(esdm_cuse_shm_status != NULL,
	      "the status segment was not attached again");
	CHECK_EQ(esdm_cuse_shm_status->version, 0);

	/* A fresh segment, so the version has to be put back into it */
	esdm_cuse_shm_status->version = ESDM_SHM_STATUS_VERSION;

	/*
	 * With a segment in place the poll mask follows what it says. Each
	 * flag wakes a different waiter, and the shutdown one wakes both -
	 * a poller must not be left waiting on a device that is going away.
	 */
	atomic_store(&esdm_cuse_shm_status->operational, true);
	esdm_cuse_get_pollmask(&mask);
	CHECK_EQ(mask, POLLIN | POLLRDNORM);

	atomic_store(&esdm_cuse_shm_status->operational, false);
	atomic_store(&esdm_cuse_shm_status->need_entropy, true);
	esdm_cuse_get_pollmask(&mask);
	CHECK_EQ(mask, POLLOUT | POLLWRNORM);

	atomic_store(&esdm_cuse_shm_status->need_entropy, false);
	atomic_store(&esdm_cuse_shm_status->suspend_trigger, true);
	esdm_cuse_get_pollmask(&mask);
	CHECK_EQ(mask, POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM);
	atomic_store(&esdm_cuse_shm_status->suspend_trigger, false);

	/* The status ioctl answers out of the same segment */
	esdm_cuse_shm_status->infolen = 5;
	memcpy(esdm_cuse_shm_status->info, "ESDM", 5);

	ioctl_call(42, NULL, 0, 0, -1);
	CHECK_EQ(reply.kind, REPLY_IOCTL_RETRY);

	ioctl_call(42, NULL, 0, sizeof(reply.buf), -1);
	CHECK_EQ(reply.kind, REPLY_IOCTL);
	CHECK_EQ(reply.size, 5);
	CHECK_STR_EQ((const char *)reply.buf, "ESDM");

	/*
	 * A length beyond the segment is clamped rather than read past - the
	 * segment is written by another process, so its length is not to be
	 * trusted.
	 */
	esdm_cuse_shm_status->infolen = ESDM_SHM_STATUS_INFO_SIZE * 2;
	ioctl_call(42, NULL, 0, sizeof(reply.buf), -1);
	CHECK(reply.kind == REPLY_IOCTL &&
		      reply.size == ESDM_SHM_STATUS_INFO_SIZE,
	      "an oversized info length was not clamped to the segment");

	/* Waiting on a semaphore that was never created says so and returns */
	CHECK_EQ(esdm_cuse_semid, SEM_FAILED);
	esdm_cuse_shm_status_down();

	/* The name is what the frontend passes in; without one there is none */
	CHECK_EQ(esdm_cuse_shm_status_create_sem(), -EFAULT);

	esdm_sem_name = "/esdm-cuse-device-test";
	CHECK_EQ(esdm_cuse_shm_status_create_sem(), 0);
	CHECK(esdm_cuse_semid != SEM_FAILED,
	      "the semaphore was not created");

	/* Opening the one that is already there is the other startup order */
	esdm_cuse_shm_status_close_sem();
	CHECK_EQ(esdm_cuse_shm_status_create_sem(), 0);

	/*
	 * The wait returns without blocking once the shutdown flag is set,
	 * which is how the poll checker is let go when the device stops.
	 */
	atomic_store(&esdm_cuse_poll_thread_shutdown, true);
	esdm_cuse_shm_status_down();
	atomic_store(&esdm_cuse_poll_thread_shutdown, false);

	esdm_cuse_shm_status_close_sem();
	sem_unlink(esdm_sem_name);
	CHECK_EQ(esdm_cuse_semid, SEM_FAILED);
	esdm_cuse_shm_status_close_sem();

	esdm_cuse_shm_status_close_shm();
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	caller_is_root(false);

	test_open();
	test_ioctl_compat();
	test_ioctl_retries();
	test_ioctl_addentropy_rejected();
	test_ioctl_privileged_refused();
	test_ioctl_status_and_unknown();
	test_read_fallback();
	test_write_fallback();
	test_poll_registration();
	test_pollmask();
	test_privileged_ioctls();
	test_shm_status();

	return common_test_result("cuse_device");
}
