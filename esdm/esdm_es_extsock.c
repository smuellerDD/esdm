/*
 * ESDM External Entropy Source: provider process connected over a Unix socket
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
 * An external entropy source served by a provider process - see the protocol
 * in esdm_es_ext.h.
 *
 * One connection, one request at a time under the mutex. Anything going
 * wrong on it - an error, no answer in time, an answer breaking the protocol
 * - closes it, as a late answer would be taken for the next one. It is made
 * again on demand, at most every ESDM_EXT_RETRY_INTERVAL_SEC after a failure,
 * and starts with INFO and a self test: the provider may be another process
 * than the one tested before, restarted with its noise source set up anew.
 *
 * Whoever can create the socket file could feed the ESDM data credited as
 * entropy, so the provider has to run as root or as the uid accepted. A block
 * is credited with its claim, at most at the rate of extsock_rate(). A
 * provider failing a request is credited with nothing until it delivers again
 * - the ES monitor probes it meanwhile - and one failing its self test until
 * it passes one, periodically or on a new connection.
 *
 * Connecting and probing are left to the ES monitor: a seeding holds the DRNG
 * lock, and asks a credited connection only.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_ext_json.h"
#include "esdm_es_extsock.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"
#include "mutex.h"
#include "visibility.h"

#define EXTSOCK_NAME "ExternalSocket"
#define EXTSOCK_NSEC 1000000000ULL

/* Why connecting failed, see extsock_log_once() */
enum extsock_event {
	EXTSOCK_LOGGED_NONE,
	EXTSOCK_UNREACHABLE,
	EXTSOCK_REFUSED,
	EXTSOCK_NO_INFO,
};

static struct {
	/* Held for every request, and by the ESDM status */
	mutex_t mutex;

	/* --es_ext, NULL for the build default; configuration kept by fini */
	char *path;
	int64_t peer_uid;

	int fd;
	uid_t uid;
	/*
	 * What the provider declared, empty and NONE for nothing - kept once it
	 * is gone, so that the status still names it
	 */
	char name[ESDM_ES_EXT_NAME_MAX + 1];
	uint32_t rate;

	/*
	 * Only data delivered clears a failed request, only a self test passed
	 * a failed self test; a new connection is due one before data.
	 */
	bool read_failed;
	bool selftest_failed;
	bool selftest_due;

	/* Monotonic ns: earliest connection attempt, and probe of a failure */
	uint64_t retry_at;
	uint64_t probe_at;
	bool was_connected;
	/* Not to log the same failure to connect on every attempt */
	enum extsock_event last_logged;

	/* The status of the provider, NULL for none, and when it was asked */
	struct json_object *status;
	uint64_t status_at;
	bool status_warned;

	/* The last message received and its decoding, wiped after use */
	uint8_t msg[ESDM_ES_EXT_PROTO_MSG_MAX];
	struct esdm_es_ext_proto_rsp rsp;

	/* For the ES manager, which is not to wait for a request in progress */
	atomic_bool configured;
	atomic_bool credited;
	atomic_uint published_rate;

#if (ESDM_EXT_ENTROPY_BLOCKS != 0)
	/* Filled by the ES monitor: a slow provider holds up no reseed */
	struct esdm_es_buf buf;
	bool buf_alloced;
#endif
} extsock = {
	.mutex = MUTEX_UNLOCKED,
	.peer_uid = ESDM_EXT_PEER_UID,
	.fd = -1,
	.rate = ESDM_ES_EXT_PROTO_RATE_NONE,
	.published_rate = ESDM_ES_EXT_PROTO_RATE_NONE,
};

/* Logs naming the provider by the name it declared */
#define extsock_log(level, fmt, ...)                                           \
	esdm_logger(level, LOGGER_C_ES, "External ES provider%s%s%s: " fmt,    \
		    extsock.name[0] ? " (" : "", extsock.name,                 \
		    extsock.name[0] ? ")" : "", ##__VA_ARGS__)

static uint64_t extsock_retry_time(void)
{
	return esdm_monotonic_now_ns() +
	       ESDM_EXT_RETRY_INTERVAL_SEC * EXTSOCK_NSEC;
}

static const char *extsock_path(void)
{
	return extsock.path ? extsock.path : ESDM_EXT_PATH;
}

static bool extsock_credited(void)
{
	return extsock.fd >= 0 && !extsock.read_failed &&
	       !extsock.selftest_failed && !extsock.selftest_due;
}

/*
 * The rate configured, else the one @declared, else 0. Accepting the user a
 * provider runs as means trusting the rate it declares - an operator who does
 * not want that configures one.
 */
static uint32_t extsock_rate(uint32_t declared, const char **source)
{
	uint32_t rate = esdm_config_es_ext_entropy_rate();
	const char *from = "config";

	if (rate == ESDM_ES_EXT_ENTROPY_RATE_AUTO) {
		from = declared != ESDM_ES_EXT_PROTO_RATE_NONE ? "provider" :
								 "default";
		rate = declared != ESDM_ES_EXT_PROTO_RATE_NONE ? declared : 0;
	}

	if (source)
		*source = from;
	return min_uint32(rate, ESDM_DRNG_SECURITY_STRENGTH_BITS);
}

static uint32_t extsock_level(bool credited, uint32_t declared,
			      uint32_t requested_bits)
{
	return credited ?
		       esdm_fast_noise_entropylevel(
			       extsock_rate(declared, NULL), requested_bits) :
		       0;
}

static void extsock_lock(void)
{
	mutex_lock(&extsock.mutex);
}

/* Release the mutex, publishing the state read without it */
static void extsock_unlock(void)
{
	atomic_store(&extsock.configured, extsock_path()[0] != '\0');
	atomic_store(&extsock.credited, extsock_credited());
	atomic_store(&extsock.published_rate, extsock.rate);
	mutex_unlock(&extsock.mutex);
}

/*
 * The status went with the connection: the next one may be another provider.
 * Published at once, not to keep a seeding waiting for the next connection.
 */
static void extsock_disconnect(void)
{
	if (extsock.fd >= 0)
		close(extsock.fd);
	extsock.fd = -1;
	atomic_store(&extsock.credited, false);
	json_object_put(extsock.status);
	extsock.status = NULL;
	extsock.status_at = 0;
}

/*
 * Give up on a connection that failed until the retry interval is over: a
 * provider failing every request, or answering just too late, must not cost
 * a timeout per seeding.
 */
static void extsock_drop(void)
{
	extsock_disconnect();
	extsock.retry_at = extsock_retry_time();
}

static void extsock_log_once(enum extsock_event what,
			     enum esdm_logger_verbosity level, const char *msg)
{
	if (extsock.last_logged == what)
		return;
	extsock.last_logged = what;
	esdm_logger(level, LOGGER_C_ES, "External ES provider %s: %s\n",
		    extsock_path(), msg);
}

/* The next message by @deadline, monotonic ns: its size or a negative errno */
static ssize_t extsock_recv(uint64_t deadline)
{
	for (;;) {
		struct pollfd pfd = { .fd = extsock.fd, .events = POLLIN };
		uint64_t now = esdm_monotonic_now_ns();
		ssize_t n;

		if (now >= deadline)
			return -ETIMEDOUT;
		n = poll(&pfd, 1, (int)((deadline - now + 999999) / 1000000));
		if (n < 0 && errno != EINTR)
			return -errno;
		if (n <= 0)
			continue;

		/* MSG_TRUNC: the size of a message larger than any answer */
		n = recv(extsock.fd, extsock.msg, sizeof(extsock.msg),
			 MSG_DONTWAIT | MSG_TRUNC);
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (n < 0)
			return -errno;
		if (!n)
			return -ECONNRESET;
		return (size_t)n > sizeof(extsock.msg) ? -EPROTO : n;
	}
}

/*
 * Send a request and decode its answer into extsock.rsp, waiting @timeout_ms
 * for it: 0, or a negative errno with the connection dropped
 */
static int extsock_call(uint16_t type, uint32_t length, unsigned int timeout_ms)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_MAX];
	size_t reqlen =
		esdm_es_ext_proto_req_pack(req, sizeof(req), type, length);
	ssize_t n;

	/* One request at a time: it fits the socket buffer */
	n = send(extsock.fd, req, reqlen, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (reqlen && n == (ssize_t)reqlen)
		n = extsock_recv(esdm_monotonic_now_ns() +
				 (uint64_t)timeout_ms * 1000000);
	else
		n = n < 0 ? -errno : -EIO;

	if (n >= 0 && esdm_es_ext_proto_rsp_unpack(extsock.msg, (size_t)n, type,
						   length, &extsock.rsp))
		n = -EPROTO;
	memset_secure(extsock.msg, 0, sizeof(extsock.msg));
	if (n < 0) {
		extsock_drop();
		return (int)n;
	}
	return 0;
}

/* The blocks collected before are not to be served any more */
static void extsock_es_reset(void)
{
#if (ESDM_EXT_ENTROPY_BLOCKS != 0)
	if (extsock.buf_alloced)
		esdm_es_buf_reset(&extsock.buf);
#endif
}

/*
 * 0 if the provider passed, -EFAULT otherwise. A failure discards the blocks
 * cached: they were made just before it.
 */
static int extsock_selftest_locked(void)
{
	int32_t status;

	/* Dropped: the next connection is tested anew */
	if (extsock_call(ESDM_ES_EXT_PROTO_SELFTEST, 0, ESDM_EXT_TIMEOUT_MS)) {
		extsock_log(LOGGER_ERR, "self test not answered\n");
		return -EFAULT;
	}

	status = extsock.rsp.status;
	extsock.selftest_due = false;
	extsock.selftest_failed = !!status;
	if (status) {
		extsock_log(LOGGER_ERR, "self test failed: %s\n",
			    strerror(-status));
		extsock_es_reset();
		return -EFAULT;
	}
	return 0;
}

/* Take the name and rate the provider declares - see INFO in esdm_es_ext.h */
static int extsock_info(void)
{
	int ret = extsock_call(ESDM_ES_EXT_PROTO_INFO, 0, ESDM_EXT_TIMEOUT_MS);
	size_t len = extsock.rsp.namelen;

	extsock.name[0] = '\0';
	extsock.rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	if (ret)
		return ret;
	/* An INFO answered with an errno declares nothing */
	if (extsock.rsp.status)
		return 0;

	extsock.rate = esdm_es_ext_rate_cap(extsock.rsp.rate);
	if (len && !esdm_es_ext_name_valid(extsock.rsp.name, len)) {
		extsock_log(LOGGER_WARN,
			    "the name it declares is invalid, shown as %s\n",
			    EXTSOCK_NAME);
	} else if (len) {
		memcpy(extsock.name, extsock.rsp.name, len);
		extsock.name[len] = '\0';
		if (esdm_es_name_taken(extsock.name, &esdm_es_extsock)) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"External ES provider: it declares the name %s of another entropy source, shown as %s\n",
				extsock.name, EXTSOCK_NAME);
			extsock.name[0] = '\0';
		}
	}
	return 0;
}

/* Connect to the provider, ask it what it declares and test it */
static bool extsock_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	const char *path = extsock_path(), *source;
	struct ucred cred;
	socklen_t len = sizeof(cred);
	uint32_t rate;
	int fd;

	extsock_disconnect();
	if (strlen(path) >= sizeof(addr.sun_path))
		return false;
	strcpy(addr.sun_path, path);

	/*
	 * Non-blocking: a full backlog fails at once, and a request polls for
	 * its answer
	 */
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return false;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		extsock_log_once(EXTSOCK_UNREACHABLE, LOGGER_WARN,
				 "not reachable, no entropy until it is");
		goto err;
	}
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
		goto err;
	if (cred.uid != 0 &&
	    (extsock.peer_uid < 0 || cred.uid != (uid_t)extsock.peer_uid)) {
		extsock_log_once(
			EXTSOCK_REFUSED, LOGGER_ERR,
			"refused - it runs neither as root nor as the uid accepted");
		goto err;
	}

	extsock.fd = fd;
	extsock.uid = cred.uid;
	extsock.selftest_due = true;
	if (extsock_info()) {
		extsock_log_once(EXTSOCK_NO_INFO, LOGGER_WARN,
				 "no valid answer to INFO");
		return false;
	}

	extsock.last_logged = EXTSOCK_LOGGED_NONE;
	/* Its claims are not assessed by the ESDM, which is worth a line */
	rate = extsock_rate(extsock.rate, &source);
	extsock_log(
		extsock.was_connected ? LOGGER_VERBOSE : LOGGER_STATUS,
		"%s connected (uid %u), its entropy claims credited with up to %u bits per 256 bits (rate of the %s)\n",
		path, (unsigned int)cred.uid, rate, source);
	extsock.was_connected = true;

	extsock_selftest_locked();
	return extsock.fd >= 0;

err:
	close(fd);
	return false;
}

/*
 * Is the connection there? Nothing is to be read on an idle one, so whatever
 * poll(2) reports is its end - a provider restarted, or making room for
 * another client: it is made again at once, the next request not lost on it.
 */
static bool extsock_alive(void)
{
	struct pollfd pfd = { .fd = extsock.fd, .events = POLLIN };

	if (extsock.fd < 0)
		return false;
	if (poll(&pfd, 1, 0) <= 0)
		return true;

	extsock_log(LOGGER_VERBOSE, "connection closed by the provider\n");
	extsock_disconnect();
	extsock.retry_at = 0;
	return false;
}

/* Connected, or connected now if it is time to */
static bool extsock_ensure(void)
{
	if (extsock_alive())
		return true;
	if (!extsock_path()[0] || esdm_monotonic_now_ns() < extsock.retry_at)
		return false;

	/* The retry interval counts from the end of the attempt */
	if (!extsock_connect()) {
		extsock.retry_at = extsock_retry_time();
		return false;
	}
	return true;
}

/* Forget the provider: the next one is connected to on demand */
static void extsock_reset_locked(void)
{
	extsock_disconnect();
	extsock.retry_at = extsock.probe_at = 0;
	extsock.last_logged = EXTSOCK_LOGGED_NONE;
	extsock.was_connected = false;
	extsock.read_failed = extsock.selftest_failed = false;
	extsock.selftest_due = true;
	extsock.name[0] = '\0';
	extsock.rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	extsock.status_warned = false;
}

static int extsock_init(void)
{
	extsock_lock();
	extsock_reset_locked();
	/* A provider not there yet is connected to by the ES monitor */
	if (extsock_path()[0])
		extsock_connect();
	extsock_unlock();

	extsock_es_reset();
#if (ESDM_EXT_ENTROPY_BLOCKS != 0)
	if (!extsock.buf_alloced &&
	    !esdm_es_buf_alloc(&extsock.buf, ESDM_EXT_ENTROPY_BLOCKS,
			       EXTSOCK_NAME))
		extsock.buf_alloced = true;
#endif

	return 0;
}

static void extsock_fini(void)
{
	extsock_lock();
	extsock_reset_locked();
	extsock_unlock();

#if (ESDM_EXT_ENTROPY_BLOCKS != 0)
	if (extsock.buf_alloced) {
		esdm_es_buf_free(&extsock.buf);
		extsock.buf_alloced = false;
	}
#endif
}

/* As published: a request in progress is not waited for */
static uint32_t extsock_entropylevel(uint32_t requested_bits)
{
	return extsock_level(atomic_load(&extsock.credited),
			     atomic_load(&extsock.published_rate),
			     requested_bits);
}

static uint32_t extsock_poolsize(void)
{
	return extsock_entropylevel(esdm_security_strength());
}

/*
 * From a credited connection only: one going is not waited for, nor is a
 * failing provider asked by every seeding
 */
static void extsock_get(struct entropy_es *eb_es, uint32_t requested_bits)
{
	uint32_t len = requested_bits >> 3;
	int32_t status;
	int ret;

	/* A whole seed buffer can be asked for in one request */
	BUILD_BUG_ON(ESDM_DRNG_INIT_SEED_SIZE_BYTES >
		     ESDM_ES_EXT_PROTO_MAX_DATA);

	eb_es->e_bits = 0;
	if (!len || len > sizeof(eb_es->e) || !atomic_load(&extsock.credited))
		return;

	extsock_lock();
	if (!extsock_alive() || !extsock_credited())
		goto out;

	ret = extsock_call(ESDM_ES_EXT_PROTO_GET_ENTROPY, len,
			   ESDM_EXT_TIMEOUT_MS);
	status = ret ? 0 : extsock.rsp.status;
	if (!ret && !status) {
		memcpy(eb_es->e, extsock.rsp.data, len);
		extsock.read_failed = false;
		eb_es->e_bits =
			min_uint32(extsock.rsp.entropy_bits,
				   extsock_level(extsock_credited(),
						 extsock.rate, requested_bits));
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "obtained %u bits of entropy from external ES\n",
			    eb_es->e_bits);
	} else {
		extsock_log(LOGGER_WARN, "no entropy delivered: %s\n",
			    strerror(ret ? -ret : -status));
		extsock.read_failed = true;
	}

out:
	memset_secure(&extsock.rsp, 0, sizeof(extsock.rsp));
	extsock_unlock();
}

#if (ESDM_EXT_ENTROPY_BLOCKS != 0)

static void extsock_buf_fill(struct entropy_es *eb_es, uint32_t requested_bits,
			     void *ctx)
{
	(void)ctx;
	extsock_get(eb_es, requested_bits);
}

/*
 * A block of the cache at most at the rate now, none while the provider is not
 * credited. A block without entropy from a source credited at a rate is
 * skipped: one of a failed request, or claimed with nothing.
 */
static bool extsock_get_cached(struct entropy_es *eb_es,
			       uint32_t requested_bits)
{
	uint32_t level;
	unsigned int i;

	if (!extsock.buf_alloced || !atomic_load(&extsock.credited))
		return false;

	level = extsock_entropylevel(requested_bits);
	for (i = 0; i < ESDM_EXT_ENTROPY_BLOCKS; i++) {
		if (!esdm_es_buf_try_get(&extsock.buf, eb_es, requested_bits))
			return false;
		if (eb_es->e_bits || !level) {
			eb_es->e_bits = min_uint32(eb_es->e_bits, level);
			return true;
		}
	}

	return false;
}

#endif

static void extsock_get_ent(struct entropy_es *eb_es, uint32_t requested_bits,
			    bool __unused fully_seeded)
{
#if (ESDM_EXT_ENTROPY_BLOCKS != 0)
	if (extsock_get_cached(eb_es, requested_bits))
		return;
#endif
	extsock_get(eb_es, requested_bits);
}

/*
 * The monitor connects to the provider, and probes a failing one with data it
 * discards. It fills the block cache from a credited one, starting no request
 * after one timeout: a slow provider is not to hold up the pass of every
 * source, nor a reinitialization waiting for it.
 */
static int extsock_monitor(void)
{
	extsock_lock();
	if (extsock_ensure() && extsock.read_failed &&
	    esdm_monotonic_now_ns() >= extsock.probe_at) {
		extsock.probe_at = extsock_retry_time();
		if (!extsock_call(ESDM_ES_EXT_PROTO_GET_ENTROPY,
				  ESDM_DRNG_SECURITY_STRENGTH_BYTES,
				  ESDM_EXT_TIMEOUT_MS) &&
		    !extsock.rsp.status) {
			extsock.read_failed = false;
			extsock_log(LOGGER_STATUS, "delivering again\n");
		}
		memset_secure(&extsock.rsp, 0, sizeof(extsock.rsp));
	}
	extsock_unlock();

#if (ESDM_EXT_ENTROPY_BLOCKS != 0)
	if (extsock.buf_alloced && atomic_load(&extsock.credited))
		esdm_es_buf_monitor_until(
			&extsock.buf, esdm_get_seed_entropy_osr(false, true),
			extsock_buf_fill, NULL,
			esdm_monotonic_now_ns() +
				ESDM_EXT_TIMEOUT_MS * 1000000ULL);
#endif
	return 0;
}

/*
 * Ask the provider connected to for its status, at most every
 * ESDM_EXT_STATUS_INTERVAL_SEC: a seeding waits meanwhile, and whoever asks
 * for the ESDM status is not to make the seedings wait at will. No connection
 * is made for it.
 */
static void extsock_status_refresh(void)
{
	uint64_t now = esdm_monotonic_now_ns();
	int32_t status;

	if (extsock.status_at &&
	    now - extsock.status_at <
		    ESDM_EXT_STATUS_INTERVAL_SEC * EXTSOCK_NSEC)
		return;
	json_object_put(extsock.status);
	extsock.status = NULL;
	extsock.status_at = now;

	if (!extsock_alive())
		return;
	if (extsock_call(ESDM_ES_EXT_PROTO_STATUS, ESDM_ES_EXT_PROTO_STATUS_MAX,
			 ESDM_EXT_STATUS_TIMEOUT_MS)) {
		extsock_log(LOGGER_WARN,
			    "no valid answer to STATUS, disconnected\n");
		return;
	}
	status = extsock.rsp.status;
	if (status) {
		if (status != -EOPNOTSUPP)
			extsock_log(LOGGER_DEBUG, "no status: %s\n",
				    strerror(-status));
		return;
	}

	/* One level deeper than the status of a source: the server wraps it */
	extsock.status = esdm_es_ext_json_object(
		(const char *)extsock.rsp.data, extsock.rsp.datalen,
		ESDM_ES_EXT_PROTO_STATUS_MAX, ESDM_ES_EXT_STATUS_MAX_DEPTH + 1);
	if (!extsock.status && !extsock.status_warned)
		extsock_log(LOGGER_WARN,
			    "its status is no JSON object of up to %u bytes\n",
			    ESDM_ES_EXT_PROTO_STATUS_MAX);
	extsock.status_warned = !extsock.status;
}

/* The state of the source, as both renderings show it */
struct extsock_state {
	uint32_t poolsize;
	uint32_t entropy_rate;
	uint32_t rate;
	const char *rate_source;
	const char *path;
	char status[64];
	char accepted[48];
};

/* Caller holds the mutex, which keeps what @st points to */
static void extsock_state_locked(struct extsock_state *st)
{
	extsock_status_refresh();

	st->poolsize = extsock_level(extsock_credited(), extsock.rate,
				     esdm_security_strength());
	st->entropy_rate = extsock_level(extsock_credited(), extsock.rate, 256);
	st->rate = extsock_rate(extsock.rate, &st->rate_source);
	st->path = extsock_path()[0] ? extsock_path() : "(unset)";

	if (extsock.fd < 0)
		snprintf(st->status, sizeof(st->status), "not connected");
	else
		snprintf(st->status, sizeof(st->status), "connected (uid %u)%s",
			 (unsigned int)extsock.uid,
			 extsock.selftest_failed ? ", failing its self test" :
			 extsock.read_failed	 ? ", failing" :
						   "");

	if (extsock.peer_uid >= 0)
		snprintf(st->accepted, sizeof(st->accepted),
			 "root and uid %" PRId64, extsock.peer_uid);
	else
		snprintf(st->accepted, sizeof(st->accepted), "root");
}

static void extsock_es_state(char *buf, size_t buflen)
{
	struct extsock_state st;
	size_t len;

	extsock_lock();
	extsock_state_locked(&st);
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n"
		 " Assessed rate: %u\n"
		 " Assessed rate source: %s\n"
		 "%s%s%s"
		 " Provider socket: %s\n"
		 " Provider accepted: %s\n"
		 " Status: %s\n",
		 st.poolsize, st.entropy_rate, st.rate, st.rate_source,
		 extsock.name[0] ? " Declared name: " : "", extsock.name,
		 extsock.name[0] ? "\n" : "", st.path, st.accepted, st.status);

	/* JSON escapes the control characters of the status */
	len = strlen(buf);
	if (extsock.status)
		snprintf(buf + len, buflen - len, " Provider status: %s\n",
			 json_object_to_json_string_ext(
				 extsock.status,
				 JSON_C_TO_STRING_PLAIN |
					 JSON_C_TO_STRING_NOSLASHESCAPE));
	extsock_unlock();
}

/*
 * The members of the text above, but for the name declared: it replaces
 * "name", the ES table name kept as "instance" - see esdm_es_mgr_cb.h - and
 * the status of the provider is the object "provider".
 */
static void extsock_es_state_json(char *buf, size_t buflen)
{
	struct json_object *obj = json_object_new_object();
	struct extsock_state st;
	const char *json;
	size_t len;

	if (!obj) {
		snprintf(buf, buflen, "{}");
		return;
	}

	extsock_lock();
	extsock_state_locked(&st);
	json_object_object_add(obj, "name",
			       json_object_new_string(extsock.name[0] ?
							      extsock.name :
							      EXTSOCK_NAME));
	json_object_object_add(obj, "instance",
			       json_object_new_string(EXTSOCK_NAME));
	json_object_object_add(obj, "available_entropy",
			       json_object_new_int64(st.poolsize));
	json_object_object_add(obj, "entropy_rate_per_256_data_bits",
			       json_object_new_int64(st.entropy_rate));
	json_object_object_add(obj, "assessed_rate",
			       json_object_new_int64(st.rate));
	json_object_object_add(obj, "assessed_rate_source",
			       json_object_new_string(st.rate_source));
	json_object_object_add(obj, "provider_socket",
			       json_object_new_string(st.path));
	json_object_object_add(obj, "provider_accepted",
			       json_object_new_string(st.accepted));
	json_object_object_add(obj, "status",
			       json_object_new_string(st.status));
	/* Its references are counted under the mutex */
	if (extsock.status)
		json_object_object_add(obj, "provider",
				       json_object_get(extsock.status));

	/* A status of the provider too large for @buf is left out */
	json = json_object_to_json_string_length(obj, JSON_C_TO_STRING_PLAIN,
						 &len);
	if (len >= buflen && extsock.status) {
		json_object_object_del(obj, "provider");
		json = json_object_to_json_string_length(
			obj, JSON_C_TO_STRING_PLAIN, &len);
	}
	snprintf(buf, buflen, "%s", json ? json : "{}");
	json_object_put(obj);
	extsock_unlock();
}

/* Active once configured: a provider not reachable is connected on demand */
static bool extsock_active(void)
{
	return atomic_load(&extsock.configured);
}

/*
 * Of the connection there: no other is made, and a provider not connected is
 * no failure - it is tested once connected to
 */
static int extsock_selftest(void)
{
	int ret = 0;

	extsock_lock();
	if (extsock_alive())
		ret = extsock_selftest_locked();
	extsock_unlock();
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_set_path(const char *path)
{
	char *copy = NULL;

	if (!path ||
	    strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
		return -EINVAL;
	if (path[0] && !(copy = strdup(path)))
		return -ENOMEM;

	/* Nor is what the provider of the old path delivered served */
	esdm_es_mgr_monitor_pause();
	extsock_lock();
	free(extsock.path);
	extsock.path = copy;
	extsock_reset_locked();
	extsock_unlock();
	extsock_es_reset();
	esdm_es_mgr_monitor_resume();
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_set_peer_uid(int64_t uid)
{
	/* (uid_t)-1 is no uid, see setreuid(2) */
	if (uid < -1 || uid >= (int64_t)UINT32_MAX)
		return -EINVAL;

	extsock_lock();
	extsock.peer_uid = uid;
	extsock_unlock();
	return 0;
}

struct esdm_es_cb esdm_es_extsock = {
	.name = EXTSOCK_NAME,
	.init = extsock_init,
	.fini = extsock_fini,
	.monitor_es = extsock_monitor,
	.get_ent = extsock_get_ent,
	.curr_entropy = extsock_entropylevel,
	.max_entropy = extsock_poolsize,
	.state = extsock_es_state,
	.state_json = extsock_es_state_json,
	.reset = extsock_es_reset,
	.active = extsock_active,
	.selftest = extsock_selftest,
};
