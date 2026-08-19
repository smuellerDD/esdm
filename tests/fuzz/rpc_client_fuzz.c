/*
 * Fuzz harness: the server through the RPC client library
 *
 * The other RPC harnesses each take one side of the protocol and hand it a
 * buffer: the server's request handling, or the client's response handling.
 * Neither of them ever sends anything over a socket, and neither exercises the
 * client's own packing - the code that turns a call into the bytes the server
 * then has to make sense of.
 *
 * This one closes the loop. It brings up an ESDM with the server's real accept
 * loop and worker threads on one side and the client library on the other, and
 * every input is a script of client calls with arguments the fuzzer chose:
 * esdm_rpcc_get_random_bytes(), esdm_rpcc_write_data(), esdm_rpcc_status() and
 * the rest of what a program linking the client library gets. What each call
 * does from there is what it does in production - pack the request, send it,
 * wait for the answer, decode it and copy it into the caller's buffer.
 *
 * Both sides are in this process, so what the server does with a request is
 * part of what guides the fuzzer, and a crash on either side is a crash here.
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

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "fuzz.h"
#include "priv_access.pb-c.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

/*
 * Not esdm.h: it and the client header declare the same enum, deliberately - a
 * program speaks to the ESDM through one interface or the other, and this
 * harness is the one place driving both ends at once.
 */
int esdm_init(void);

/* Largest buffer a call is given, and the guard behind it. */
#define FUZZ_BUF_MAX 4096
#define FUZZ_GUARD 64
#define FUZZ_GUARD_BYTE 0x5a

/* The prediction resistance call collects entropy per request - ask for little */
#define FUZZ_PR_MAX 32

/* Calls of an input, so one input cannot run for arbitrarily long */
#define FUZZ_MAX_CALLS 32

/* How long the server is given to come up, in 10ms slices */
#define FUZZ_SERVER_SLICES 500

/* Long enough for a serve call that cannot bind to have said so */
#define FUZZ_SERVER_SETTLE_MS 100

/*
 * Exit code meson reads as "this test was skipped". A machine running an
 * esdm-server of its own owns the socket paths this harness needs, which is a
 * reason to stand down rather than to fail: there is nothing wrong with the
 * code under test, it simply cannot be reached from here.
 */
#define FUZZ_EXIT_SKIP 77

static uint64_t fuzz_area[(FUZZ_BUF_MAX + FUZZ_GUARD) / sizeof(uint64_t)];

struct fuzz_input {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

static uint8_t fuzz_u8(struct fuzz_input *in)
{
	return (in->pos < in->len) ? in->data[in->pos++] : 0;
}

static uint32_t fuzz_u32(struct fuzz_input *in)
{
	uint32_t val = 0;
	unsigned int i;

	for (i = 0; i < 4; i++)
		val = (val << 8) | fuzz_u8(in);

	return val;
}

static size_t fuzz_len(struct fuzz_input *in, size_t max)
{
	size_t val = ((size_t)fuzz_u8(in) << 8) | fuzz_u8(in);

	return (val % (max + 1));
}

/* Fill a NUL terminated string of at most @max characters from the input. */
static char *fuzz_text(struct fuzz_input *in, char *buf, size_t max)
{
	size_t len = fuzz_len(in, max - 1);
	size_t avail = in->len - in->pos;
	size_t take = (avail < len) ? avail : len;

	memcpy(buf, in->data + in->pos, take);
	in->pos += take;
	buf[take] = '\0';

	return buf;
}

static uint8_t *fuzz_buf(size_t len)
{
	uint8_t *buf = (uint8_t *)fuzz_area;

	memset(buf, 0, len);
	memset(buf + len, FUZZ_GUARD_BYTE, FUZZ_GUARD);

	return buf;
}

/* Nothing may be written behind the buffer the call was given. */
static void fuzz_check_guard(const char *call, size_t len, ssize_t ret)
{
	const uint8_t *buf = (const uint8_t *)fuzz_area;
	unsigned int i;

	for (i = 0; i < FUZZ_GUARD; i++) {
		if (buf[len + i] == FUZZ_GUARD_BYTE)
			continue;

		fprintf(stderr,
			"%s wrote %u byte(s) behind the buffer of %zu it was given\n",
			call, FUZZ_GUARD - i, len);
		abort();
	}

	if (ret > (ssize_t)len) {
		fprintf(stderr, "%s reports %zd bytes in a buffer of %zu\n",
			call, ret, len);
		abort();
	}
}

/* Text handed to a caller has to end inside the buffer it was given */
static void fuzz_check_string(const char *call, size_t len, int ret)
{
	const char *buf = (const char *)fuzz_area;
	size_t i;

	fuzz_check_guard(call, len, 0);

	if (!len || ret < 0)
		return;

	for (i = 0; i < len; i++) {
		if (!buf[i])
			return;
	}

	fprintf(stderr, "%s returned %d with %zu bytes of text and no end\n",
		call, ret, len);
	abort();
}

/* The calls an input can pick from */
enum fuzz_call {
	fuzz_call_get_random_bytes,
	fuzz_call_get_random_bytes_full,
	fuzz_call_get_random_bytes_full_timeout,
	fuzz_call_get_random_bytes_pr,
	fuzz_call_get_seed,
	fuzz_call_write_data,
	fuzz_call_status,
	fuzz_call_status_json,
	fuzz_call_drng_status_json,
	fuzz_call_drng_status_pr_json,
	fuzz_call_jent_status,
	fuzz_call_get_ent_lvl,
	fuzz_call_is_fully_seeded,
	fuzz_call_rnd_get_ent_cnt,
	fuzz_call_get_poolsize,
	fuzz_call_get_write_wakeup_thresh,
	fuzz_call_get_min_reseed_secs,
	fuzz_call_priv_calls,
	fuzz_calls
};

/* The calls of the privileged interface. */
static void fuzz_priv_call(struct fuzz_input *in)
{
	struct esdm_rpcc_selftest_result selftest;
	uint8_t *buf;
	size_t len;

	switch (fuzz_u8(in) % 8) {
	case 0:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		esdm_rpcc_rnd_add_entropy(buf, len, fuzz_u32(in));
		fuzz_check_guard("esdm_rpcc_rnd_add_entropy", len, 0);
		break;
	case 1:
		esdm_rpcc_rnd_add_to_ent_cnt(fuzz_u32(in));
		break;
	case 2:
		esdm_rpcc_rnd_clear_pool();
		break;
	case 3:
		esdm_rpcc_rnd_reseed_crng();
		break;
	case 4:
		esdm_rpcc_set_write_wakeup_thresh(fuzz_u32(in));
		break;
	case 5:
		esdm_rpcc_set_min_reseed_secs(fuzz_u32(in));
		break;
	case 6: {
		/*
		 * The one call carrying text rather than numbers, and the only
		 * place a client packs a string into a request: two of them,
		 * either of which may be absent - which the packing has to
		 * tell apart from an empty one.
		 */
		static char label[64], pin[64];
		uint8_t which = fuzz_u8(in);

		esdm_rpcc_set_pkcs11_config(
			(which & 1) ? NULL :
				      fuzz_text(in, label, sizeof(label)),
			(which & 2) ? NULL : fuzz_text(in, pin, sizeof(pin)));
		break;
	}
	default:
		memset(&selftest, 0, sizeof(selftest));
		esdm_rpcc_selftest(&selftest);
		break;
	}
}

static void fuzz_one_call(struct fuzz_input *in)
{
	unsigned int val = 0;
	bool seeded = false;
	uint8_t *buf;
	ssize_t rc;
	size_t len;
	int ret;

	switch ((enum fuzz_call)(fuzz_u8(in) % fuzz_calls)) {
	case fuzz_call_get_random_bytes:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		rc = esdm_rpcc_get_random_bytes(buf, len);
		fuzz_check_guard("esdm_rpcc_get_random_bytes", len, rc);
		break;

	case fuzz_call_get_random_bytes_full:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		rc = esdm_rpcc_get_random_bytes_full(buf, len);
		fuzz_check_guard("esdm_rpcc_get_random_bytes_full", len, rc);
		break;

	case fuzz_call_get_random_bytes_full_timeout: {
		/*
		 * The deadline comes from the input, zero included: a call
		 * that gives up on its answer leaves the answer coming, and
		 * what the connection does with it afterwards is the point.
		 */
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };

		len = fuzz_len(in, FUZZ_BUF_MAX);
		ts.tv_nsec = (long)fuzz_u8(in) * 1000 * 1000;
		buf = fuzz_buf(len);
		rc = esdm_rpcc_get_random_bytes_full_timeout(buf, len, &ts);
		fuzz_check_guard("esdm_rpcc_get_random_bytes_full_timeout", len,
				 rc);
		break;
	}

	case fuzz_call_get_random_bytes_pr:
		len = fuzz_len(in, FUZZ_PR_MAX);
		buf = fuzz_buf(len);
		rc = esdm_rpcc_get_random_bytes_pr(buf, len);
		fuzz_check_guard("esdm_rpcc_get_random_bytes_pr", len, rc);
		break;

	case fuzz_call_get_seed:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		rc = esdm_rpcc_get_seed(buf, len, fuzz_u8(in));
		fuzz_check_guard("esdm_rpcc_get_seed", len, rc);
		break;

	case fuzz_call_write_data:
		/*
		 * The one call carrying bytes the fuzzer chose all the way
		 * into the entropy pool the other calls then generate from.
		 */
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		if (len) {
			size_t avail = in->len - in->pos;
			size_t take = (avail < len) ? avail : len;

			memcpy(buf, in->data + in->pos, take);
			in->pos += take;
		}
		esdm_rpcc_write_data(buf, len);
		fuzz_check_guard("esdm_rpcc_write_data", len, 0);
		break;

	case fuzz_call_status:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_rpcc_status((char *)buf, len);
		fuzz_check_string("esdm_rpcc_status", len, ret);
		break;

	case fuzz_call_status_json:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_rpcc_status_json((char *)buf, len);
		fuzz_check_string("esdm_rpcc_status_json", len, ret);
		break;

	case fuzz_call_drng_status_json:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_rpcc_drng_status_json(fuzz_u32(in), (char *)buf,
						 len);
		fuzz_check_string("esdm_rpcc_drng_status_json", len, ret);
		break;

	case fuzz_call_drng_status_pr_json:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_rpcc_drng_status_pr_json((char *)buf, len);
		fuzz_check_string("esdm_rpcc_drng_status_pr_json", len, ret);
		break;

	case fuzz_call_jent_status:
		len = fuzz_len(in, FUZZ_BUF_MAX);
		buf = fuzz_buf(len);
		ret = esdm_rpcc_jent_status((char *)buf, len);
		fuzz_check_string("esdm_rpcc_jent_status", len, ret);
		break;

	case fuzz_call_get_ent_lvl:
		esdm_rpcc_get_ent_lvl(&val);
		break;

	case fuzz_call_is_fully_seeded:
		esdm_rpcc_is_fully_seeded(&seeded);
		break;

	case fuzz_call_rnd_get_ent_cnt:
		esdm_rpcc_rnd_get_ent_cnt(&val);
		break;

	case fuzz_call_get_poolsize:
		esdm_rpcc_get_poolsize(&val);
		break;

	case fuzz_call_get_write_wakeup_thresh:
		esdm_rpcc_get_write_wakeup_thresh(&val);
		break;

	case fuzz_call_get_min_reseed_secs:
		esdm_rpcc_get_min_reseed_secs(&val);
		break;

	case fuzz_call_priv_calls:
		fuzz_priv_call(in);
		break;

	case fuzz_calls:
	default:
		break;
	}
}

/******************************************************************************
 * The server behind the calls
 ******************************************************************************/

/*
 * Set by an interface thread whose serve call returned. It only returns when it
 * could not start, which is a reason to stop rather than to carry on: the
 * socket paths are fixed at build time, so a machine already running an
 * esdm-server owns them, and the paths are there whether or not this harness
 * put them there. Going on regardless fuzzes nothing - every call reaches
 * somebody else's socket, or none at all, and spends the client's connect
 * retries before failing - while the run looks like it is working.
 */
static volatile bool fuzz_serve_stopped;

static void fuzz_serve_report(const char *which, int ret)
{
	fprintf(stderr, "the %s RPC server did not run: %s\n", which,
		strerror(ret < 0 ? -ret : ret));
	fuzz_serve_stopped = true;
}

/* The two interface threads. */
static void *fuzz_serve_unpriv(void *unused)
{
	(void)unused;

	fuzz_serve_report("unprivileged",
			  esdm_rpcs_fuzz_serve(
				  ESDM_RPC_UNPRIV_SOCKET,
				  (ProtobufCService *)&unpriv_access_service,
				  false));

	return NULL;
}

static void *fuzz_serve_priv(void *unused)
{
	(void)unused;

	fuzz_serve_report("privileged",
			  esdm_rpcs_fuzz_serve(
				  ESDM_RPC_PRIV_SOCKET,
				  (ProtobufCService *)&priv_access_service,
				  true));

	return NULL;
}

/* Wait for a socket to turn up, so the first call does not race the server */
static bool fuzz_wait_for_socket(const char *path)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
	unsigned int i;
	struct stat sb;

	for (i = 0; i < FUZZ_SERVER_SLICES; i++) {
		if (fuzz_serve_stopped)
			return false;
		if (!stat(path, &sb) && S_ISSOCK(sb.st_mode))
			return true;
		nanosleep(&ts, NULL);
	}

	return false;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct timespec settle = { .tv_sec = 0,
				   .tv_nsec = FUZZ_SERVER_SETTLE_MS * 1000 *
					      1000 };
	pthread_t unpriv_thread, priv_thread;
	unsigned int ent_cnt;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(getenv("ESDM_FUZZ_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	/*
	 * The sockets are a fixed pair of paths, so two of these cannot run
	 * side by side - a second one would bind over the first.
	 */
	esdm_server_remove_stale_socket(ESDM_RPC_UNPRIV_SOCKET, SOCK_SEQPACKET);
	esdm_server_remove_stale_socket(ESDM_RPC_PRIV_SOCKET, SOCK_SEQPACKET);

	if (esdm_init()) {
		fprintf(stderr, "cannot initialize the ESDM\n");
		exit(1);
	}

	if (thread_init(1)) {
		fprintf(stderr, "cannot initialize threading support\n");
		exit(1);
	}

	if (pthread_create(&unpriv_thread, NULL, fuzz_serve_unpriv, NULL) ||
	    pthread_create(&priv_thread, NULL, fuzz_serve_priv, NULL)) {
		fprintf(stderr, "cannot start the RPC server threads\n");
		exit(1);
	}

	/*
	 * A serve call that cannot bind returns at once, so this is all the
	 * grace the threads need to have reported it - and the socket paths
	 * exist either way when somebody else owns them, which is why their
	 * presence alone says nothing.
	 */
	nanosleep(&settle, NULL);

	if (fuzz_serve_stopped ||
	    !fuzz_wait_for_socket(ESDM_RPC_UNPRIV_SOCKET) ||
	    !fuzz_wait_for_socket(ESDM_RPC_PRIV_SOCKET)) {
		fprintf(stderr, "the RPC server did not come up\n");
		exit(FUZZ_EXIT_SKIP);
	}

	if (esdm_rpcc_init_unpriv_service(NULL) ||
	    esdm_rpcc_init_priv_service(NULL)) {
		fprintf(stderr, "cannot reach the RPC server\n");
		exit(1);
	}

	/*
	 * And one round trip, because reaching the socket is not the same as
	 * being served over it: what answers has to be the server this harness
	 * started, not a leftover path or a daemon of the machine.
	 */
	if (esdm_rpcc_rnd_get_ent_cnt(&ent_cnt)) {
		fprintf(stderr,
			"the RPC server does not answer - is an esdm-server of this machine holding %s?\n",
			ESDM_RPC_UNPRIV_SOCKET);
		exit(FUZZ_EXIT_SKIP);
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_input in = { .data = data, .len = size, .pos = 0 };
	unsigned int calls = 0;

	while (in.pos < in.len && calls++ < FUZZ_MAX_CALLS)
		fuzz_one_call(&in);

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

/*
 * One seed per call so every one of them is reached at least once, plus a
 * script running through all of them - what a client does to a server is a
 * sequence of calls, and the entropy one of them writes is what the next one
 * generates from.
 */
#define FUZZ_MAX_SEEDS (fuzz_calls + 2)
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static char fuzz_seed_names[FUZZ_MAX_SEEDS][32];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][4 * FUZZ_MAX_SEEDS + 16];
static size_t fuzz_num_seeds;

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	unsigned int call;
	uint8_t *seed;

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	for (call = 0; call < fuzz_calls; call++) {
		seed = fuzz_seed_data[fuzz_num_seeds];

		/* The call, a length of 32, and room for its arguments */
		seed[0] = (uint8_t)call;
		seed[1] = 0;
		seed[2] = 32;
		memset(seed + 3, 0, 8);

		snprintf(fuzz_seed_names[fuzz_num_seeds],
			 sizeof(fuzz_seed_names[0]), "call-%u", call);

		fuzz_seeds[fuzz_num_seeds].name =
			fuzz_seed_names[fuzz_num_seeds];
		fuzz_seeds[fuzz_num_seeds].data = seed;
		fuzz_seeds[fuzz_num_seeds].len = 11;
		fuzz_num_seeds++;
	}

	seed = fuzz_seed_data[fuzz_num_seeds];
	for (call = 0; call < fuzz_calls; call++) {
		seed[3 * call] = (uint8_t)call;
		seed[3 * call + 1] = 0;
		seed[3 * call + 2] = 16;
	}

	snprintf(fuzz_seed_names[fuzz_num_seeds], sizeof(fuzz_seed_names[0]),
		 "every-call");

	fuzz_seeds[fuzz_num_seeds].name = fuzz_seed_names[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = 3 * fuzz_calls;
	fuzz_num_seeds++;

	/*
	 * A call that gives up on its answer, then another one on the same
	 * connection.
	 */
	seed = fuzz_seed_data[fuzz_num_seeds];
	seed[0] = fuzz_call_get_random_bytes_full_timeout;
	seed[1] = 0x0f;
	seed[2] = 0xff; /* as many bytes as the harness hands out */
	seed[3] = 0; /* no deadline at all */
	seed[4] = fuzz_call_get_seed;
	seed[5] = 0;
	seed[6] = 0; /* into a buffer of no size */
	seed[7] = 0; /* no flags */

	snprintf(fuzz_seed_names[fuzz_num_seeds], sizeof(fuzz_seed_names[0]),
		 "abandoned-answer");

	fuzz_seeds[fuzz_num_seeds].name = fuzz_seed_names[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = 8;
	fuzz_num_seeds++;

	*num = fuzz_num_seeds;

	return fuzz_seeds;
}
