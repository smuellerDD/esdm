/*
 * The peer of the OpenSSL RPC provider harness: a whole ESDM in this process
 *
 * The RPC based providers reach the ESDM through the client library, which
 * needs a server on the other end of its sockets. Rather than mocking one, this
 * brings up the real thing - the ESDM itself, the server's accept loop and its
 * worker threads - so a request the provider sends is packed, transferred,
 * decoded and served the way it is in production, and what the ESDM does with
 * it guides the fuzzer alongside what the provider does.
 *
 * The sockets are the pair of paths this ESDM was built with, so only one
 * harness of this kind runs at a time.
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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "esdm_rpc_client.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "ossl_prov_fuzz.h"
#include "priv_access.pb-c.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

/*
 * Not esdm.h: it and the client header declare the same enum, deliberately - a
 * program speaks to the ESDM through one interface or the other, and this
 * harness is the one place driving both ends at once.
 */
int esdm_init(void);

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

/*
 * Set by an interface thread whose serve call returned. It only returns when it
 * could not start, which is a reason to stop rather than to carry on: the
 * socket paths are fixed at build time, so a machine already running an
 * esdm-server owns them, and a harness that went on regardless would fuzz its
 * calls against somebody else's socket - or, as is the case for a socket
 * activated server that is not up, against nothing at all, every call spending
 * the client's connect retries before failing.
 */
static volatile bool fuzz_serve_stopped;

static void fuzz_serve_report(const char *which, int ret)
{
	fprintf(stderr, "the %s RPC server did not run: %s\n", which,
		strerror(ret < 0 ? -ret : ret));
	fuzz_serve_stopped = true;
}

/* The two interface threads */
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

int fuzz_backend_init(void)
{
	struct timespec settle = { .tv_sec = 0,
				   .tv_nsec = FUZZ_SERVER_SETTLE_MS * 1000 *
					      1000 };
	pthread_t unpriv_thread, priv_thread;
	unsigned int ent_cnt;

	/*
	 * The sockets are a fixed pair of paths, so two of these cannot run
	 * side by side - a second one would bind over the first.
	 */
	esdm_server_remove_stale_socket(ESDM_RPC_UNPRIV_SOCKET, SOCK_SEQPACKET);
	esdm_server_remove_stale_socket(ESDM_RPC_PRIV_SOCKET, SOCK_SEQPACKET);

	if (esdm_init()) {
		fprintf(stderr, "cannot initialize the ESDM\n");
		return 1;
	}

	if (thread_init(1)) {
		fprintf(stderr, "cannot initialize threading support\n");
		return 1;
	}

	if (pthread_create(&unpriv_thread, NULL, fuzz_serve_unpriv, NULL) ||
	    pthread_create(&priv_thread, NULL, fuzz_serve_priv, NULL)) {
		fprintf(stderr, "cannot start the RPC server threads\n");
		return 1;
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
		return FUZZ_EXIT_SKIP;
	}

	/*
	 * A reference of the harness' own on the client connection the
	 * provider shares with everybody else in this process. The provider is
	 * loaded and torn down once per input, and each teardown drops the
	 * reference its initialization took; without this one the connection
	 * would be built up and taken down again for every input, which is
	 * both slow and not what a loaded provider does.
	 */
	if (esdm_rpcc_init_unpriv_service(NULL)) {
		fprintf(stderr, "cannot reach the RPC server\n");
		return 1;
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
		return FUZZ_EXIT_SKIP;
	}

	return 0;
}

void fuzz_backend_begin(const uint8_t *data, size_t len)
{
	/*
	 * The ESDM answers for itself - the bytes an input carries for a peer
	 * that makes up its answers have no place here.
	 */
	(void)data;
	(void)len;
}

void fuzz_backend_end(void)
{
}
