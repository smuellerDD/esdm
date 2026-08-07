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

#ifndef ACCOUNTING_PROBE_H
#define ACCOUNTING_PROBE_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "esdm_rpc_service.h"
#include "test_pertubation.h"

/*
 * Check the byte accounting for one request of each shape the client's chunking
 * can produce.
 *
 * A request larger than one RPC message is split, and the last piece is a
 * partial one whenever the length is not a multiple of ESDM_RPC_MAX_DATA. Each
 * shape is therefore probed on its own - well below a message, exactly one
 * message, and one message plus a remainder - so that a discrepancy is
 * attributed to a specific shape rather than inferred from the totals of a
 * megabyte-sized request that contains all of them at once.
 *
 * The server counts what it generated and the client what it kept. The two are
 * expected to agree: entropy the server produces and then discards is worth
 * knowing about, both because generating it is not free and because it means a
 * request was answered twice.
 *
 * Returns the number of shapes that did not add up.
 */
typedef ssize_t (*probe_call_t)(uint8_t *buf, size_t buflen);

static inline unsigned int probe_accounting(probe_call_t call, const char *name)
{
	static const size_t remainder = 384;
	const size_t probes[] = {
		remainder,
		ESDM_RPC_MAX_DATA,
		ESDM_RPC_MAX_DATA + remainder,
	};
	unsigned int i, failures = 0;
	uint8_t *buf = malloc(ESDM_RPC_MAX_DATA + remainder);

	if (!buf) {
		printf("PROBE %s: out of memory\n", name);
		return 1;
	}

	printf("PROBE %s: RPC message payload is %zu bytes\n", name,
	       (size_t)ESDM_RPC_MAX_DATA);

	for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
		size_t want = probes[i];
		size_t client, server;
		ssize_t rc;

		esdm_test_shm_status_reset();

		rc = call(buf, want);
		if (rc < 0) {
			printf("PROBE %s: request of %zu bytes failed: %zd\n",
			       name, want, rc);
			failures++;
			continue;
		}

		client = esdm_test_shm_status_get_rpc_client_written();
		server = esdm_test_shm_status_get_rpc_server_written();

		if (client == want && server == want) {
			printf("PROBE %s: %zu bytes - client %zu, server %zu: ok\n",
			       name, want, client, server);
			continue;
		}

		failures++;
		printf("PROBE %s: %zu bytes - client %zu, server %zu: MISMATCH\n",
		       name, want, client, server);

		if (server > want) {
			size_t excess = server - want;

			printf("PROBE %s: the server generated %zu bytes more than were kept",
			       name, excess);
			if (want % ESDM_RPC_MAX_DATA &&
			    excess == ESDM_RPC_MAX_DATA -
					      (want % ESDM_RPC_MAX_DATA)) {
				printf(" - exactly the unused part of a full message, so the partial request was served as a whole one");
			} else if (!(excess % ESDM_RPC_MAX_DATA)) {
				printf(" - exactly %zu whole messages, so a request was served more than once",
				       excess / ESDM_RPC_MAX_DATA);
			}
			printf("\n");
		}
	}

	free(buf);

	return failures;
}

/* Spell out how a total relates to the chunking when the loop below trips */
static inline void report_accounting_mismatch(const char *what, size_t len,
					      size_t counted)
{
	printf("ERROR: amount of %s (%zu) does not match received data (%zu)\n",
	       what, counted, len);

	if (counted > len) {
		size_t excess = counted - len;

		printf("       excess %zu, RPC message payload %zu, request remainder %zu",
		       excess, (size_t)ESDM_RPC_MAX_DATA,
		       len % ESDM_RPC_MAX_DATA);
		if (!(excess % ESDM_RPC_MAX_DATA))
			printf(" - %zu whole messages",
			       excess / ESDM_RPC_MAX_DATA);
		printf("\n");
	}
}

#endif /* ACCOUNTING_PROBE_H */
