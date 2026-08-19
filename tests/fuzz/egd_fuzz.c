/*
 * Fuzz harness: the EGD interface of the server
 *
 * The EGD compatibility interface serves the protocol of egd.pl and prngd on a
 * Unix domain stream socket, so that legacy consumers - libgcrypt's rndegd
 * backend, OpenSSL's RAND_egd() - can draw from the ESDM unmodified. Whoever
 * can reach that socket is parsed by it, and the protocol is a bare byte
 * stream: a command byte, sometimes a length byte, sometimes data. There is no
 * length prefix over a whole message, no request ID and no error response, so
 * the parser has nothing to resynchronize on and everything rests on it
 * reading the stream exactly right.
 *
 * That stream is what an input is here. It arrives in records - a length byte
 * and that many bytes - and each record is one read() as the connection would
 * see it, so the fuzzer decides where a command is cut in half as well as what
 * the commands are. Command by command is what the ordinary case looks like;
 * half a write command followed by the rest of it two reads later is what the
 * state machine has to survive, and the harness can produce both.
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esdm_egd_protocol.h"
#include "esdm_egd_server.h"
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "fuzz.h"

/*
 * Not esdm.h: only the call bringing the ESDM up behind the interface is
 * needed from it, and the EGD headers next to it carry no declaration of it.
 */
int esdm_init(void);

/*
 * The first byte selects the prediction resistance socket when all of these
 * bits are set - see LLVMFuzzerTestOneInput() for why it is not a single one.
 */
#define FUZZ_PR_SOCKET_MASK 0x0f

/* Where the responses go, and its other end, which the harness empties */
static int fuzz_response_fd = -1;
static int fuzz_response_peer_fd = -1;

static void fuzz_drain_responses(void)
{
	static uint8_t sink[4096];

	while (recv(fuzz_response_peer_fd, sink, sizeof(sink), MSG_DONTWAIT) >
	       0)
		;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int sockets[2];

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(getenv("ESDM_FUZZ_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	/* A stream socket, which is what an EGD client connects with */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		fprintf(stderr, "cannot create the response socket: %s\n",
			strerror(errno));
		exit(1);
	}

	fuzz_response_fd = sockets[0];
	fuzz_response_peer_fd = sockets[1];

	/*
	 * Non-blocking like an accepted connection: a response that does not
	 * fit into the socket buffer is then held as a pending one, which is
	 * a state of the connection worth reaching rather than a stall.
	 */
	if (set_fd_nonblocking(fuzz_response_fd) ||
	    set_fd_nonblocking(fuzz_response_peer_fd)) {
		fprintf(stderr,
			"cannot set the response socket non-blocking\n");
		exit(1);
	}

	if (esdm_init()) {
		fprintf(stderr, "cannot initialize the ESDM\n");
		exit(1);
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* The first byte picks the socket, so an empty input has none */
	if (!size)
		return 0;

	/*
	 * Which of the two sockets the client reached decides which generator
	 * answers it - the protocol cannot ask for prediction resistance, so it
	 * is a property of the socket.
	 */
	esdm_egd_fuzz_stream((data[0] & FUZZ_PR_SOCKET_MASK) ==
				     FUZZ_PR_SOCKET_MASK,
			     fuzz_response_fd, data + 1, size - 1);

	fuzz_drain_responses();

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

/*
 * One well formed command each, plus the two shapes that only a stream protocol
 * has: several commands in one read, and one command split across two.
 */
#define FUZZ_MAX_SEEDS 9
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][64];
static size_t fuzz_num_seeds;

/* One record - a length byte and its bytes - appended to a seed */
static size_t fuzz_seed_record(uint8_t *seed, size_t pos, const uint8_t *cmd,
			       size_t len)
{
	seed[pos++] = (uint8_t)len;
	memcpy(seed + pos, cmd, len);

	return pos + len;
}

static void fuzz_seed_add(const char *name, const uint8_t *cmd, size_t len)
{
	uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];

	if (fuzz_num_seeds >= FUZZ_MAX_SEEDS)
		return;

	seed[0] = 0; /* the ordinary socket */

	fuzz_seeds[fuzz_num_seeds].name = name;
	fuzz_seeds[fuzz_num_seeds].data = seed;
	fuzz_seeds[fuzz_num_seeds].len = fuzz_seed_record(seed, 1, cmd, len);
	fuzz_num_seeds++;
}

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	static const uint8_t entropy_count[] = { ESDM_EGD_CMD_ENTROPY_COUNT };
	static const uint8_t get_pid[] = { ESDM_EGD_CMD_GET_PID };
	static const uint8_t read_nonblock[] = { ESDM_EGD_CMD_READ_NONBLOCK,
						 32 };
	static const uint8_t read_block[] = { ESDM_EGD_CMD_READ_BLOCK, 32 };
	static const uint8_t write_entropy[] = { ESDM_EGD_CMD_WRITE_ENTROPY,
						 0x00,
						 0x40,
						 8,
						 1,
						 2,
						 3,
						 4,
						 5,
						 6,
						 7,
						 8 };
	uint8_t *seed;
	size_t pos;

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	fuzz_seed_add("entropy-count", entropy_count, sizeof(entropy_count));
	fuzz_seed_add("get-pid", get_pid, sizeof(get_pid));
	fuzz_seed_add("read-nonblock", read_nonblock, sizeof(read_nonblock));
	fuzz_seed_add("read-block", read_block, sizeof(read_block));
	fuzz_seed_add("write-entropy", write_entropy, sizeof(write_entropy));

	/* Several commands arriving in one read */
	if (fuzz_num_seeds < FUZZ_MAX_SEEDS) {
		uint8_t batch[sizeof(entropy_count) + sizeof(read_nonblock) +
			      sizeof(get_pid)];

		memcpy(batch, entropy_count, sizeof(entropy_count));
		memcpy(batch + sizeof(entropy_count), read_nonblock,
		       sizeof(read_nonblock));
		memcpy(batch + sizeof(entropy_count) + sizeof(read_nonblock),
		       get_pid, sizeof(get_pid));

		fuzz_seed_add("batched-commands", batch, sizeof(batch));
	}

	/* The same read on the prediction resistance socket. */
	if (fuzz_num_seeds < FUZZ_MAX_SEEDS) {
		seed = fuzz_seed_data[fuzz_num_seeds];
		seed[0] = FUZZ_PR_SOCKET_MASK;
		pos = fuzz_seed_record(seed, 1, read_block, sizeof(read_block));

		fuzz_seeds[fuzz_num_seeds].name = "read-block-pr";
		fuzz_seeds[fuzz_num_seeds].data = seed;
		fuzz_seeds[fuzz_num_seeds].len = pos;
		fuzz_num_seeds++;
	}

	/* And one command split across two reads, which is the harder case */
	if (fuzz_num_seeds < FUZZ_MAX_SEEDS) {
		seed = fuzz_seed_data[fuzz_num_seeds];
		seed[0] = 0;
		pos = fuzz_seed_record(seed, 1, write_entropy, 3);
		pos = fuzz_seed_record(seed, pos, write_entropy + 3,
				       sizeof(write_entropy) - 3);

		fuzz_seeds[fuzz_num_seeds].name = "split-command";
		fuzz_seeds[fuzz_num_seeds].data = seed;
		fuzz_seeds[fuzz_num_seeds].len = pos;
		fuzz_num_seeds++;
	}

	*num = fuzz_num_seeds;

	return fuzz_seeds;
}
