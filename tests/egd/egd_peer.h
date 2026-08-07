/*
 * Test peer speaking the EGD wire protocol
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

#ifndef EGD_PEER_H
#define EGD_PEER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A peer for the EGD client tests: it speaks the protocol of
 * esdm_egd_protocol.h on a Unix domain socket of its own, which the esdm-server
 * cannot stand in for here. What is under test is how the client behaves when
 * the other side answers in ways a correct server never would - a short
 * answer, more data than was asked for, a connection that goes away mid
 * stream - and the answers have to be deterministic for the client's framing
 * to be checkable at all.
 */
enum egd_peer_mode {
	/* Serve every command as the protocol prescribes. */
	EGD_PEER_NORMAL,

	/* Accept, then never answer anything: for the timeout paths. */
	EGD_PEER_SILENT,

	/*
	 * Answer a non-blocking read with fewer bytes than requested, which is
	 * what a server that is not operational yet legitimately does.
	 */
	EGD_PEER_SHORT,

	/*
	 * Answer a non-blocking read with more bytes than requested, which no
	 * server speaking this protocol may do.
	 */
	EGD_PEER_OVERLONG,

	/*
	 * Drop the first connection right after it was accepted and serve
	 * every later one normally - a daemon restarted between two requests.
	 */
	EGD_PEER_HANGUP,
};

/* What the peer answers an entropy count command with. */
#define EGD_PEER_ENTROPY_BITS 0x01020304u

/* What it answers a PID request with. */
#define EGD_PEER_PID 4711

struct egd_peer;

/**
 * @brief Start a peer listening on @path
 *
 * @return 0 on success, < 0 on error
 */
int egd_peer_start(struct egd_peer **peer, const char *path,
		   enum egd_peer_mode mode);

/**
 * @brief Stop the peer, release it and unlink its socket
 */
void egd_peer_stop(struct egd_peer *peer);

/**
 * @brief Number of connections the peer has accepted so far
 */
unsigned int egd_peer_connections(struct egd_peer *peer);

/**
 * @brief Number of requests the peer has received so far
 *
 * Counted when the command arrives rather than when its answer goes out, so a
 * client that has its answer has necessarily been counted already.
 */
unsigned int egd_peer_requests(struct egd_peer *peer);

/**
 * @brief The data of the last write entropy command received
 *
 * @param [out] buf Buffer for the data, at most @buflen bytes are copied
 * @param [out] len Length of the data
 * @param [out] entropy_bits Entropy claim that came with it
 *
 * @return the number of write commands received so far
 */
unsigned int egd_peer_last_write(struct egd_peer *peer, uint8_t *buf,
				 size_t buflen, size_t *len,
				 uint32_t *entropy_bits);

/**
 * @brief The byte a read command is answered with at offset @offset
 *
 * The peer answers reads with a counter rather than a constant, so that a
 * request the client had to split into several protocol transfers can be
 * checked to have been reassembled completely and in order. The offset counts
 * from the first byte the peer delivered on that connection.
 */
static inline uint8_t egd_peer_data_byte(size_t offset)
{
	return (uint8_t)offset;
}

#ifdef __cplusplus
}
#endif

#endif /* EGD_PEER_H */
