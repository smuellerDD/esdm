/*
 * Wire protocol of the Entropy Gathering Daemon (EGD)
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

#ifndef ESDM_EGD_PROTOCOL_H
#define ESDM_EGD_PROTOCOL_H

/*
 * The protocol of the Entropy Gathering Daemon (egd.pl) and its compatible
 * re-implementations (prngd, ...), as spoken by the ESDM's EGD interface and
 * by the legacy entropy consumers on the other side - libgcrypt's rndegd
 * backend, OpenSSL's RAND_egd(), ...
 *
 * It is a request / response protocol on a Unix domain stream socket. Each
 * request starts with a one byte command:
 *
 * 0x00 get entropy count	-> 4 byte big endian number of available bits
 * 0x01 read non-blocking	-> request byte follows; the answer is one byte
 *				   holding the number of delivered bytes,
 *				   followed by that many bytes
 * 0x02 read blocking		-> request byte follows; the answer is exactly
 *				   the requested number of bytes
 * 0x03 write entropy		-> 2 byte big endian entropy bit count, one
 *				   length byte and that many bytes of data;
 *				   there is no answer
 * 0x04 get PID			-> one length byte followed by the PID
 *				   rendered as a string
 *
 * As the length of a transfer is expressed in a single byte, no request can
 * ever ask for more than 255 bytes. There are no request identifiers, so
 * responses are matched to requests purely by their order on the stream, and
 * clients keep the connection open and issue an arbitrary number of commands
 * on it.
 *
 * A client reading more than 255 bytes therefore sends the commands of its
 * transfers at once and reads the answers after, rather than paying a round
 * trip per transfer. The ESDM's bulk read 0xeb below has no such limit.
 */

#define ESDM_EGD_CMD_ENTROPY_COUNT 0x00
#define ESDM_EGD_CMD_READ_NONBLOCK 0x01
#define ESDM_EGD_CMD_READ_BLOCK 0x02
#define ESDM_EGD_CMD_WRITE_ENTROPY 0x03
#define ESDM_EGD_CMD_GET_PID 0x04

/*
 * ESDM extensions
 *
 * What the EGD protocol cannot express is offered by commands of the ESDM's
 * own, far away from the standard commands above so that no EGD client ever
 * sends one by accident. A peer that does not know them - another EGD, or an
 * ESDM from before they were added - treats one as any unknown command and
 * closes the connection, which a client takes for "not supported".
 *
 * They are framed in the spirit of EGD: a command byte, fixed size arguments,
 * and an answer whose size is known from the request or announced by a length
 * prefix. All numbers are big endian, like those of EGD.
 *
 * 0xe0 PR read non-blocking	-> request byte follows; answered as 0x01, but
 *				   from the prediction resistance DRNG
 * 0xe1 PR read blocking	-> request byte follows; answered as 0x02, but
 *				   from the prediction resistance DRNG
 * 0xe2 read unseeded		-> request byte follows; answered as 0x01, but
 *				   from the DRNG without waiting for all DRNGs
 *				   to be fully seeded - the semantics of
 *				   /dev/urandom (esdm_get_random_bytes()). The
 *				   ESDM hands out nothing before it is
 *				   operational, so the answer is empty then;
 *				   otherwise it is short when the DRNG serving
 *				   it reached the most it may generate without
 *				   a full reseed on the way - in a build for
 *				   SP800-90C every 2^17 bits -, or on an
 *				   error.
 * 0xe3 get state		-> one byte holding the number of fields that
 *				   follow, each a 4 byte number, see
 *				   ESDM_EGD_STATE_*. A client takes the fields
 *				   it knows and ignores the rest, so fields are
 *				   only ever appended.
 * 0xe4 status			-> 4 byte length, at most ESDM_EGD_MAX_STATUS,
 *				   followed by the status report as text,
 *				   without a terminating NUL. A report that does
 *				   not fit is sent as far as it got.
 * 0xe5 status JSON		-> the same with the status as JSON document;
 *				   one that does not fit is not sent at all,
 *				   the length is 0 then.
 *
 * The following change the entropy accounting or the DRNGs and are therefore
 * only carried out for a privileged peer - one connected with UID 0 per
 * SO_PEERCRED, just like the entropy claim of 0x03. Each is answered with a
 * 4 byte status: 0 on success, otherwise a negative errno in two's complement,
 * -EPERM for an unprivileged peer. Refusing one keeps the connection usable.
 *
 * 0xe6 add to entropy count	-> 4 byte number of bits follows; credits them
 *				   to the auxiliary pool (RNDADDTOENTCNT)
 * 0xe7 clear pool		-> no argument; sets the entropy of the
 *				   auxiliary pool to zero (RNDZAPENTCNT,
 *				   RNDCLEARPOOL)
 * 0xe8 reseed			-> no argument; reseeds the DRNGs at their next
 *				   use (RNDRESEEDCRNG)
 * 0xe9 set write wakeup	-> 4 byte threshold in bits follows
 *				   (write_wakeup_threshold)
 * 0xea set min reseed secs	-> 4 byte number of seconds follows
 *				   (urandom_min_reseed_secs)
 *
 * Inserting data with an entropy claim needs no command of its own: 0x03 does
 * that for a privileged peer.
 *
 * Transfers beyond the 255 bytes of EGD, for every peer:
 *
 * 0xeb bulk read		-> one byte naming the non-blocking read it
 *				   stands for - 0x01, 0xe0 or 0xe2 - and a
 *				   4 byte length, at most ESDM_EGD_MAX_BULK;
 *				   answered as that read, but with a 4 byte
 *				   length
 * 0xec bulk insert		-> 4 byte length, at most ESDM_EGD_MAX_BULK,
 *				   and that many bytes, inserted into the
 *				   auxiliary pool without entropy credit;
 *				   answered with a 4 byte status as above once
 *				   all of them are in
 *
 * Any other byte naming the read of 0xeb, or a length beyond the bound, is
 * treated as an unknown command.
 *
 * A non-blocking read of the regular DRNGs is answered empty only by an ESDM
 * that is not operational: one finding them waiting for a reseed is answered
 * once it landed, or empty after a second.
 */

#define ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK 0xe0
#define ESDM_EGD_CMD_ESDM_PR_READ_BLOCK 0xe1
#define ESDM_EGD_CMD_ESDM_READ_UNSEEDED 0xe2
#define ESDM_EGD_CMD_ESDM_GET_STATE 0xe3
#define ESDM_EGD_CMD_ESDM_STATUS 0xe4
#define ESDM_EGD_CMD_ESDM_STATUS_JSON 0xe5
#define ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT 0xe6
#define ESDM_EGD_CMD_ESDM_CLEAR_POOL 0xe7
#define ESDM_EGD_CMD_ESDM_RESEED 0xe8
#define ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP 0xe9
#define ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS 0xea
#define ESDM_EGD_CMD_ESDM_BULK_READ 0xeb
#define ESDM_EGD_CMD_ESDM_BULK_INSERT 0xec

/* Fields of the answer to ESDM_EGD_CMD_ESDM_GET_STATE, in this order */
/* Flags, see ESDM_EGD_STATE_FLAG_* */
#define ESDM_EGD_STATE_FLAGS 0
/* Entropy of the auxiliary pool in bits (RNDGETENTCNT, entropy_avail) */
#define ESDM_EGD_STATE_ENT_CNT 1
/* Size of the auxiliary pool in bits (poolsize) */
#define ESDM_EGD_STATE_POOLSIZE 2
/* write_wakeup_threshold in bits */
#define ESDM_EGD_STATE_WRITE_WAKEUP 3
/* urandom_min_reseed_secs */
#define ESDM_EGD_STATE_MIN_RESEED_SECS 4
/* Number of fields this version of the protocol defines */
#define ESDM_EGD_STATE_NUM_FIELDS 5

/* The ESDM is operational: the reads of 0x01 and 0x02 are served */
#define ESDM_EGD_STATE_FLAG_OPERATIONAL (1U << 0)
/* All DRNGs are fully seeded */
#define ESDM_EGD_STATE_FLAG_FULLY_SEEDED (1U << 1)

/* Largest status report of ESDM_EGD_CMD_ESDM_STATUS and _STATUS_JSON */
#define ESDM_EGD_MAX_STATUS 65536

/* Largest transfer of ESDM_EGD_CMD_ESDM_BULK_READ and _BULK_INSERT */
#define ESDM_EGD_MAX_BULK 65536

/* The protocol's length byte caps every transfer at 255 bytes. */
#define ESDM_EGD_MAX_TRANSFER 255

/* Longest command: write entropy (command, 2 entropy bytes, length byte). */
#define ESDM_EGD_MAX_CMD_SIZE (4 + ESDM_EGD_MAX_TRANSFER)

#endif /* ESDM_EGD_PROTOCOL_H */
