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
 */

#define ESDM_EGD_CMD_ENTROPY_COUNT 0x00
#define ESDM_EGD_CMD_READ_NONBLOCK 0x01
#define ESDM_EGD_CMD_READ_BLOCK 0x02
#define ESDM_EGD_CMD_WRITE_ENTROPY 0x03
#define ESDM_EGD_CMD_GET_PID 0x04

/* The protocol's length byte caps every transfer at 255 bytes. */
#define ESDM_EGD_MAX_TRANSFER 255

/* Longest command: write entropy (command, 2 entropy bytes, length byte). */
#define ESDM_EGD_MAX_CMD_SIZE (4 + ESDM_EGD_MAX_TRANSFER)

#endif /* ESDM_EGD_PROTOCOL_H */
