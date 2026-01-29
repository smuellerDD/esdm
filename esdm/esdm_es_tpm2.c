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
 * ESDM Fast Entropy Source: Linux jitter-based entropy source
 *
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "bitshift.h"
#include "conv_be_le.h"
#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_tpm2.h"
#include "helper.h"
#include "mutex.h"

static int tpm2_fd = -1;
static DEFINE_MUTEX_UNLOCKED(tpm2_mutex);

/* return code */
typedef uint32_t TPM2_RC;
/* command code */
typedef uint32_t TPM2_CC;
/* session type */
typedef uint16_t TPM2_ST;

static const TPM2_ST TPM2_ST_NO_SESSIONS = 0x8001;

static const TPM2_CC TPM2_CC_STIR_RANDOM = 0x00000146;
static const TPM2_CC TPM2_CC_GET_RANDOM = 0x0000017B;

static const TPM2_RC TPM2_RC_SUCCESS = 0x00000000;
static const TPM2_RC TPM2_RC_RETRY   = 0x00000922;
static const TPM2_RC TPM2_RC_TESTING = 0x0000090A;
static const TPM2_RC TPM2_RC_YIELDED = 0x00000908;

struct TPM2CommandHeader {
	TPM2_ST tag;
	uint32_t commandSize;
	TPM2_CC commandCode;
} __attribute((__packed__));

struct TPM2ResponseHeader {
	TPM2_ST tag;
	uint32_t responseSize;
	TPM2_RC responseCode;
} __attribute((__packed__));

static int esdm_es_tpm2_transceive(struct TPM2CommandHeader *cmd,
				   uint8_t *cmd_buffer, uint32_t cmd_buffer_len,
				   struct TPM2ResponseHeader *rsp,
				   uint8_t *rsp_buffer, uint32_t rsp_buffer_len)
{
	static uint8_t buf[256] = { 0 };
	static const int max_retries = 5;
	int retries = 0;
	bool should_retry = false;
	int ret = 0;

	be16_to_ptr((uint8_t *)&cmd->tag, cmd->tag);
	be32_to_ptr((uint8_t *)&cmd->commandSize, cmd->commandSize);
	be32_to_ptr((uint8_t *)&cmd->commandCode, cmd->commandCode);

	do {
		retries++;
		memcpy(buf, cmd, sizeof(struct TPM2CommandHeader));
		memcpy(buf + sizeof(struct TPM2CommandHeader), cmd_buffer,
		cmd_buffer_len);

		if (esdm_safe_write(tpm2_fd, buf,
				sizeof(struct TPM2CommandHeader) +
					cmd_buffer_len)) {
			esdm_logger(LOGGER_WARN, LOGGER_C_ES,
				"TPM 2.0 command write failed\n");
			close(tpm2_fd);
			tpm2_fd = -1;
			ret = -1;
			goto out;
		}

		if (esdm_safe_read(tpm2_fd, buf,
				sizeof(struct TPM2ResponseHeader) +
					rsp_buffer_len)) {
			esdm_logger(LOGGER_WARN, LOGGER_C_ES,
				"TPM 2.0 response read failed\n");
			close(tpm2_fd);
			tpm2_fd = -1;
			ret = -1;
			goto out;
		}

		memcpy(rsp, buf, sizeof(struct TPM2ResponseHeader));
		rsp->tag = ptr_to_be16((uint8_t *)&rsp->tag);
		rsp->responseSize = ptr_to_be32((uint8_t *)&rsp->responseSize);
		rsp->responseCode = ptr_to_be32((uint8_t *)&rsp->responseCode);
		memcpy(rsp_buffer, buf + sizeof(struct TPM2ResponseHeader),
		min_size(rsp->responseSize, rsp_buffer_len));

		should_retry = rsp->responseCode == TPM2_RC_RETRY ||
			       rsp->responseCode == TPM2_RC_YIELDED ||
			       rsp->responseCode == TPM2_RC_TESTING;
	} while(should_retry && retries < max_retries);

out:
	memset_secure(buf, 0, sizeof(buf));
	return ret;
}

static void esdm_es_tpm2_finalize_locked(void)
{
	if (tpm2_fd < 0)
		return;

	close(tpm2_fd);
	tpm2_fd = -1;
}

static void esdm_es_tpm2_finalize(void)
{
	mutex_lock(&tpm2_mutex);
	esdm_es_tpm2_finalize_locked();
	mutex_unlock(&tpm2_mutex);
}

static int esdm_es_tpm2_init(void)
{
	int ret;

	mutex_lock(&tpm2_mutex);

	/* Allow the init function to be called multiple times */
	esdm_es_tpm2_finalize_locked();

	ret = open("/dev/tpmrm0", O_RDWR | O_CLOEXEC);
	if (ret < 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling TPM 2.0 entropy source as it is not present, error: %s\n",
			strerror(errno));
	} else {
		tpm2_fd = ret;
	}

	mutex_unlock(&tpm2_mutex);

	return 0;
}

static uint32_t esdm_es_tpm2_entropylevel(uint32_t requested_bits)
{
	if (tpm2_fd < 0)
		return 0;

	return esdm_fast_noise_entropylevel(esdm_config_es_tpm2_entropy_rate(),
					    requested_bits);
}

static uint32_t esdm_es_tpm2_poolsize(void)
{
	if (tpm2_fd < 0)
		return 0;

	return esdm_es_tpm2_entropylevel(esdm_security_strength());
}

static int esdm_es_tpm2_get_internal(uint8_t *buf, uint32_t len)
{
	uint8_t stir_buf[32 + 2] = { 0 };
	struct TPM2CommandHeader stirrandom_cmd = {
		.tag = TPM2_ST_NO_SESSIONS,
		.commandSize =
			sizeof(struct TPM2CommandHeader) + sizeof(stir_buf),
		.commandCode = TPM2_CC_STIR_RANDOM
	};
	struct TPM2ResponseHeader stirrandom_rsp;
	struct TPM2CommandHeader getrandom_cmd = {
		.tag = TPM2_ST_NO_SESSIONS,
		.commandSize =
			sizeof(struct TPM2CommandHeader) + sizeof(uint16_t),
		.commandCode = TPM2_CC_GET_RANDOM
	};
	uint16_t bytes_requested = be_bswap16(len);
	uint8_t resp_buf[256 + 2];
	struct TPM2ResponseHeader getrandom_rsp;
	uint16_t bytes_returned = 0;

	if (len > 32)
		return -1;

	/* stir buffer size */
	be16_to_ptr(stir_buf, 32);
	arc4random_buf(stir_buf + 2, sizeof(stir_buf) - 2);
	esdm_es_tpm2_transceive(&stirrandom_cmd, (uint8_t *)stir_buf,
				sizeof(stir_buf), &stirrandom_rsp, NULL, 0);

	if (stirrandom_rsp.responseCode != TPM2_RC_SUCCESS ||
	    stirrandom_rsp.responseSize != sizeof(struct TPM2ResponseHeader)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 stir random failed: %u\n",
			    stirrandom_rsp.responseCode);
		return -1;
	}

	esdm_es_tpm2_transceive(&getrandom_cmd, (uint8_t *)&bytes_requested,
				sizeof(bytes_requested), &getrandom_rsp,
				resp_buf, len + 2);
	if (getrandom_rsp.responseCode != TPM2_RC_SUCCESS ||
	    getrandom_rsp.responseSize != sizeof(struct TPM2ResponseHeader) +
						  sizeof(uint16_t) + len) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 get random failed. RC: 0x%04x Len: %u\n",
			    getrandom_rsp.responseCode,
			    getrandom_rsp.responseSize);
		return -1;
	}
	bytes_returned = ptr_to_be16(resp_buf);
	if (bytes_returned != len) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 returned less bytes than expected %u\n",
			    bytes_returned);
		return -1;
	}

	memcpy(buf, resp_buf + 2, len);
	memset_secure(resp_buf, 0, sizeof(resp_buf));

	return 0;
}

static void esdm_es_tpm2_get(struct entropy_es *eb_es, uint32_t requested_bits,
			     bool __unused unsused)
{
	static const size_t tpm2_guaranteed_read_len = 32;
	uint8_t buffer[tpm2_guaranteed_read_len];
	uint32_t done_bits = 0;

	mutex_reader_lock(&tpm2_mutex);

	if (tpm2_fd < 0)
		goto err;

	do {
		uint32_t chunk_size_bits =
			min_uint32(tpm2_guaranteed_read_len * 8,
				   requested_bits - done_bits);
		if (esdm_es_tpm2_get_internal(buffer, tpm2_guaranteed_read_len))
			goto err;
		done_bits += chunk_size_bits;
		memcpy(eb_es->e + (done_bits >> 3), buffer,
		       (chunk_size_bits >> 3));
	} while (done_bits < requested_bits);

	eb_es->e_bits = esdm_es_tpm2_entropylevel(requested_bits);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from TPM 2.0 entropy source\n",
		    eb_es->e_bits);

	mutex_reader_unlock(&tpm2_mutex);

	return;

err:
	mutex_reader_unlock(&tpm2_mutex);
	eb_es->e_bits = 0;
}

static void esdm_es_tpm2_es_state(char *buf, size_t buflen)
{
	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n",
		 esdm_es_tpm2_poolsize(), esdm_es_tpm2_entropylevel(256));
}

static bool esdm_es_tpm2_active(void)
{
	return tpm2_fd >= 0;
}

struct esdm_es_cb esdm_es_tpm2 = {
	.name = "TPM2.0",
	.init = esdm_es_tpm2_init,
	.fini = esdm_es_tpm2_finalize,
	.monitor_es = NULL,
	.get_ent = esdm_es_tpm2_get,
	.curr_entropy = esdm_es_tpm2_entropylevel,
	.max_entropy = esdm_es_tpm2_poolsize,
	.state = esdm_es_tpm2_es_state,
	.reset = NULL,
	.active = esdm_es_tpm2_active,
	.switch_hash = NULL,
};
