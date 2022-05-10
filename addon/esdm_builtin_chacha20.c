/*
 * Backend for the ESDM providing a ChaCha20-based DRNG
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include "esdm_crypto.h"
#include "builtin/chacha20_drng.h"
#include "esdm_builtin_chacha20.h"
#include "logger.h"

static int esdm_chacha20_seed_helper(void *drng, const uint8_t *inbuf,
				     size_t inbuflen)
{
	struct chacha20_drng *cc20 = (struct chacha20_drng *)drng;

	return drng_chacha20_reseed(cc20, inbuf, inbuflen);
}

static int esdm_chacha20_generate_helper(void *drng, uint8_t *outbuf,
					 size_t outbuflen)
{
	struct chacha20_drng *cc20 = (struct chacha20_drng *)drng;
	int ret = drng_chacha20_get(cc20, outbuf, outbuflen);

	if (ret < 0)
		return ret;

	return (int)outbuflen;
}

static int esdm_chacha20_alloc(void **drng, uint32_t sec_strength)
{
	struct chacha20_drng **cc20 = (struct chacha20_drng **)drng;

	if (sec_strength > CHACHA20_KEY_SIZE) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Security strength of ChaCha20 DRNG (%u bits) lower than requested by ESDM (%u bits)\n",
		       CHACHA20_KEY_SIZE * 8, sec_strength * 8);
		return -EINVAL;
	}
	if (sec_strength < CHACHA20_KEY_SIZE)
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Security strength of ChaCha20 DRNG (%u bits) higher than requested by ESDM (%u bits)\n",
		       CHACHA20_KEY_SIZE * 8, sec_strength * 8);

	return drng_chacha20_init(cc20);
}

static void esdm_chacha20_dealloc(void *drng)
{
	struct chacha20_drng *cc20 = (struct chacha20_drng *)drng;

	drng_chacha20_destroy(cc20);
	logger(LOGGER_VERBOSE, LOGGER_C_ANY,
	       "ChaCha20 core zeroized and freed\n");
}

static const char *esdm_chacha20_name(void)
{
	return "builtin ChaCha20 DRNG";
}

const struct esdm_drng_cb esdm_builtin_chacha20_cb = {
	.drng_name	= esdm_chacha20_name,
	.drng_selftest	= drng_chacha20_drng_selftest,
	.drng_alloc	= esdm_chacha20_alloc,
	.drng_dealloc	= esdm_chacha20_dealloc,
	.drng_seed	= esdm_chacha20_seed_helper,
	.drng_generate	= esdm_chacha20_generate_helper,
};
