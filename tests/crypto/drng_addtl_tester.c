/*
 * The DRNG of the crypto backend takes the additional input of a seed whole
 *
 * The DRNG manager passes the uncredited entropy source output, a struct
 * entropy_buf, as additional input. Seeds differing only in its last byte must
 * give different output, at instantiation and reseed. leancrypto's XDRBG cut
 * it to 84 bytes, the OpenSSL backend dropped it from each reseed.
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esdm_crypto.h"
#include "esdm_drng_mgr.h"

/* Longer than any limit a DRNG puts on its additional input */
#define ADDTL_TEST_LEN 1024
#define ADDTL_TEST_SEED 64
#define ADDTL_TEST_OUT 32

/* Instantiate a DRNG, reseed it unless @reseed is NULL, and generate */
static int drng_out(const uint8_t *inst, const uint8_t *reseed, uint8_t *out)
{
	const struct esdm_drng_cb *cb = esdm_default_drng_cb;
	uint8_t seed[ADDTL_TEST_SEED];
	void *drng = NULL;
	int ret;

	memset(seed, 0x5a, sizeof(seed));

	ret = cb->drng_alloc(&drng, ESDM_DRNG_SECURITY_STRENGTH_BYTES);
	if (ret)
		return ret;

	ret = cb->drng_seed(drng, seed, sizeof(seed), inst, ADDTL_TEST_LEN);
	if (ret >= 0 && reseed)
		ret = cb->drng_seed(drng, seed, sizeof(seed), reseed,
				    ADDTL_TEST_LEN);
	if (ret >= 0 &&
	    cb->drng_generate(drng, out, ADDTL_TEST_OUT) != ADDTL_TEST_OUT)
		ret = -EFAULT;

	cb->drng_dealloc(drng);
	return ret < 0 ? ret : 0;
}

int main(int argc, char *argv[])
{
	static uint8_t a[ADDTL_TEST_LEN], b[ADDTL_TEST_LEN];
	uint8_t out_a[ADDTL_TEST_OUT], out_b[ADDTL_TEST_OUT];
	int ret = 0;

	(void)argc;
	(void)argv;

	/* Their generate mixes in a time stamp: no output repeats */
#if (defined(ESDM_OPENSSL) && defined(ESDM_OPENSSL_DRNG_HMAC)) ||              \
	(defined(ESDM_BOTAN) && defined(ESDM_BOTAN_DRNG_HMAC))
	printf("DRNG additional input: the DRNG output is not reproducible\n");
	return 77;
#endif

	memset(a, 0xa5, sizeof(a));
	memcpy(b, a, sizeof(b));
	b[sizeof(b) - 1] ^= 0x01;

	/* The same seeds give the same output, else the rest proves nothing */
	if (drng_out(a, a, out_a) || drng_out(a, a, out_b) ||
	    memcmp(out_a, out_b, sizeof(out_a))) {
		printf("DRNG additional input: the DRNG output is not reproducible\n");
		return 1;
	}

	if (drng_out(a, NULL, out_a) || drng_out(b, NULL, out_b) ||
	    !memcmp(out_a, out_b, sizeof(out_a))) {
		printf("DRNG additional input: the instantiation drops the end of it\n");
		ret = 1;
	}

	if (drng_out(a, a, out_a) || drng_out(a, b, out_b) ||
	    !memcmp(out_a, out_b, sizeof(out_a))) {
		printf("DRNG additional input: the reseed drops the end of it\n");
		ret = 1;
	}

	if (!ret)
		printf("DRNG additional input: passed\n");

	return ret;
}
