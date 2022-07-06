/*
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constructor.h"
#include "esdm_config.h"
#include "fips.h"
#include "lc_hmac.h"
#include "lc_sha256.h"
#include "logger.h"

#define FIPS_LOGGER_PREFIX "FIPS POST: "

static int fips_post_hmac_sha256(void)
{
	LC_HMAC_CTX_ON_STACK(hmac_ctx, lc_sha256);
	static const uint8_t key[] = "\x85";
	static const uint8_t msg[] = "\xC9\x0E\x0F\x1E\x8C\xA1\xFD\x0E"
				     "\x0B\x17\xE4\xFA\xC4\xB6\xAA\x73";
	static const char mac[] = "\xff\xd9\xd4\x56\xf0\xea\x5f\x9f"
				  "\x6e\x69\xf6\x05\xe4\x66\xc3\x8c"
				  "\x9f\x77\x4a\x37\x1c\xb0\xd4\xfb"
				  "\x78\x2d\xca\xbb\x1c\x25\x20\x4b";
	uint8_t calculated[LC_SHA_MAX_SIZE_DIGEST];
	int ret;

	lc_hmac_init(hmac_ctx, key, sizeof(key) - 1);
	lc_hmac_update(hmac_ctx, msg, sizeof(msg) - 1);
	lc_hmac_final(hmac_ctx, calculated);

	if (lc_hmac_macsize(hmac_ctx) != sizeof(mac) - 1) {
		fprintf(stderr, FIPS_LOGGER_PREFIX
			"Calculated MAC length has unexpected length\n");
		ret = -EINVAL;
		goto out;
	}

	if (memcmp(calculated, mac, lc_hmac_macsize(hmac_ctx))) {
		fprintf(stderr, FIPS_LOGGER_PREFIX "Message mismatch\n");
		ret = -EBADMSG;
		goto out;
	}

	ret = 0;

out:
	lc_hmac_zero(hmac_ctx);
	return ret;
}

ESDM_DEFINE_CONSTRUCTOR(fips_post);
static void fips_post(void)
{
	int ret;

	if (!esdm_config_fips_enabled())
		return;

	ret = fips_post_hmac_sha256();
	if (ret)
		exit(-ret);

	ret = fips_post_integrity(NULL);
	if (ret)
		exit(-ret);
}

bool fips_enabled(void)
{
	static char fipsflag[1] = { 'A' };
	size_t n = 0;

	if (fipsflag[0] == 'A') {
#ifdef HAVE_SECURE_GETENV
		if (secure_getenv("ESDM_SERVER_FORCE_FIPS")) {
#else
		if (getenv("ESDM_SERVER_FORCE_FIPS")) {
#endif
			fipsflag[0] = '1';
		} else {
			FILE *fipsfile = NULL;

			fipsfile = fopen("/proc/sys/crypto/fips_enabled", "r");
			if (!fipsfile) {
				if (errno == ENOENT) {
					/* FIPS support not enabled in kernel */
					return 0;
				} else {
					logger(LOGGER_ERR, LOGGER_C_ANY,
						"FIPS: Cannot open fips_enabled file: %s\n",
						strerror(errno));
					return -EIO;
				}
			}

			n = fread((void *)fipsflag, 1, 1, fipsfile);
			fclose(fipsfile);
			if (n != 1) {
				logger(LOGGER_ERR, LOGGER_C_ANY,
				       "FIPS: Cannot read FIPS flag\n");
				return false;
			}
		}
	}

	return (fipsflag[0] == '1');
}
