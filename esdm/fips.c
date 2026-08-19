/*
 * Copyright (C) 2018 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <unistd.h>

#include "constructor.h"
#include "esdm_config.h"
#include "fips.h"
#include "fips_integrity.h"
#include "esdm_hmac.h"
#include "esdm_sha256.h"
#include "esdm_logger.h"

#define FIPS_LOGGER_PREFIX "FIPS POST: "

/*
 * An address inside this object, which is what identifies the file the ESDM was
 * loaded from - see the integrity test below.
 */
static const char fips_module_marker[] = "ESDM";

/*
 * The shared objects that make up the module next to libesdm.so: the entropy
 * source, and the library providing the cryptography where that is not the
 * built-in implementation.
 */
static const char *const fips_module_objects[] = {
#ifdef ESDM_ES_JENT
	"libjitterentropy.so",
#endif
#ifdef ESDM_OPENSSL
	"libcrypto.so",
#endif
#ifdef ESDM_GNUTLS
	"libgnutls.so",
	/* The SP800-90A CTR DRBG of that backend is nettle's */
	"libnettle.so",
#endif
#ifdef ESDM_BOTAN
	"libbotan-",
#endif
#ifdef ESDM_LEANCRYPTO
	"libleancrypto.so",
#endif
	NULL
};

static int fips_post_hmac_sha256(void)
{
	ESDM_HMAC_CTX_ON_STACK(hmac_ctx, esdm_sha256);
	static const uint8_t key[] = "\x85";
	static const uint8_t msg[] = "\xC9\x0E\x0F\x1E\x8C\xA1\xFD\x0E"
				     "\x0B\x17\xE4\xFA\xC4\xB6\xAA\x73";
	static const char mac[] = "\xff\xd9\xd4\x56\xf0\xea\x5f\x9f"
				  "\x6e\x69\xf6\x05\xe4\x66\xc3\x8c"
				  "\x9f\x77\x4a\x37\x1c\xb0\xd4\xfb"
				  "\x78\x2d\xca\xbb\x1c\x25\x20\x4b";
	uint8_t calculated[ESDM_SHA_MAX_SIZE_DIGEST];
	int ret;

	ret = esdm_hmac_init(hmac_ctx, key, sizeof(key) - 1);
	if (ret)
		goto out;
	esdm_hmac_update(hmac_ctx, msg, sizeof(msg) - 1);
	esdm_hmac_final(hmac_ctx, calculated);

	if (esdm_hmac_macsize(hmac_ctx) != sizeof(mac) - 1) {
		fprintf(stderr, FIPS_LOGGER_PREFIX
			"Calculated MAC length has unexpected length\n");
		ret = -EINVAL;
		goto out;
	}

	if (memcmp(calculated, mac, esdm_hmac_macsize(hmac_ctx))) {
		fprintf(stderr, FIPS_LOGGER_PREFIX "Message mismatch\n");
		ret = -EBADMSG;
		goto out;
	}

	ret = 0;

out:
	esdm_hmac_zero(hmac_ctx);
	return ret;
}

static void fips_post_objects(void)
{
	unsigned int i;

	for (i = 0; fips_module_objects[i]; i++) {
		int ret = fips_post_integrity_loaded(fips_module_objects[i]);

		if (ret < 0)
			exit(-ret);

		/* Nothing of that name is loaded. */
		if (!ret) {
			fprintf(stderr,
				FIPS_LOGGER_PREFIX
				"%s* is not loaded as a shared object - it is covered only where it is linked into an attested file\n",
				fips_module_objects[i]);
		}
	}
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

	/* The executable ... */
	ret = fips_post_integrity(NULL);
	if (ret)
		exit(-ret);

	/* ... and the ESDM itself. */
	ret = fips_post_integrity_obj(fips_module_marker);
	if (ret)
		exit(-ret);

	/* ... and the libraries it was built against, where they are loaded */
	fips_post_objects();
}

bool fips_enabled(void)
{
	static char fipsflag[1] = { 'A' };
	size_t n = 0;

	if (fipsflag[0] == 'A') {
#ifdef HAVE_SECURE_GETENV
		if (secure_getenv("ESDM_SERVER_FORCE_FIPS")) {
#else
		/*
		 * Without secure_getenv, only trust the environment
		 * if not running with elevated privileges.
		 */
		if (getuid() == geteuid() && getgid() == getegid() &&
		    getenv("ESDM_SERVER_FORCE_FIPS")) {
#endif
			fipsflag[0] = '1';
		} else {
			FILE *fipsfile = NULL;

			fipsfile = fopen("/proc/sys/crypto/fips_enabled", "r");
			if (!fipsfile) {
				if (errno == ENOENT) {
					/* FIPS support not enabled in kernel */
					fipsflag[0] = '0';
					return 0;
				} else {
					esdm_logger(
						LOGGER_ERR, LOGGER_C_ANY,
						"FIPS: Cannot open fips_enabled file: %s\n",
						strerror(errno));
					return false;
				}
			}

			n = fread((void *)fipsflag, 1, 1, fipsfile);
			fclose(fipsfile);
			if (n != 1) {
				esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
					    "FIPS: Cannot read FIPS flag\n");
				return false;
			}
		}
	}

	return (fipsflag[0] == '1');
}
