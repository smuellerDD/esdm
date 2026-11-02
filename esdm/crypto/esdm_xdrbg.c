/*
 * XDRBG-256 of the entropy pools
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

/*
 * The kernel module esdm_es compiles this file, with the environment
 * esdm_portable.h provides there.
 */
#include "esdm_portable.h"
#include "esdm_xdrbg.h"
#include "selftest_kat.h"

int esdm_xdrbg_alloc(struct esdm_xdrbg *xdrbg)
{
	xdrbg->xof_cb = esdm_default_xof_cb;
	xdrbg->xof = NULL;
	xdrbg->started = false;
	xdrbg->instantiated = false;
	return xdrbg->xof_cb->xof_alloc(&xdrbg->xof);
}

void esdm_xdrbg_free(struct esdm_xdrbg *xdrbg)
{
	if (xdrbg->xof && xdrbg->xof_cb)
		xdrbg->xof_cb->xof_dealloc(xdrbg->xof);
	xdrbg->xof = NULL;
	esdm_xdrbg_discard(xdrbg);
}

void esdm_xdrbg_discard(struct esdm_xdrbg *xdrbg)
{
	/* What the context absorbed is wiped as it is started again */
	xdrbg->started = false;
	xdrbg->instantiated = false;
}

int esdm_xdrbg_start(struct esdm_xdrbg *xdrbg)
{
	int ret;

	if (xdrbg->started)
		return 0;

	/* Never allocated or released already: nothing to start */
	if (!xdrbg->xof)
		return -EOPNOTSUPP;

	CKINT(xdrbg->xof_cb->xof_init(xdrbg->xof));
	xdrbg->instantiated = false;
	xdrbg->started = true;

out:
	return ret;
}

int esdm_xdrbg_insert(struct esdm_xdrbg *xdrbg, const uint8_t *in, size_t inlen)
{
	int ret;

	CKINT(esdm_xdrbg_start(xdrbg));
	ret = xdrbg->xof_cb->xof_update(xdrbg->xof, in, inlen);

	/* The XOF may have absorbed part of the data: no torn state goes on */
	if (ret)
		esdm_xdrbg_discard(xdrbg);

out:
	return ret;
}

/* Absorb encode(alpha, n) */
static int esdm_xdrbg_encode(const struct esdm_xof_cb *xof_cb, void *xof,
			     const uint8_t *alpha, size_t alphalen, uint8_t n)
{
	uint8_t encode = (uint8_t)(n * 85 + alphalen);
	int ret;

	CKINT(xof_cb->xof_update(xof, alpha, alphalen));
	CKINT(xof_cb->xof_update(xof, &encode, sizeof(encode)));

out:
	return ret;
}

int esdm_xdrbg_extract(struct esdm_xdrbg *xdrbg, const uint8_t *alpha,
		       size_t alphalen, uint8_t *out, size_t outlen)
{
	const struct esdm_xof_cb *xof_cb = xdrbg->xof_cb;
	uint8_t v[ESDM_XDRBG_V_SIZE + ESDM_XDRBG_MAX_OUT];
	void *xof = xdrbg->xof;
	int ret;

	if (!xdrbg->started || outlen > ESDM_XDRBG_MAX_OUT ||
	    alphalen > ESDM_XDRBG_MAX_ALPHA)
		return -EINVAL;

	/* Reseed, or instantiate */
	CKINT(esdm_xdrbg_encode(xof_cb, xof, alpha, alphalen,
				xdrbg->instantiated ? 1 : 0));
	CKINT(xof_cb->xof_final(xof, v, ESDM_XDRBG_V_SIZE));
	xdrbg->instantiated = true;

	/* Generate */
	CKINT(xof_cb->xof_init(xof));
	CKINT(xof_cb->xof_update(xof, v, ESDM_XDRBG_V_SIZE));
	CKINT(esdm_xdrbg_encode(xof_cb, xof, alpha, alphalen, 2));
	CKINT(xof_cb->xof_final(xof, v, ESDM_XDRBG_V_SIZE + outlen));

	/* The next reseed starts with the new V */
	CKINT(xof_cb->xof_init(xof));
	CKINT(xof_cb->xof_update(xof, v, ESDM_XDRBG_V_SIZE));

	memcpy(out, v + ESDM_XDRBG_V_SIZE, outlen);

out:
	if (ret)
		esdm_xdrbg_discard(xdrbg);
	memset_secure(v, 0, sizeof(v));
	return ret;
}

/*
 * Known-answer test of the XDRBG-256, the self test of its SHAKE256 as well:
 * instantiate from the bytes 0x00 ... 0x3f and generate, reseed from 0x40 ...
 * 0x7f and generate, all with the alpha of auxiliary pool 0. The known answer
 * is XDRBG-256 as specified, computed independently of the ESDM.
 */
#define ESDM_XDRBG_KAT_LEN 32

int esdm_xdrbg_selftest(void)
{
	/* "ESDM aux pool" and the index 0 as two bytes */
	static const char alpha[] = "ESDM aux pool\0";
	static const uint8_t exp1[] = {
		0xa6, 0x72, 0xf6, 0xb2, 0x42, 0x5b, 0x61, 0xb0,
		0xa3, 0xfe, 0xad, 0x10, 0x1c, 0x71, 0xbc, 0x1e,
		0x2b, 0xef, 0x4c, 0xf6, 0x43, 0xf0, 0xa8, 0xf5,
		0x27, 0x5e, 0x64, 0xaa, 0x66, 0xf1, 0x95, 0x71,
	};
	static const uint8_t exp2[] = {
		0x28, 0x38, 0x6c, 0x23, 0x92, 0xb8, 0xd1, 0x1f,
		0x17, 0xa3, 0x19, 0x95, 0x5c, 0x7b, 0x72, 0x2d,
		0x9f, 0x82, 0xf6, 0x92, 0xc7, 0xe3, 0x1b, 0x78,
		0xae, 0x36, 0xab, 0x87, 0xd2, 0xc6, 0xe7, 0x57,
	};
	struct esdm_xdrbg xdrbg;
	uint8_t seed[2 * ESDM_XDRBG_V_SIZE];
	uint8_t act[ESDM_XDRBG_KAT_LEN];
	unsigned int i;
	int ret;

	BUILD_BUG_ON(sizeof(exp1) != ESDM_XDRBG_KAT_LEN ||
		     sizeof(exp2) != ESDM_XDRBG_KAT_LEN);
	BUILD_BUG_ON(ESDM_XDRBG_KAT_LEN > ESDM_XDRBG_MAX_OUT);
	BUILD_BUG_ON(sizeof(alpha) != 15);

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;

	CKINT(esdm_xdrbg_alloc(&xdrbg));

	for (i = 0; i < 2; i++) {
		/* A seed off by its first byte must not produce that output */
		if (i)
			seed[0] ^= 0x01;

		esdm_xdrbg_discard(&xdrbg);
		CKINT(esdm_xdrbg_insert(&xdrbg, seed, ESDM_XDRBG_V_SIZE));
		CKINT(esdm_xdrbg_extract(&xdrbg, (const uint8_t *)alpha,
					 sizeof(alpha), act, sizeof(act)));
		if (i) {
			CKINT(esdm_kat_check_differs(act, exp1, sizeof(exp1)));
			break;
		}
		CKINT(esdm_kat_check(act, exp1, sizeof(exp1)));

		CKINT(esdm_xdrbg_insert(&xdrbg, seed + ESDM_XDRBG_V_SIZE,
					ESDM_XDRBG_V_SIZE));
		CKINT(esdm_xdrbg_extract(&xdrbg, (const uint8_t *)alpha,
					 sizeof(alpha), act, sizeof(act)));
		CKINT(esdm_kat_check(act, exp2, sizeof(exp2)));
	}

out:
	esdm_xdrbg_free(&xdrbg);
	memset_secure(act, 0, sizeof(act));
	return ret;
}
