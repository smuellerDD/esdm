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
 * A PKCS#11 module for the tests of esdm-es-pkcs11, in front of a real one -
 * SoftHSM, $ESDM_PKCS11_SHIM_MODULE - passing everything on to it, but:
 *
 * - C_Login is written to stderr, the log of the daemon, with its result:
 *   SoftHSM counts no PIN retries, so this tells a PIN tried again.
 * - C_GenerateRandom fails with CKR_DEVICE_ERROR while the file "fail" exists
 *   in the working directory, as a token pulled mid-request does, and hands
 *   out the same bytes every time while "repeat" does, as a broken noise
 *   source does.
 *
 * The PKCS#11 types are spelled out rather than taken from a pkcs11.h, which
 * no dependency of the ESDM installs: the function list of PKCS#11 2.40 is a
 * version followed by the 68 functions, found in it by the addresses the real
 * module exports them under rather than by their position.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef void (*ck_fn)(void);

#define CKR_GENERAL_ERROR 0x05UL
#define CKR_DEVICE_ERROR 0x30UL
#define CK_FUNCTIONS 68

struct ck_function_list {
	CK_BYTE version[2];
	ck_fn fn[CK_FUNCTIONS];
};

typedef CK_RV (*ck_get_function_list)(struct ck_function_list **list);
typedef CK_RV (*ck_login)(CK_ULONG session, CK_ULONG user, CK_BYTE *pin,
			  CK_ULONG pin_len);
typedef CK_RV (*ck_generate_random)(CK_ULONG session, CK_BYTE *data,
				    CK_ULONG len);

static struct ck_function_list shim_list;
static ck_login real_login;
static ck_generate_random real_generate_random;

static CK_RV shim_login(CK_ULONG session, CK_ULONG user, CK_BYTE *pin,
			CK_ULONG pin_len)
{
	CK_RV rv = real_login(session, user, pin, pin_len);

	fprintf(stderr, "C_Login user %lu rv 0x%lx\n", user, rv);
	return rv;
}

static CK_RV shim_generate_random(CK_ULONG session, CK_BYTE *data, CK_ULONG len)
{
	if (!access("fail", F_OK))
		return CKR_DEVICE_ERROR;
	if (!access("repeat", F_OK)) {
		memset(data, 0x5a, len);
		return 0;
	}
	return real_generate_random(session, data, len);
}

/* The function @name of @handle, NULL if there is none */
static ck_fn shim_sym(void *handle, const char *name)
{
	void *sym = dlsym(handle, name);
	ck_fn fn;

	/* An object pointer is no function pointer to ISO C */
	memcpy(&fn, &sym, sizeof(fn));
	return sym ? fn : NULL;
}

/* Replace the function at @real in the list by @shim, false if it is none */
static int shim_replace(ck_fn real, ck_fn shim)
{
	unsigned int i;

	for (i = 0; i < CK_FUNCTIONS; i++) {
		if (shim_list.fn[i] == real) {
			shim_list.fn[i] = shim;
			return 1;
		}
	}
	return 0;
}

/* What the module exports, all libp11 looks for in it */
__attribute__((visibility("default"))) CK_RV
C_GetFunctionList(struct ck_function_list **list);

CK_RV C_GetFunctionList(struct ck_function_list **list)
{
	const char *module = getenv("ESDM_PKCS11_SHIM_MODULE");
	struct ck_function_list *real;
	ck_fn get, login, generate;
	void *handle;

	/* Never unloaded: the list handed out points into it */
	handle = list && module ? dlopen(module, RTLD_NOW | RTLD_LOCAL) : NULL;
	if (!handle)
		return CKR_GENERAL_ERROR;

	get = shim_sym(handle, "C_GetFunctionList");
	login = shim_sym(handle, "C_Login");
	generate = shim_sym(handle, "C_GenerateRandom");
	if (!get || !login || !generate || ((ck_get_function_list)get)(&real) ||
	    !real)
		return CKR_GENERAL_ERROR;

	memcpy(&shim_list, real, sizeof(shim_list));
	real_login = (ck_login)login;
	real_generate_random = (ck_generate_random)generate;
	if (!shim_replace(login, (ck_fn)shim_login) ||
	    !shim_replace(generate, (ck_fn)shim_generate_random))
		return CKR_GENERAL_ERROR;

	*list = &shim_list;
	return 0;
}
