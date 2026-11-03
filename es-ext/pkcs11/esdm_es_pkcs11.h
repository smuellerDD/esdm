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

/* The PKCS#11 entropy source of esdm-es-pkcs11(8), see esdm_es_pkcs11.c */

#ifndef _ESDM_ES_PKCS11_H
#define _ESDM_ES_PKCS11_H

#include <stdint.h>

#include "esdm_es_ext.h"

#define ESDM_PKCS11_NAME "PKCS#11"

/**
 * struct esdm_es_pkcs11_config - what the source is told to use
 *
 * @module_path: Path of the PKCS#11 module
 * @token_label: Label of the token; NULL or empty for the first one with an RNG
 * @pin: User PIN, NULL for none, taken over by the source
 * @entropy_rate: Bits of entropy per 256 bits of data the source declares
 */
struct esdm_es_pkcs11_config {
	const char *module_path;
	const char *token_label;
	char *pin;
	uint32_t entropy_rate;
};

/* Before the server initializes the source; the strings must outlive it */
void esdm_es_pkcs11_configure(struct esdm_es_pkcs11_config *config);

extern struct esdm_es_ext_plugin esdm_es_pkcs11_plugin;

#endif /* _ESDM_ES_PKCS11_H */
