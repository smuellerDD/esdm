/*
 * XOF of the XDRBG-256
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

#ifndef _ESDM_XOF_H
#define _ESDM_XOF_H

/*
 * Shared by the ESDM and the kernel module esdm_es (kernel/esdm_es), which
 * both operate the XDRBG-256 of esdm_xdrbg.c on such an XOF - the crypto
 * backend's SHAKE256 in the ESDM, the kernel's in the module.
 */

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * struct esdm_xof_cb - cryptographic callback functions defining SHAKE256,
 *			the extendable-output function the XDRBG-256 operating
 *			the auxiliary pool is built on
 * @xof_name		Name of the XOF
 * @xof_init:		Start a new message, discarding the previous one
 *			xof: is pointer to data structure allocated with
 *			     xof_alloc
 *			return: 0 on success, < 0 on error
 * @xof_update:		Absorb data into the message
 *			xof: is pointer to data structure allocated with
 *			     xof_alloc
 *			return: 0 on success, < 0 on error
 * @xof_final:		Squeeze outlen bytes of output of the message in one
 *			go. The context takes no further data or output until
 *			it is initialized again.
 *			xof: is pointer to data structure allocated with
 *			     xof_alloc
 *			return: 0 on success, < 0 on error
 * @xof_alloc		Allocate an XOF context
 *			return: 0 on success, < 0 on error
 * @xof_dealloc		Zeroize and deallocate an XOF context
 *
 * The known-answer test of the XDRBG-256 is the self test of the XOF.
 *
 * Assumptions:
 *
 * 1. XOF operation will not sleep
 */
struct esdm_xof_cb {
	const char *(*xof_name)(void);
	int (*xof_init)(void *xof);
	int (*xof_update)(void *xof, const uint8_t *inbuf, size_t inbuflen);
	int (*xof_final)(void *xof, uint8_t *out, size_t outlen);
	int (*xof_alloc)(void **ctx);
	void (*xof_dealloc)(void *ctx);
};

/* The XOF esdm_xdrbg_alloc() gives an XDRBG */
extern const struct esdm_xof_cb *esdm_default_xof_cb;

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_XOF_H */
