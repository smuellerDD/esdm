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

#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct buffer {
	size_t len;
	size_t consumed;
	uint8_t *buf;
};

#define BUFFER_INIT(name) struct buffer name = { 0, 0, NULL }

void buffer_free(struct buffer *buf);
int buffer_alloc(size_t size, struct buffer *buf);

#define ALIGN_APPLY(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN(x, a)		ALIGN_APPLY((x), (unsigned long)(a))
#define ALIGN_PTR_64(p, a)	((uint64_t *)ALIGN((unsigned long)(p), (a)))
#define ALIGN_PTR_32(p, a)	((uint32_t *)ALIGN((unsigned long)(p), (a)))
#define ALIGN_PTR_16(p, a)	((uint16_t *)ALIGN((unsigned long)(p), (a)))
#define ALIGN_PTR_8(p, a)	((uint8_t *)ALIGN((unsigned long)(p), (a)))

#ifdef __cplusplus
}
#endif

#endif /* BUFFER_H */
