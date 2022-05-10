/*
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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

#ifndef HELPER_H
#define HELPER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define __aligned(x)	__attribute__((aligned(x)))
#define __unused	__attribute__((__unused__))
#define __maybe_unused	__attribute__((__unused__))

#define min_t(type, a, b)						\
	((type)a < (type)b) ? (type)a : (type)b

#define max_t(type, a, b)						\
	((type)a > (type)b) ? (type)a : (type)b

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define member_to_struct(member, data_type, member_var)                 \
        (data_type *)((char *)(member) - (char *) &((data_type *)0)->member_var)

uint32_t esdm_online_nodes(void);
uint32_t esdm_curr_node(void);

#ifdef __cplusplus
}
#endif

#endif /* HELPER_H */
