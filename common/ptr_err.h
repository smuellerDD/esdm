/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef PTR_ERR_H
#define PTR_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

#define PTR_MAX_ERRNO 255

#define IS_ERR_VALUE(x)                                                        \
	((unsigned long)(void *)(x) >= (unsigned long)-PTR_MAX_ERRNO)

/* Convert error value to pointer */
static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

/* Convert pointer into error code */
static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

/* Is the pointer including an error? */
static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

#ifdef __cplusplus
}
#endif

#endif /* PTR_ERR_H */
