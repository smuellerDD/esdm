/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef MATH_HELPER_H
#define MATH_HELPER_H

#ifdef __cplusplus
extern "C" {
#endif

/* prevents double evaluation */
#define min(a, b)                                                              \
	__extension__({                                                        \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _a : _b;                                             \
	})

#define max(a, b)                                                              \
	__extension__({                                                        \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a > _b ? _a : _b;                                             \
	})


static inline uint32_t min_uint32(uint32_t a, uint32_t b)
{
	return min(a, b);
}

static inline uint64_t min_uint64(uint64_t a, uint64_t b)
{
	return min(a, b);
}

static inline size_t min_size(size_t a, size_t b)
{
	return min(a, b);
}

static inline uint32_t max_uint32(uint32_t a, uint32_t b)
{
	return max(a, b);
}

#ifdef __cplusplus
}
#endif

#endif /* MATH_HELPER_H */
