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

#ifndef TEST_PERTUBATION_H
#define TEST_PERTUBATION_H

#include <stdint.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ESDM_TESTMODE

#include "atomic.h"

#define TESTMODE_STR "TEST MODE CONFIGURATION ESDM "

extern uint32_t seed_entropy[];
extern atomic_t seed_entropy_ptr;
void esdm_test_seed_entropy(uint32_t ent);

void esdm_test_disable_fallback(int disable);
int esdm_test_fallback_fd(int fd);

int esdm_test_shm_status_init(void);
void esdm_test_shm_status_fini(void);
void esdm_test_shm_status_reset(void);
void esdm_test_shm_status_add_rpc_client_written(size_t written);
size_t esdm_test_shm_status_get_rpc_client_written(void);
void esdm_test_shm_status_add_rpc_server_written(size_t written);
size_t esdm_test_shm_status_get_rpc_server_written(void);

#else /* ESDM_TESTMODE */

#define TESTMODE_STR ""

static inline void esdm_test_seed_entropy(uint32_t ent)
{
	(void)ent;
}

static inline void esdm_test_disable_fallback(int disable)
{
	(void)disable;
}
static inline int esdm_test_fallback_fd(int fd)
{
	return fd;
}

static inline int esdm_test_shm_status_init(void)
{
	return 0;
}
static inline void esdm_test_shm_status_fini(void)
{
}
static inline void esdm_test_shm_status_reset(void)
{
}
static inline void esdm_test_shm_status_add_rpc_client_written(size_t written)
{
	(void)written;
}
static inline size_t esdm_test_shm_status_get_rpc_client_written(void)
{
	return 0;
}
static inline void esdm_test_shm_status_add_rpc_server_written(size_t written)
{
	(void)written;
}
static inline size_t esdm_test_shm_status_get_rpc_server_written(void)
{
	return 0;
}

#endif /* ESDM_TESTMODE */

#ifdef __cplusplus
}
#endif

#endif /* TEST_PERTUBATION_H */
