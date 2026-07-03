/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_RPC_SERVICE_H
#define ESDM_RPC_SERVICE_H

#include <stdint.h>
#include <sys/ipc.h>

#include <stdatomic.h>
#include "config.h"
#include "esdm_rpc_protocol.h"
#include "priv_access.pb-c.h"
#include "test_pertubation.h"
#include "unpriv_access.pb-c.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 * IPC configuration
 ******************************************************************************/

#ifdef ESDM_TESTMODE

#define ESDM_RPC_UNPRIV_SOCKET "/tmp/esdm-rpc-unpriv-testmode.socket"

#define ESDM_RPC_PRIV_SOCKET "/tmp/esdm-rpc-priv-testmode.socket"

#define ESDM_SHM_NAME "/"
#define ESDM_SHM_STATUS 0x6573646d

#define ESDM_SEM_RANDOM_NAME "esdm-random-shm-status-semaphore-testmode"
#define ESDM_SEM_URANDOM_NAME "esdm-urandom-shm-status-semaphore-testmode"
#define ESDM_SEM_NEED_ENTROPY_LEVEL "esdm-need-entropy-level-semaphore-testmode"

#else /* ESDM_TESTMODE */

#define ESDM_RPC_UNPRIV_SOCKET                                                 \
	ESDM_SERVER_RPC_BASE_PATH_UNPRIVILEGED "/esdm-rpc-unpriv.socket"

#define ESDM_RPC_PRIV_SOCKET                                                   \
	ESDM_SERVER_RPC_BASE_PATH_PRIVILEGED "/esdm-rpc-priv.socket"

#define ESDM_SHM_NAME "/"
#define ESDM_SHM_STATUS 0x6d647365

#define ESDM_SEM_RANDOM_NAME "esdm-random-shm-status-semaphore"
#define ESDM_SEM_URANDOM_NAME "esdm-urandom-shm-status-semaphore"
#define ESDM_SEM_NEED_ENTROPY_LEVEL "esdm-need-entropy-level-semaphore"

#endif /* ESDM_TESTMODE */

#define ESDM_SHM_STATUS_VERSION 1
#define ESDM_SHM_STATUS_INFO_SIZE 1536

struct esdm_shm_status {
	/* Monotonic increasing version */
	uint32_t version;

	/* String with status information */
	char info[ESDM_SHM_STATUS_INFO_SIZE];
	size_t infolen;

	/* Number of threads handling the unprivileged interface */
	uint32_t unpriv_threads;

	/* Is the ESDM operational? */
	atomic_bool operational;
	/* Do we need new entropy? */
	atomic_bool need_entropy;
	/* Wake up due to suspend/hibernate trigger */
	atomic_bool suspend_trigger;
};

static inline key_t esdm_ftok(const char *pathname, int proj_id)
{
	return ftok(pathname, proj_id);
}

/******************************************************************************
 * Service functions wrapping the ESDM library
 *
 * For documentation, see the protobuf file
 ******************************************************************************/

void esdm_rpc_status(UnprivAccess_Service *service,
		     const StatusRequest *request,
		     StatusResponse_Closure closure, void *closure_data);

void esdm_rpc_is_fully_seeded(UnprivAccess_Service *service,
			      const EmptyRequest *request,
			      IsFullySeededResponse_Closure closure,
			      void *closure_data);

void esdm_rpc_get_ent_lvl(UnprivAccess_Service *service,
			  const EmptyRequest *request,
			  ValResponse_Closure closure,
			  void *closure_data);

void esdm_rpc_get_random_bytes_full(UnprivAccess_Service *service,
				    const GetRandomBytesRequest *request,
				    RandValResponse_Closure closure,
				    void *closure_data);

void esdm_rpc_get_random_bytes_pr(UnprivAccess_Service *service,
				  const GetRandomBytesRequest *request,
				  RandValResponse_Closure closure,
				  void *closure_data);

void esdm_rpc_get_random_bytes(UnprivAccess_Service *service,
			       const GetRandomBytesRequest *request,
			       RandValResponse_Closure closure,
			       void *closure_data);

void esdm_rpc_get_seed(UnprivAccess_Service *service,
		       const GetSeedRequest *request,
		       RandValResponse_Closure closure, void *closure_data);

void esdm_rpc_write_data(UnprivAccess_Service *service,
			 const WriteDataRequest *request,
			 RetResponse_Closure closure, void *closure_data);

/* IOCTL implementations */
void esdm_rpc_rnd_get_ent_cnt(UnprivAccess_Service *service,
			      const EmptyRequest *request,
			      ValResponse_Closure closure,
			      void *closure_data);
void esdm_rpc_rnd_add_to_ent_cnt(PrivAccess_Service *service,
				 const RndAddToEntCntRequest *request,
				 RetResponse_Closure closure,
				 void *closure_data);
void esdm_rpc_rnd_add_entropy(PrivAccess_Service *service,
			      const RndAddEntropyRequest *request,
			      RetResponse_Closure closure,
			      void *closure_data);
void esdm_rpc_rnd_clear_pool(PrivAccess_Service *service,
			     const EmptyRequest *request,
			     RetResponse_Closure closure,
			     void *closure_data);
void esdm_rpc_rnd_reseed_crng(PrivAccess_Service *service,
			      const EmptyRequest *request,
			      RetResponse_Closure closure,
			      void *closure_data);

/* /proc implementations */
void esdm_rpc_get_poolsize(UnprivAccess_Service *service,
			   const EmptyRequest *request,
			   ValResponse_Closure closure,
			   void *closure_data);
void esdm_rpc_get_write_wakeup_thresh(
	UnprivAccess_Service *service,
	const EmptyRequest *request,
	ValResponse_Closure closure, void *closure_data);
void esdm_rpc_set_write_wakeup_thresh(
	PrivAccess_Service *service, const SetWriteWakeupThreshRequest *request,
	RetResponse_Closure closure, void *closure_data);
void esdm_rpc_get_min_reseed_secs(UnprivAccess_Service *service,
				  const EmptyRequest *request,
				  ValResponse_Closure closure,
				  void *closure_data);
void esdm_rpc_set_min_reseed_secs(PrivAccess_Service *service,
				  const SetMinReseedSecsRequest *request,
				  RetResponse_Closure closure,
				  void *closure_data);

/* entropy source specific implementations */
void esdm_rpc_jent_status(UnprivAccess_Service *service,
			  const StatusRequest *request,
			  StatusResponse_Closure closure,
			  void *closure_data);
void esdm_rpc_set_pkcs11_config(PrivAccess_Service *service,
				const SetPkcs11ConfigRequest *request,
				RetResponse_Closure closure,
				void *closure_data);

/******************************************************************************
 * Definition of Protobuf-C service
 ******************************************************************************/

extern UnprivAccess_Service unpriv_access_service;
extern PrivAccess_Service priv_access_service;

/******************************************************************************
 * Common Helper
 ******************************************************************************/

/*
 * Initially it should have been 65536, but somehow protobuf-c has some
 * additional meta data along with the buffer and has an internal limit. This
 * causes a hang when choosing a value > 65512. To be a bit more conservative
 * let us pick a value with some more leeway.
 */
#define ESDM_RPC_MAX_MSG_SIZE 65536
#define ESDM_RPC_MAX_RPC_HEADER_SIZE sizeof(struct esdm_rpc_proto_sc_header)
#define ESDM_RPC_MAX_INTERNAL_MSG_HEADER_SIZE sizeof(uint64_t)
#define ESDM_RPC_MAX_INTERNAL_MSG_SIZE                                         \
	(ESDM_RPC_MAX_MSG_SIZE - ESDM_RPC_MAX_RPC_HEADER_SIZE)
#define ESDM_RPC_MAX_DATA                                                      \
	(ESDM_RPC_MAX_INTERNAL_MSG_SIZE - ESDM_RPC_MAX_INTERNAL_MSG_HEADER_SIZE)

/*
 * Scratch buffer size for unpacking a received protobuf message with the
 * esdm_rpc_alloc() bump allocator instead of malloc()/free() on every call.
 * It must hold the unpacked message struct plus the largest possible
 * variable-length field (up to ESDM_RPC_MAX_DATA) plus per-allocation
 * alignment padding, hence the headroom over the raw wire message size.
 */
#define ESDM_RPC_MAX_UNPACK_SIZE (ESDM_RPC_MAX_MSG_SIZE + 1024)

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_SERVICE_H */
