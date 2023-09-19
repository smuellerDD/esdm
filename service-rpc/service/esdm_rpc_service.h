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

#ifndef ESDM_RPC_SERVICE_H
#define ESDM_RPC_SERVICE_H

#include <sys/ipc.h>

#include "atomic_bool.h"
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

#define ESDM_SEM_NAME "esdm-shm-status-semaphore-testmode"

#else /* ESDM_TESTMODE */

#define ESDM_RPC_UNPRIV_SOCKET "/var/run/esdm-rpc-unpriv.socket"

#define ESDM_RPC_PRIV_SOCKET "/var/run/esdm-rpc-priv.socket"

#define ESDM_SHM_NAME "/"
#define ESDM_SHM_STATUS 0x6d647365

#define ESDM_SEM_NAME "esdm-shm-status-semaphore"

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
	atomic_bool_t operational;
	/* Do we need new entropy? */
	atomic_bool_t need_entropy;
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

void esdm_rpc_status_json(UnprivAccess_Service *service,
		     const StatusRequest *request,
		     StatusResponse_Closure closure, void *closure_data);

void esdm_rpc_get_random_bytes_full(UnprivAccess_Service *service,
				    const GetRandomBytesFullRequest *request,
				    GetRandomBytesFullResponse_Closure closure,
				    void *closure_data);

void esdm_rpc_get_random_bytes_min(UnprivAccess_Service *service,
				   const GetRandomBytesMinRequest *request,
				   GetRandomBytesMinResponse_Closure closure,
				   void *closure_data);

void esdm_rpc_get_random_bytes_pr(UnprivAccess_Service *service,
				  const GetRandomBytesPrRequest *request,
				  GetRandomBytesPrResponse_Closure closure,
				  void *closure_data);

void esdm_rpc_get_random_bytes(UnprivAccess_Service *service,
			       const GetRandomBytesRequest *request,
			       GetRandomBytesResponse_Closure closure,
			       void *closure_data);

void esdm_rpc_get_seed(UnprivAccess_Service *service,
		       const GetSeedRequest *request,
		       GetSeedResponse_Closure closure, void *closure_data);

void esdm_rpc_write_data(UnprivAccess_Service *service,
			 const WriteDataRequest *request,
			 WriteDataResponse_Closure closure, void *closure_data);

/* IOCTL implementations */
void esdm_rpc_rnd_get_ent_cnt(UnprivAccess_Service *service,
			      const RndGetEntCntRequest *request,
			      RndGetEntCntResponse_Closure closure,
			      void *closure_data);
void esdm_rpc_rnd_add_to_ent_cnt(PrivAccess_Service *service,
				 const RndAddToEntCntRequest *request,
				 RndAddToEntCntResponse_Closure closure,
				 void *closure_data);
void esdm_rpc_rnd_add_entropy(PrivAccess_Service *service,
			      const RndAddEntropyRequest *request,
			      RndAddEntropyResponse_Closure closure,
			      void *closure_data);
void esdm_rpc_rnd_clear_pool(PrivAccess_Service *service,
			     const RndClearPoolRequest *request,
			     RndClearPoolResponse_Closure closure,
			     void *closure_data);
void esdm_rpc_rnd_reseed_crng(PrivAccess_Service *service,
			      const RndReseedCRNGRequest *request,
			      RndReseedCRNGResponse_Closure closure,
			      void *closure_data);

/* /proc implementations */
void esdm_rpc_get_poolsize(UnprivAccess_Service *service,
			   const GetPoolsizeRequest *request,
			   GetPoolsizeResponse_Closure closure,
			   void *closure_data);
void esdm_rpc_get_write_wakeup_thresh(
	UnprivAccess_Service *service,
	const GetWriteWakeupThreshRequest *request,
	GetWriteWakeupThreshResponse_Closure closure, void *closure_data);
void esdm_rpc_set_write_wakeup_thresh(
	PrivAccess_Service *service, const SetWriteWakeupThreshRequest *request,
	SetWriteWakeupThreshResponse_Closure closure, void *closure_data);
void esdm_rpc_get_min_reseed_secs(UnprivAccess_Service *service,
				  const GetMinReseedSecsRequest *request,
				  GetMinReseedSecsResponse_Closure closure,
				  void *closure_data);
void esdm_rpc_set_min_reseed_secs(PrivAccess_Service *service,
				  const SetMinReseedSecsRequest *request,
				  SetMinReseedSecsResponse_Closure closure,
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
#define ESDM_RPC_MAX_DATA                                                      \
	(ESDM_RPC_MAX_MSG_SIZE - sizeof(struct esdm_rpc_proto_sc_header))

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_SERVICE_H */
