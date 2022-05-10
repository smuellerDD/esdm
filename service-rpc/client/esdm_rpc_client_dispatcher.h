/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_RPC_CLIENT_DISPATCHER_H
#define ESDM_RPC_CLIENT_DISPATCHER_H

#include "bool.h"
#include "mutex_w.h"
#include "protobuf-c-rpc/protobuf-c-rpc-dispatch.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Approach: allocate a separate dispatcher per "node". When requiring a
 * dispatcher, the current "node" is resolved and then the respective
 * dispatcher is locked.
 *
 * A "node" is defined as a CPU.
 */
struct esdm_dispatcher {
	ProtobufCService *service;		/* RPC client reference */
	ProtobufCRPCDispatch *dispatch;		/* RPC dispatch queue */
	mutex_w_t lock;				/* Lock to be held when using */
	bool available;				/* Is dispatcher available? */
};

/******************************************************************************
 * Unprivileged RPC
 ******************************************************************************/

/**
 * @brief Obtain dispatch queue and RPC service reference to be used for
 *	  subsequent RPC calls.
 *
 * This call locks the resources against parallel use, ensure the release of
 * the resource after the completion of a transaction with esdm_disp_put_unpriv.
 *
 * @param disp [out] Received dispatcher
 *
 * @return: 0 on success, < 0 on error
 */
int esdm_disp_get_unpriv(struct esdm_dispatcher **disp);

/**
 * @brief Release the resources for subsequent callers
 *
 * @param disp [in] Dispatcher to allow resolving the used lock
 */
void esdm_disp_put_unpriv(struct esdm_dispatcher *disp);

/******************************************************************************
 * Privileged RPC
 ******************************************************************************/

/**
 * @brief Obtain dispatch queue and RPC service reference to be used for
 *	  subsequent RPC calls.
 *
 * This call locks the resources against parallel use, ensure the release of
 * the resource after the completion of a transaction with esdm_disp_put_unpriv.
 *
 * @param disp [out] Received dispatcher
 *
 * @return: 0 on success, < 0 on error
 */
int esdm_disp_get_priv(struct esdm_dispatcher **disp);

/**
 * @brief Release the resources for subsequent callers
 *
 * @param dispatch [in] Dispatcher to allow resolving the used lock
 */
void esdm_disp_put_priv(struct esdm_dispatcher *disp);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_DISPATCHER_H */
