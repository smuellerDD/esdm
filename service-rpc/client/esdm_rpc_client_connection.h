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

#ifndef ESDM_RPC_CLIENT_CONNECTION_H
#define ESDM_RPC_CLIENT_CONNECTION_H

#include "esdm_rpc_client_dispatcher.h"
#include "protobuf-c-rpc/protobuf-c-rpc.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Close connection
 *
 * @param disp [in] Dispatcher with connection handle to close
 */
void esdm_fini_proto_service(struct esdm_dispatcher *disp);

/******************************************************************************
 * Unprivileged ESDM interface
 ******************************************************************************/

/**
 * @brief Initiate connection
 *
 * @param disp [in] Dispatcher which shall be used. Note, this queue
 *		    must also be used for subsequent communication.
 *
 * To get the proper dispatcher, use esdm_disp_get_unpriv.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_init_unpriv_proto_service(struct esdm_dispatcher *disp);

/******************************************************************************
 * Privileged ESDM interface
 ******************************************************************************/

/**
 * @brief Initiate connection
 *
 * @param disp [in] Dispatcher which shall be used. Note, this queue
 *		    must also be used for subsequent communication.
 *
 * To get the proper dispatcher, use esdm_disp_get_priv.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_init_priv_proto_service(struct esdm_dispatcher *disp);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_CONNECTION_H */
