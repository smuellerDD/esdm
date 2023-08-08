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

#ifndef ESDM_RPC_SERVER_H
#define ESDM_RPC_SERVER_H

#include <protobuf-c/protobuf-c.h>

#include "bool.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check whether Unix Domain Socket client is privileged (UID 0)
 *
 * This call uses getsockupt(SO_PEERCRED) to obtain the remote caller's
 * UID.
 *
 * NOTE: For Protobuf-C-RPC, a connection is left open. Thus, the CUSE
 *	 daemon's drop of privileges may not be caught by this check. Therefore
 *	 the CUSE daemons are considered trusted to implement another check
 *	 whether its callers is privileged.
 */
bool esdm_rpc_client_is_privileged(void *closure_data);

int esdm_rpc_server_init(const char *username);
void esdm_rpc_server_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_SERVER_H */
