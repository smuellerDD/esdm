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

#include "esdm_es_mgr.h"
#include "esdm_rpc_service.h"
#include "memset_secure.h"
#include "unpriv_access.pb-c.h"

void esdm_rpc_get_write_wakeup_thresh(
				UnprivAccess_Service *service,
				const GetWriteWakeupThreshRequest *request,
				GetWriteWakeupThreshResponse_Closure closure,
				void *closure_data)
{
	GetWriteWakeupThreshResponse response =
					GET_WRITE_WAKEUP_THRESH_RESPONSE__INIT;
	(void)request;
	(void)service;

	response.wakeup = esdm_get_write_wakeup_bits();
	response.ret = 0;
	closure (&response, closure_data);
}
