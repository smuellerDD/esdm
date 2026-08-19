/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

#include <errno.h>

#include "build_bug_on.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_rpc_service.h"
#include "esdm_selftest.h"
#include "priv_access.pb-c.h"

void esdm_rpc_selftest(PrivAccess_Service *service, const EmptyRequest *request,
		       SelftestResponse_Closure closure, void *closure_data)
{
	SelftestResponse response = SELFTEST_RESPONSE__INIT;
	int ret;

	(void)request;
	(void)service;

	/*
	 * The states travel as the numbers the ESDM uses for them - the
	 * protobuf file documents those values, so they are part of the wire
	 * protocol and cannot follow a renumbering of the enum.
	 */
	BUILD_BUG_ON(esdm_selftest_undone != 0);
	BUILD_BUG_ON(esdm_selftest_passed != 1);
	BUILD_BUG_ON(esdm_selftest_failed != 2);

	ret = esdm_selftest_run();

	/*
	 * A crypto self test that failed is not recovered from within this
	 * process: a later pass may well pass, while the ESDM keeps holding its
	 * output back.
	 */
	if (!ret && !esdm_selftest_crypto_passed())
		ret = -EOPNOTSUPP;

	response.ret = ret;
	response.crypto_state = (uint32_t)esdm_selftest_crypto_state();
	response.es_state = (uint32_t)esdm_selftest_es_state();
	response.es_sources = esdm_selftest_es_sources();
	response.es_failures = esdm_selftest_es_failures();

	closure(&response, closure_data);
}
