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
#include <stdbool.h>
#include <strings.h>

#include "config.h"
#include "esdm_config.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "priv_access.pb-c.h"

/* Taking entropy away from the ESDM is for tests and debugging only */
#if defined(ESDM_TESTMODE) || defined(ESDM_BUILDTYPE_DEBUG)
#define ESDM_RPC_SET_ES_RATE
#endif

#ifdef ESDM_RPC_SET_ES_RATE
/*
 * The entropy sources under the names their status reports. Setting the rate
 * of a source this build left out does nothing, so all of them are listed.
 */
static const struct {
	const char *name;
	void (*set)(uint32_t rate);
} esdm_rpc_es_rates[] = {
	{ "CPU", esdm_config_es_cpu_entropy_rate_set },
	{ "Interrupt", esdm_config_es_irq_entropy_rate_set },
	{ "InterruptEBPF", esdm_config_es_irq_ebpf_entropy_rate_set },
	{ "JitterRNG", esdm_config_es_jent_entropy_rate_set },
	{ "KernelJitterRNG", esdm_config_es_jent_kernel_entropy_rate_set },
	{ "KernelRNG", esdm_config_es_krng_entropy_rate_set },
	{ "LinuxHWRand", esdm_config_es_hwrand_entropy_rate_set },
	{ "PKCS#11", esdm_config_es_pkcs11_entropy_rate_set },
	{ "Scheduler", esdm_config_es_sched_entropy_rate_set },
	{ "SchedulerEBPF", esdm_config_es_sched_ebpf_entropy_rate_set },
	{ "TPM2.0", esdm_config_es_tpm2_entropy_rate_set },
};

static int esdm_rpc_set_es_rate_by_name(const char *es, uint32_t rate)
{
	bool all = !strcasecmp(es, "all"), set = false;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(esdm_rpc_es_rates); i++) {
		if (!all && strcasecmp(es, esdm_rpc_es_rates[i].name))
			continue;

		esdm_rpc_es_rates[i].set(rate);
		set = true;
	}

	return set ? 0 : -EINVAL;
}
#endif /* ESDM_RPC_SET_ES_RATE */

void esdm_rpc_set_es_rate(PrivAccess_Service *service,
			  const SetEsRateRequest *request,
			  RetResponse_Closure closure, void *closure_data)
{
	RetResponse response = RET_RESPONSE__INIT;

	(void)service;

	if (!request || !request->es) {
		response.ret = -EFAULT;
	} else if (!esdm_rpc_client_is_privileged(closure_data)) {
		response.ret = -EPERM;
	} else {
#ifdef ESDM_RPC_SET_ES_RATE
		response.ret = esdm_rpc_set_es_rate_by_name(request->es,
							    request->rate);
#else
		response.ret = -EOPNOTSUPP;
#endif
	}

	closure(&response, closure_data);
}
