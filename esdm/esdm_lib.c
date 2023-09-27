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

#include "config.h"
#include "esdm.h"
#include "esdm_config_internal.h"
#include "esdm_crypto.h"
#include "esdm_es_mgr.h"
#include "esdm_node.h"
#include "esdm_shm_status.h"
#include "ret_checkers.h"
#include "visibility.h"

DSO_PUBLIC
int esdm_init(void)
{
	int ret = 0;

#ifdef ESDM_OVERSAMPLE_ENTROPY_SOURCES
	/* Enable oversampling of entropy sources if selected at compile time */
	if (!esdm_config_sp80090c_compliant())
		esdm_config_force_fips_set(esdm_config_force_sp80090c_enabled);
#endif

	/* Initialize configuration subsystem */
	CKINT(esdm_config_init());

	/*
	 * Initialize the DRNG manager: the DRNG should be ready before the
	 * entropy manager as the entropy manager may try to immediately
	 * seed the DRNG.
	 */
	CKINT(esdm_drng_mgr_initialize());

	/* Initialize the entropy source manager */
	CKINT(esdm_es_mgr_initialize());

	/* Initialize all nodes */
	esdm_drngs_node_alloc();

	/* Initialize the status ESDM shared memory segment */
	CKINT(esdm_shm_status_init());

out:
	return ret;
}

DSO_PUBLIC
int esdm_reinit(void)
{
	int ret;

	/* Initialize configuration subsystem */
	CKINT(esdm_config_reinit());

	/* Reinitialize the DRNG manager */
	CKINT(esdm_drng_mgr_reinitialize());

	/* Reinitialize the entropy source manager */
	CKINT(esdm_es_mgr_reinitialize());

	/* Reinitialize the status ESDM shared memory segment */
	CKINT(esdm_shm_status_reinit());

out:
	return ret;
}

DSO_PUBLIC
void esdm_fini(void)
{
	/* Clear up the SHM information */
	esdm_shm_status_exit();

	/* Finalize the entropy source manager and all its entropy sources. */
	esdm_es_mgr_finalize();

	/* Terminate the DRNG manager after the ES are all silenced. */
	esdm_drng_mgr_finalize();

	/* Terminate all nodes */
	esdm_node_fini();
}

DSO_PUBLIC
int esdm_init_monitor(void (*priv_init_completion)(void))
{
	return esdm_es_mgr_monitor_initialize(priv_init_completion);
}
