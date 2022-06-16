/*
 * ESDM Multi-Node support
 *
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

#include <stdlib.h>

#include "atomic.h"
#include "esdm_crypto.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_irq.h"
#include "esdm_es_mgr.h"
#include "esdm_info.h"
#include "esdm_node.h"
#include "logger.h"
#include "mutex.h"

static struct esdm_drng **esdm_drng = NULL;
static DEFINE_MUTEX_UNLOCKED(esdm_node_cleanup_lock);

struct esdm_drng **esdm_drng_get_instances(void)
{
	/* counterpart to cmpxchg_release in _esdm_drngs_node_alloc */
	mb();
	mutex_reader_lock(&esdm_node_cleanup_lock);
	return esdm_drng;
}

void esdm_drng_put_instances(void)
{
	mutex_reader_unlock(&esdm_node_cleanup_lock);
}

static void esdm_drngs_node_dealloc(struct esdm_drng **drngs)
{
	struct esdm_drng *esdm_drng_init = esdm_drng_init_instance();
	uint32_t node;

	if (!drngs)
		return;

	for_each_online_node(node) {
		struct esdm_drng *drng = drngs[node];

		if (drng == esdm_drng_init)
			continue;

		if (drng) {
			mutex_w_lock(&drng->lock);
			drng->drng_cb->drng_dealloc(drng->drng);
			mutex_w_unlock(&drng->lock);
			free(drng);
			drngs[node] = NULL;
		}
	}
	free(drngs);
}

/* Allocate the data structures for the per-node DRNGs */
void esdm_drngs_node_alloc(void)
{
	struct esdm_drng **drngs;
	struct esdm_drng *esdm_drng_init = esdm_drng_init_instance();
	uint32_t node;
	bool init_drng_used = false;

	mutex_w_lock(&esdm_crypto_cb_update);

	/* per-node DRNGs are already present */
	if (esdm_drng)
		goto unlock;

	/* Make sure the initial DRNG is initialized and its drng_cb is set */
	if (esdm_drng_mgr_initalize())
		goto unlock;

	drngs = calloc(esdm_config_online_nodes(), sizeof(struct esdm_drng *));
	if (!drngs)
		goto unlock;

	for_each_online_node(node) {
		struct esdm_drng *drng;

		if (!init_drng_used) {
			drngs[node] = esdm_drng_init;
			init_drng_used = true;
			continue;
		}

		drng = calloc(1, sizeof(struct esdm_drng));

		if (esdm_drng_alloc_common(drng, esdm_drng_init->drng_cb)) {
			free(drng);
			goto err;
		}

		drng->hash_cb = esdm_drng_init->hash_cb;

		mutex_w_init(&drng->lock, 0);
		mutex_init(&drng->hash_lock, 0);

		/*
		 * No reseeding of node DRNGs from previous DRNGs as this
		 * would complicate the code. Let it simply reseed.
		 */
		drngs[node] = drng;

		esdm_pool_inc_node_node();
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "DRNG and entropy pool read hash for node %d allocated\n",
		       node);
	}

	/* counterpart to memory barrier in esdm_drng_get_instances */
	if (!__sync_val_compare_and_swap(&esdm_drng, NULL, drngs)) {
		esdm_pool_all_nodes_seeded(false);
		esdm_es_add_entropy();
		goto unlock;
	}

err:
	esdm_drngs_node_dealloc(drngs);

unlock:
	mutex_w_unlock(&esdm_crypto_cb_update);
}

void esdm_node_fini(void)
{
	struct esdm_drng **drngs;

	mutex_lock(&esdm_node_cleanup_lock);
	drngs = __atomic_exchange_n(&esdm_drng, NULL, __ATOMIC_ACQUIRE);
	esdm_drngs_node_dealloc(drngs);
	mutex_unlock(&esdm_node_cleanup_lock);
}
