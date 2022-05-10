/* RPC Client: Dispatcher queue handling
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

#include <errno.h>
#include <stdlib.h>

#include "esdm_rpc_client_connection.h"
#include "esdm_rpc_client_dispatcher.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "visibility.h"

static void *esdm_system_alloc(void *allocator_data, size_t size)
{
	(void)allocator_data;
	return malloc(size);
}

static void esdm_system_free(void *allocator_data, void *data)
{
	(void)allocator_data;
	free(data);
}

static ProtobufCAllocator esdm_rpc_allocator = {
	.alloc = &esdm_system_alloc,
	.free = &esdm_system_free,
	.allocator_data = NULL,
};

static uint32_t esdm_disp_online_nodes_max = 0xffffffff;
static uint32_t esdm_disp_online_nodes(void)
{
	return min_t(uint32_t, esdm_online_nodes(), esdm_disp_online_nodes_max);
}

static uint32_t esdm_disp_curr_node(void)
{
	return (esdm_curr_node() % esdm_disp_online_nodes_max);
}

static void esdm_disp_fini(struct esdm_dispatcher *disp)
{
	uint32_t i, nodes = esdm_disp_online_nodes();
	struct esdm_dispatcher *disp_p = disp;

	if (!disp)
		return;

	for (i = 0; i < nodes; i++, disp_p++) {
		mutex_w_lock(&disp_p->lock);

		/* Service must be destroyed before dispatcher! */
		esdm_fini_proto_service(disp_p);

		if (disp_p->dispatch)
			protobuf_c_rpc_dispatch_free(disp_p->dispatch);
		disp_p->available = false;
		mutex_w_unlock(&disp_p->lock);
		mutex_w_destroy(&disp_p->lock);
	}

	free(disp);
}

static int esdm_disp_init(struct esdm_dispatcher **disp)
{
	struct esdm_dispatcher *disp_p, *disp_new;
	uint32_t i, nodes = esdm_disp_online_nodes();

	if (!disp)
		return -EFAULT;

	disp_new = calloc(nodes, sizeof(struct esdm_dispatcher));
	if (!disp_new)
		return -ENOMEM;

	disp_p = disp_new;

	for (i = 0; i < nodes; i++, disp_p++) {
		mutex_w_init(&disp_p->lock, 0);
		disp_p->dispatch =
			protobuf_c_rpc_dispatch_new(&esdm_rpc_allocator);
		if (!disp_p->dispatch)
			goto err;

		disp_p->available = true;
	}

	*disp = disp_new;

	return 0;

err:
	esdm_disp_fini(disp_new);
	return -EFAULT;
}

static int esdm_disp_get(struct esdm_dispatcher *disp,
			 struct esdm_dispatcher **ret_disp)
{
	struct esdm_dispatcher *disp_p;

	if (!disp)
		return -EFAULT;

	disp_p = disp + esdm_disp_curr_node();
	mutex_w_lock(&disp_p->lock);
	if (!disp_p->available) {
		mutex_w_unlock(&disp_p->lock);
		return -EFAULT;
	}

	*ret_disp = disp_p;

	return 0;
}

static void esdm_disp_put(struct esdm_dispatcher *disp)
{
	mutex_w_unlock(&disp->lock);
}

DSO_PUBLIC
void esdm_disp_set_max_online_nodes(uint32_t mask)
{
	if (mask)
		esdm_disp_online_nodes_max = mask;
}

/******************************************************************************
 * Unprivileged RPC
 ******************************************************************************/

static struct esdm_dispatcher *esdm_rpc_unpriv_dispatcher = NULL;

DSO_PUBLIC
void esdm_disp_fini_unpriv(void)
{
	esdm_disp_fini(esdm_rpc_unpriv_dispatcher);
}

DSO_PUBLIC
int esdm_disp_init_unpriv(void)
{
	return esdm_disp_init(&esdm_rpc_unpriv_dispatcher);
}

void esdm_disp_put_unpriv(struct esdm_dispatcher *disp)
{
	esdm_disp_put(disp);
}

int esdm_disp_get_unpriv(struct esdm_dispatcher **disp)
{
	struct esdm_dispatcher *disp_p;
	int ret = esdm_disp_get(esdm_rpc_unpriv_dispatcher, &disp_p);

	if (ret)
		return ret;

	ret = esdm_init_unpriv_proto_service(disp_p);
	if (ret) {
		esdm_disp_put_unpriv(disp_p);
		return ret;
	}

	*disp = disp_p;

	return 0;
}

/******************************************************************************
 * Privileged RPC
 ******************************************************************************/

static struct esdm_dispatcher *esdm_rpc_priv_dispatcher = NULL;

DSO_PUBLIC
void esdm_disp_fini_priv(void)
{
	esdm_disp_fini(esdm_rpc_priv_dispatcher);
}

DSO_PUBLIC
int esdm_disp_init_priv(void)
{
	return esdm_disp_init(&esdm_rpc_priv_dispatcher);
}

void esdm_disp_put_priv(struct esdm_dispatcher *disp)
{
	esdm_disp_put(disp);
}

int esdm_disp_get_priv(struct esdm_dispatcher **disp)
{
	struct esdm_dispatcher *disp_p;
	int ret = esdm_disp_get(esdm_rpc_priv_dispatcher, &disp_p);

	if (ret)
		return ret;

	ret = esdm_init_priv_proto_service(disp_p);
	if (ret) {
		esdm_disp_put_priv(disp_p);
		return ret;
	}

	*disp = disp_p;

	return 0;
}
