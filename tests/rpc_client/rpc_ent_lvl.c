/*
 * Copyright (C) 2024, Markus Theil <theil.markus@gmail.com>
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

#include <stdio.h>
#include <string.h>

#include "env.h"
#include "esdm_rpc_client.h"

int main(int argc, char *argv[])
{
	int ret;
	unsigned int entlvl;

	(void)argc;
	(void)argv;

	ret = env_init();
	if (ret)
		return ret;

	ret = esdm_rpcc_init_unpriv_service(NULL);
	if (ret) {
		ret = 1;
		goto out;
	}

	ret = esdm_rpcc_get_ent_lvl(&entlvl);
	if (ret < 0) {
		printf("RPC get_ent_lvl returned error %d\n", ret);
		ret = 1;
		goto out;
	}

	/* ESDM should be configured with some source for this test 
     * and already accumulated entropy */
	if (entlvl == 0) {
		printf("RPC get_ent_lvl returned zero entropy\n");
		ret = 1;
		goto out;
	}

out:
	esdm_rpcc_fini_unpriv_service();
	env_fini();
	return ret;
}
