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

#include <stdio.h>
#include <string.h>

#include "env.h"
#include "esdm_rpc_client.h"
#include "test_pertubation.h"

int main(int argc, char *argv[])
{
	uint8_t buf[32];
	uint8_t zero[sizeof(buf)];
	size_t count = 10;
	int ret;

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

	memset(zero, 0, sizeof(zero));

	while (count) {
		ssize_t rc;

		memset(buf, 0, sizeof(buf));

		rc = esdm_rpcc_get_random_bytes_pr(buf, sizeof(buf));
		if (rc < 0) {
			ret = (int)ret;
			goto out;
		}

		if (!memcmp(zero, buf, sizeof(buf))) {
			printf("output buffer is zero!\n");
			ret = 1;
			goto out;
		}

		count--;
	}

out:
	esdm_rpcc_fini_unpriv_service();
	env_fini();
	return ret;
}
