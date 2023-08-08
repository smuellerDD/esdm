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
	uint8_t buf[1024 * 1024];
	uint8_t zero[sizeof(buf)];
	size_t len = sizeof(buf);
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

	while (len) {
		ssize_t rc;
		unsigned short val;

		memset(buf, 0, len);

		rc = esdm_rpcc_get_random_bytes_min(buf, len);
		if (rc < 0) {
			ret = (int)ret;
			goto out;
		}

		if (!memcmp(zero, buf, len)) {
			printf("output buffer is zero!\n");
			ret = 1;
			goto out;
		}

#ifdef ESDM_TESTMODE
		if (len != esdm_test_shm_status_get_rpc_client_written()) {
			printf("ERROR: amount of client data requested (%zu) does not match received data (%zu)\n",
			       len,
			       esdm_test_shm_status_get_rpc_client_written());
			ret = 1;
			goto out;
		} else {
			printf("PASS: amount of client data requested matches received data (%zu)\n",
			       len);
		}

		if (len != esdm_test_shm_status_get_rpc_server_written()) {
			printf("ERROR: amount of generated server data (%zu) does not match received data (%zu)\n",
			       esdm_test_shm_status_get_rpc_server_written(),
			       len);
			ret = 1;
			goto out;
		} else {
			printf("PASS: amount of generated server data matches written data (%zu)\n",
			       len);
		}
		esdm_test_shm_status_reset();
#endif

		val = (unsigned short)buf[0];
		val |= (unsigned short)(buf[1] << 8);
		len = (len > val) ? len - val : 0;
	}

out:
	esdm_rpcc_fini_unpriv_service();
	env_fini();
	return ret;
}
