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

#include <stdio.h>
#include <string.h>

#include "esdm_rpc_client.h"
#include "logger.h"

int main(int argc, char *argv[])
{
	uint8_t buf[16];
	ssize_t rc;
	int ret;

	(void)argc;
	(void)argv;

	logger_set_verbosity(LOGGER_DEBUG);

	esdm_rpcc_set_max_online_nodes(1);
	ret = esdm_rpcc_init_unpriv_service(NULL);
	if (ret < 0) {
		ret = -ret;
		goto out;
	}

	rc = esdm_rpcc_get_random_bytes_full(buf, sizeof(buf));
	if (rc < 0) {
		ret = -(int)rc;
		goto out;
	}

out:
	esdm_rpcc_fini_unpriv_service();
	return ret;
}
