/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "inttypes.h"
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "env.h"
#include "getrandom.h"

static inline ssize_t getrandom_seed_initial_n(uint8_t *buffer,
					       size_t bufferlen)
{
	return __getrandom(buffer, bufferlen, GRND_SEED | GRND_NONBLOCK);
}

static inline ssize_t getrandom_seed_n(uint8_t *buffer, size_t bufferlen)
{
	return __getrandom(buffer, bufferlen,
			   GRND_SEED | GRND_FULLY_SEEDED | GRND_NONBLOCK);
}

int main(int argc, char *argv[])
{
	uint64_t buf[512 / sizeof(uint64_t)];
	uint64_t buf2;
	uint64_t size;
	int ret;
	ssize_t rc;

	(void)argc;
	(void)argv;

	ret = env_init();
	if (ret)
		return ret;

	rc = getrandom_seed_initial_n((uint8_t *)&buf2, 1);
	if (rc > 0 || errno != EINVAL) {
		printf("esdm_get_seed does not indicate that the buffer is too small:%d\n",
		       errno);
		ret = 1;
		goto out;
	}

	rc = getrandom_seed_initial_n((uint8_t *)&size, sizeof(size));
	if (rc > 0 || errno != EMSGSIZE) {
		printf("esdm_get_seed does not indicate that the buffer is too small %d\n",
		       errno);
		ret = 1;
		goto out;
	}
	if (size > sizeof(buf)) {
		printf("esdm_get_seed specifies a buffer that is too large: %" PRIu64
		       "\n",
		       size);
		ret = 1;
		goto out;
	}

	rc = getrandom_seed_n((uint8_t *)buf, sizeof(buf));
	if (rc < 0) {
		printf("esdm_get_seed returned an error %d\n", errno);
		ret = 1;
		goto out;
	}

	if (rc == 0) {
		printf("esdm_get_seed was unable to produce entropy\n");
		ret = 77;
		goto out;
	}

	if (buf[0] > sizeof(buf)) {
		printf("esdm_get_seed returned a strange size value %" PRIu64
		       "\n",
		       buf[0]);
		ret = 1;
		goto out;
	}

	if (buf[1] < 128) {
		printf("esdm_get_seed returned insufficient seed: %" PRIu64
		       "\n",
		       buf[1]);
		ret = 1;
		goto out;
	} else {
		printf("esdm_get_seed returned proper seed size value %" PRIu64
		       " bytes and entropy value %" PRIu64 " bits\n",
		       buf[0], buf[1]);
	}

	rc = getrandom_seed_n((uint8_t *)buf, sizeof(buf));
	if (rc < 0) {
		printf("esdm_get_seed returned an error %d\n", errno);
		ret = 1;
		goto out;
	}

	if (rc == 0) {
		printf("esdm_get_seed was unable to produce entropy\n");
		ret = 77;
		goto out;
	}

	if (buf[1] < 128) {
		printf("esdm_get_seed returned insufficient seed: %" PRIu64
		       "\n",
		       buf[1]);
		ret = 1;
		goto out;
	} else {
		printf("esdm_get_seed returned proper seed size value %" PRIu64
		       " bytes and entropy value %" PRIu64 " bits\n",
		       buf[0], buf[1]);
	}

out:
	env_fini();
	return ret;
}
