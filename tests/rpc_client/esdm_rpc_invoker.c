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

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_rpc_client.h"
#include "logger.h"

struct opt_data {
	int foo;
};

static int get_random_bytes_full(struct opt_data *opts)
{
	uint8_t buf[16];
	ssize_t rc;
	int ret = 0;

	(void)opts;

	rc = esdm_rpcc_get_random_bytes_full(buf, sizeof(buf));
	if (rc < 0) {
		ret = -(int)rc;
		goto out;
	}

out:
	return ret;
}

static int get_random_bytes_min(struct opt_data *opts)
{
	uint8_t buf[16];
	ssize_t rc;
	int ret = 0;

	(void)opts;

	rc = esdm_rpcc_get_random_bytes_min(buf, sizeof(buf));
	if (rc < 0) {
		ret = -(int)rc;
		goto out;
	}

out:
	return ret;
}

static int get_random_bytes(struct opt_data *opts)
{
	uint8_t buf[16];
	ssize_t rc;
	int ret = 0;

	(void)opts;

	rc = esdm_rpcc_get_random_bytes(buf, sizeof(buf));
	if (rc < 0) {
		ret = -(int)rc;
		goto out;
	}

out:
	return ret;
}

static void usage(void)
{
	fprintf(stderr, "\nESDM RPC Invoker\n");
}

static int parse_opts(int argc, char *argv[], struct opt_data *opts)
{
	int c = 0, ret = 0;

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{ "verbose", no_argument, 0, 'v' },
			{ "help", no_argument, 0, 'h' },

			{ "get_random_bytes_full", no_argument, 0, 'f' },
			{ "get_random_bytes_min", no_argument, 0, 'm' },
			{ "get_random_bytes", no_argument, 0, 0 },

			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "vhfm", options, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* verbose */
				logger_inc_verbosity();
				break;
			case 1:
				/* help */
				usage();
				ret = 0;
				goto out;
				break;

			case 2:
				/* get_random_bytes_full */
				ret = get_random_bytes_full(opts);
				goto out;
				break;
			case 3:
				/* get_random_bytes_min */
				ret = get_random_bytes_min(opts);
				goto out;
				break;
			case 4:
				/* get_random_bytes */
				ret = get_random_bytes(opts);
				goto out;
				break;

			default:
				usage();
				ret = -EINVAL;
				goto out;
				break;
			}
			break;

		case 'f':
			ret = get_random_bytes_full(opts);
			goto out;
			break;
		case 'm':
			ret = get_random_bytes_min(opts);
			goto out;
			break;
		case 'h':
			usage();
			ret = 0;
			goto out;
			break;
		default:
			usage();
			ret = -EINVAL;
			goto out;
			break;
		}
	}

out:
	return ret;
}

int main(int argc, char *argv[])
{
	struct opt_data opts;
	int ret;

	logger_set_verbosity(LOGGER_DEBUG);

	esdm_rpcc_set_max_online_nodes(1);
	ret = esdm_rpcc_init_unpriv_service(NULL);
	if (ret < 0)
		goto out;

	ret = parse_opts(argc, argv, &opts);

out:
	esdm_rpcc_fini_unpriv_service();
	return -ret;
}
