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

/*
 * esdm-es-pcsc: esdm_es_pcsc.c served by the provider program of
 * libesdm_es_ext, with the options of the reader:
 *
 *	esdm-es-pcsc --socket /run/esdm-es-pcsc.socket --entropy_rate 128
 *	esdm-server --es_ext /run/esdm-es-pcsc.socket
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "esdm_es_ext_provider.h"
#include "esdm_es_pcsc.h"

static const struct option pcsc_options[] = {
	{ "reader", required_argument, NULL, 'r' },
	{ "challenge_len", required_argument, NULL, 'l' },
	{ 0, 0, 0, 0 },
};

static int pcsc_option(int opt, const char *arg)
{
	unsigned long val;
	char *end;

	switch (opt) {
	case 'r':
		esdm_es_pcsc_config.reader = arg;
		return 0;
	case 'l':
		val = strtoul(arg, &end, 10);
		if (arg[0] < '0' || arg[0] > '9' || *end || !val || val > 255) {
			fprintf(stderr,
				"--challenge_len takes 1 to 255 bytes, not %s\n",
				arg);
			return -1;
		}
		esdm_es_pcsc_config.challenge_len = (unsigned int)val;
		return 0;
	default:
		return -1;
	}
}

static void pcsc_usage(FILE *out)
{
	fprintf(out,
		"\t-r --reader <NAME>\tUse the reader whose name contains NAME\n"
		"\t\t\t(default: the first one holding a card)\n"
		"\t-l --challenge_len <N>\tBytes per GET CHALLENGE, 1 to 255\n"
		"\t\t\t(default: %u)\n"
		"\tThe source declares no entropy rate without --entropy_rate.\n",
		ESDM_ES_PCSC_CHALLENGE_LEN);
}

static const struct esdm_es_ext_provider_cli pcsc_cli = {
	.name = "esdm-es-pcsc",
	.version = ESDM_ES_PCSC_VERSION,
	.title = "ESDM PC/SC smart card entropy source",
	.short_options = "r:l:",
	.options = pcsc_options,
	.option = pcsc_option,
	.usage = pcsc_usage,
};

int main(int argc, char *argv[])
{
	return esdm_es_ext_provider_cli_main(&pcsc_cli, &esdm_es_pcsc_plugin,
					     argc, argv);
}
