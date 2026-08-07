/*
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
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
 * Known-answer tests for the SP800-90B health test cutoff computation of
 * the eBPF entropy sources: the RCT cutoffs follow SP800-90B section 4.4.1
 * with alpha = 2^-30 / 2^-60 and the APT cutoffs match the tables of the
 * ESDM Linux kernel add-on (addon/linux_esdm_es/esdm_health.h).
 */

#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include "es_ebpf/esdm_es_ebpf.h"

struct cutoff_kat {
	uint32_t osr;
	uint32_t rct_cutoff;
	uint32_t rct_cutoff_permanent;
	uint32_t apt_cutoff;
	uint32_t apt_cutoff_permanent;
	const char *desc;
};

static const struct cutoff_kat kats[] = {
	/* Full entropy per event */
	{ 1, 30, 60, 325, 355, "OSR 1" },
	/* Half a bit per event */
	{ 2, 60, 120, 422, 447, "OSR 2" },
	{ 4, 120, 240, 477, 494, "OSR 4" },
	{ 8, 240, 480, 502, 512, "OSR 8" },
	/* APT cutoff clamped to the window size per FIPS IG */
	{ 16, 480, 960, 512, 512, "OSR 16 (APT clamp)" },
	/* RCT scales, APT clamped */
	{ 256, 7680, 15360, 512, 512, "OSR 256 (APT clamp)" },
	/* Unconfigured OSR: strictest cutoffs of OSR 1 */
	{ 0, 30, 60, 325, 355, "OSR 0 (treated as OSR 1)" },
};

int main(int argc, char *argv[])
{
	unsigned int i;
	int ret = 0;

	(void)argc;
	(void)argv;

	for (i = 0; i < sizeof(kats) / sizeof(kats[0]); i++) {
		const struct cutoff_kat *kat = &kats[i];
		struct esdm_ebpf_config cfg = { 0 };

		esdm_ebpf_health_cutoffs(kat->osr, &cfg);

		if (cfg.rct_cutoff != kat->rct_cutoff ||
		    cfg.rct_cutoff_permanent != kat->rct_cutoff_permanent ||
		    cfg.apt_cutoff != kat->apt_cutoff ||
		    cfg.apt_cutoff_permanent != kat->apt_cutoff_permanent) {
			printf("ES eBPF health - fail: %s: got RCT %u/%u APT %u/%u, expected RCT %u/%u APT %u/%u\n",
			       kat->desc, cfg.rct_cutoff,
			       cfg.rct_cutoff_permanent, cfg.apt_cutoff,
			       cfg.apt_cutoff_permanent, kat->rct_cutoff,
			       kat->rct_cutoff_permanent, kat->apt_cutoff,
			       kat->apt_cutoff_permanent);
			ret = 1;
			continue;
		}

		printf("ES eBPF health - pass: %s: RCT %u/%u APT %u/%u\n",
		       kat->desc, cfg.rct_cutoff, cfg.rct_cutoff_permanent,
		       cfg.apt_cutoff, cfg.apt_cutoff_permanent);
	}

	return ret;
}
