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
	uint32_t entropy_rate;
	uint32_t rct_cutoff;
	uint32_t rct_cutoff_permanent;
	uint32_t apt_cutoff;
	uint32_t apt_cutoff_permanent;
	const char *desc;
};

static const struct cutoff_kat kats[] = {
	/* Full entropy per event: OSR 1 */
	{ 256, 30, 60, 325, 355, "rate 256 (OSR 1)" },
	/* Half a bit per event: OSR 2 */
	{ 128, 60, 120, 422, 447, "rate 128 (OSR 2)" },
	/* Rounded down to OSR 2 (conservative) */
	{ 100, 60, 120, 422, 447, "rate 100 (OSR 2)" },
	/* OSR 4 */
	{ 64, 120, 240, 477, 494, "rate 64 (OSR 4)" },
	/* OSR 8 */
	{ 32, 240, 480, 502, 512, "rate 32 (OSR 8)" },
	/* OSR 16: APT cutoff clamped to the window size per FIPS IG */
	{ 16, 480, 960, 512, 512, "rate 16 (OSR 16, APT clamp)" },
	/* OSR 256: RCT scales, APT clamped */
	{ 1, 7680, 15360, 512, 512, "rate 1 (OSR 256, APT clamp)" },
	/* Uncredited source: strictest cutoffs (OSR 1) */
	{ 0, 30, 60, 325, 355, "rate 0 (uncredited, OSR 1)" },
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

		esdm_ebpf_health_cutoffs(kat->entropy_rate, &cfg);

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
