/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Cutoffs of the SP800-90B health tests of the time stamp based entropy
 * sources
 *
 * Shared by the kernel module esdm_es (kernel/esdm_es/esdm_health.c) and the
 * eBPF-based entropy sources of the ESDM (esdm/es_ebpf/esdm_es_ebpf.c), which
 * run the same tests.
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_HEALTH_CUTOFFS_H
#define _ESDM_HEALTH_CUTOFFS_H

/*
 * The RCT applies the significance level of 2^-30 (2^-60 for a permanent
 * failure) of SP800-90B section 4.4.1. Based on the formula
 * in SP800-90B section 4.4.1, when exceeding the threshold, a health alarm is
 * triggered. When applying an oversampling rate, this value is multiplied
 * by the used oversampling rate at compile time. As the OSR is an integer,
 * rounding errors occur when the actual OSR contains fractions. At compile
 * time, the OSR will always be rounded down to the nearest integer value
 * to be conservative.
 */
#define CONFIG_ESDM_RCT_CUTOFF 30
#define CONFIG_ESDM_RCT_CUTOFF_PERMANENT 60

/*
 * See the SP 800-90B comment #10b for the corrected cutoff for the SP 800-90B
 * APT.
 * http://www.untruth.org/~josh/sp80090b/UL%20SP800-90B-final%20comments%20v1.9%2020191212.pdf
 * In in the syntax of R, this is C = 2 + qbinom(1 − 2^(−30), 511, 2^(-1/osr)).
 * (The original formula wasn't correct because the first symbol must
 * necessarily have been observed, so there is no chance of observing 0 of these
 * symbols.)
 *
 * For the alpha < 2^-53, R cannot be used as it uses a float data type without
 * arbitrary precision. A SageMath script is used to calculate those cutoff
 * values.
 *
 * For any value above 14, this yields the maximal allowable value of 512
 * (by FIPS 140-2 IG 7.19 Resolution # 16, we cannot choose a cutoff value that
 * renders the test unable to fail).
 *
 * The definitions are for an significance level of 2^-30 and 2^-60
 */
#define CONFIG_ESDM_APT_CUTOFF_1 325
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_1 355

#define CONFIG_ESDM_APT_CUTOFF_2 422
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_2 447

#define CONFIG_ESDM_APT_CUTOFF_3 459
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_3 479

#define CONFIG_ESDM_APT_CUTOFF_4 477
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_4 494

#define CONFIG_ESDM_APT_CUTOFF_5 488
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_5 502

#define CONFIG_ESDM_APT_CUTOFF_6 494
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_6 507

#define CONFIG_ESDM_APT_CUTOFF_7 499
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_7 510

#define CONFIG_ESDM_APT_CUTOFF_8 502
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_8 512

#define CONFIG_ESDM_APT_CUTOFF_9 505
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_9 512

#define CONFIG_ESDM_APT_CUTOFF_10 507
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_10 512

#define CONFIG_ESDM_APT_CUTOFF_11 508
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_11 512

#define CONFIG_ESDM_APT_CUTOFF_12 509
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_12 512

#define CONFIG_ESDM_APT_CUTOFF_13 510
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_13 512

#define CONFIG_ESDM_APT_CUTOFF_14 511
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_14 512

#define CONFIG_ESDM_APT_CUTOFF_15 512
#define CONFIG_ESDM_APT_CUTOFF_PERMANENT_15 512

/* The APT cutoffs above indexed by OSR - 1, as array initializers */
#define ESDM_APT_CUTOFFS                                                       \
	{ CONFIG_ESDM_APT_CUTOFF_1,  CONFIG_ESDM_APT_CUTOFF_2,                 \
	  CONFIG_ESDM_APT_CUTOFF_3,  CONFIG_ESDM_APT_CUTOFF_4,                 \
	  CONFIG_ESDM_APT_CUTOFF_5,  CONFIG_ESDM_APT_CUTOFF_6,                 \
	  CONFIG_ESDM_APT_CUTOFF_7,  CONFIG_ESDM_APT_CUTOFF_8,                 \
	  CONFIG_ESDM_APT_CUTOFF_9,  CONFIG_ESDM_APT_CUTOFF_10,                \
	  CONFIG_ESDM_APT_CUTOFF_11, CONFIG_ESDM_APT_CUTOFF_12,                \
	  CONFIG_ESDM_APT_CUTOFF_13, CONFIG_ESDM_APT_CUTOFF_14,                \
	  CONFIG_ESDM_APT_CUTOFF_15 }
#define ESDM_APT_CUTOFFS_PERMANENT                                             \
	{ CONFIG_ESDM_APT_CUTOFF_PERMANENT_1,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_2,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_3,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_4,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_5,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_6,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_7,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_8,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_9,                                  \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_10,                                 \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_11,                                 \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_12,                                 \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_13,                                 \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_14,                                 \
	  CONFIG_ESDM_APT_CUTOFF_PERMANENT_15 }

/* Number of entries of ESDM_APT_CUTOFFS and ESDM_APT_CUTOFFS_PERMANENT */
#define ESDM_APT_CUTOFFS_NUM 15

#endif /* _ESDM_HEALTH_CUTOFFS_H */
