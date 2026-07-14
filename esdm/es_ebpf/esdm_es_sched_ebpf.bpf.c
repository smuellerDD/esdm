// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM eBPF-based scheduler entropy source: eBPF program
 *
 * Collects the timing of scheduler context switches via the stable
 * sched_switch tracepoint. The tracepoint arguments are deliberately not
 * accessed: only the event timing is of interest, which also keeps the
 * program independent of the sched_switch signature change in Linux 5.18.
 *
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
 */

#include "esdm_es_ebpf_common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp_btf/sched_switch")
int esdm_sched_switch(void *ctx)
{
	(void)ctx;

	esdm_ebpf_collect();

	return 0;
}
