// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM eBPF-based interrupt entropy source: eBPF program
 *
 * Collects the timing of hardware and soft interrupts via the stable
 * irq_handler_entry and softirq_entry tracepoints. The tracepoint arguments
 * are deliberately not accessed: only the event timing is of interest.
 *
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
 */

#include "esdm_es_ebpf_common.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tp_btf/irq_handler_entry")
int esdm_irq_handler_entry(void *ctx)
{
	(void)ctx;

	esdm_ebpf_collect();

	return 0;
}

SEC("tp_btf/softirq_entry")
int esdm_softirq_entry(void *ctx)
{
	(void)ctx;

	esdm_ebpf_collect();

	return 0;
}
