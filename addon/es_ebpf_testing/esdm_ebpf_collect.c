/*
 * ESDM eBPF entropy sources: raw event time stamp collector
 *
 * Standalone tool gathering raw, unconditioned event time stamps from the
 * eBPF entropy source programs for SP800-90B / AIS 20/31 entropy assessment.
 * The output file contains the verbatim struct esdm_ebpf_raw_rec records
 * (16 bytes each: u32 type, u32 cpu, u64 timestamp; host endianness).
 *
 * THIS TOOL IS FOR MEASUREMENT AND VALIDATION ONLY. It refuses to operate
 * when the kernel FIPS mode is enabled.
 *
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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "config.h"
#include "esdm_es_ebpf_shared.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#ifdef ESDM_ES_SCHED_EBPF
#include "esdm_es_sched_ebpf.skel.h"
#endif
#ifdef ESDM_ES_IRQ_EBPF
#include "esdm_es_irq_ebpf.skel.h"
#endif
#pragma GCC diagnostic pop

#define ESDM_COLLECT_RB_SIZE (16 * 1024 * 1024)

struct collect_ctx {
	FILE *out;
	unsigned long long events;
	unsigned long long limit;
	unsigned long long write_errors;
};

static volatile sig_atomic_t stop_requested;

static void sig_handler(int sig)
{
	(void)sig;
	stop_requested = 1;
}

static int handle_record(void *ctx, void *data, size_t size)
{
	struct collect_ctx *cctx = ctx;
	const struct esdm_ebpf_raw_rec *rec = data;

	if (size < sizeof(*rec) || rec->type != esdm_ebpf_rec_raw)
		return 0;

	if (fwrite(rec, sizeof(*rec), 1, cctx->out) != 1)
		cctx->write_errors++;
	else
		cctx->events++;

	return 0;
}

static bool fips_mode_enabled(void)
{
	char buf[4] = { 0 };
	int fd = open("/proc/sys/crypto/fips_enabled", O_RDONLY);
	bool enabled = false;

	if (fd < 0)
		return false;

	if (read(fd, buf, sizeof(buf) - 1) > 0)
		enabled = (buf[0] == '1');
	close(fd);

	return enabled;
}

/* Open a CPU cycle counter perf event on every possible CPU */
static int perf_setup(int **fds_out, unsigned int nr_cpus)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(struct perf_event_attr),
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	int *fds;
	unsigned int cpu, opened = 0;

	fds = calloc(nr_cpus, sizeof(int));
	if (!fds)
		return -ENOMEM;

	for (cpu = 0; cpu < nr_cpus; cpu++)
		fds[cpu] = -1;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		int fd = (int)syscall(__NR_perf_event_open, &attr, -1, (int)cpu,
				      -1, PERF_FLAG_FD_CLOEXEC);

		if (fd < 0) {
			if (errno == ENODEV || errno == ENXIO)
				continue; /* offline CPU */

			fprintf(stderr,
				"CPU cycle counter unavailable on CPU %u: %s\n",
				cpu, strerror(errno));
			for (cpu = 0; cpu < nr_cpus; cpu++) {
				if (fds[cpu] >= 0)
					close(fds[cpu]);
			}
			free(fds);
			return -EOPNOTSUPP;
		}
		fds[cpu] = fd;
		opened++;
	}

	if (!opened) {
		free(fds);
		return -EOPNOTSUPP;
	}

	*fds_out = fds;
	return 0;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s --source sched|irq --out FILE [OPTIONS]\n"
		"\n"
		"Collect raw event time stamps of the eBPF entropy sources.\n"
		"\n"
		"Options:\n"
		"\t--source, -s sched|irq  Entropy source to collect from\n"
		"\t--out, -o FILE          Output file (raw records)\n"
		"\t--events, -e N          Stop after N events (default: 10000000)\n"
		"\t--tier, -t 2|3          Timestamp: 2 = CPU cycle counter (perf),\n"
		"\t                        3 = monotonic clock (default: 2 with\n"
		"\t                        fallback to 3)\n"
		"\t--help, -h              This help\n",
		name);
}

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "source", required_argument, NULL, 's' },
		{ "out", required_argument, NULL, 'o' },
		{ "events", required_argument, NULL, 'e' },
		{ "tier", required_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	struct collect_ctx cctx = { .limit = 10000000 };
	struct bpf_object *obj = NULL;
	struct bpf_map *rb_map, *status_map, *perf_map, *timers_map;
	struct bpf_link *links[2] = { NULL, NULL };
	struct bpf_program *prog;
	struct ring_buffer *rb = NULL;
	struct esdm_ebpf_status status = { .reset_gen = 1 };
	struct esdm_ebpf_config *cfg = NULL;
	const char *source = NULL, *outfile = NULL;
	time_t start;
	int *perf_fds = NULL;
	unsigned int nr_cpus;
	int c, ret = 1, tier = 0, effective_tier = 3;
	uint32_t zero = 0;

#ifdef ESDM_ES_SCHED_EBPF
	struct esdm_es_sched_ebpf_bpf *sched_skel = NULL;
#endif
#ifdef ESDM_ES_IRQ_EBPF
	struct esdm_es_irq_ebpf_bpf *irq_skel = NULL;
#endif

	while ((c = getopt_long(argc, argv, "s:o:e:t:h", opts, NULL)) != -1) {
		switch (c) {
		case 's':
			source = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'e':
			cctx.limit = strtoull(optarg, NULL, 10);
			break;
		case 't':
			tier = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!source || !outfile || (tier && tier != 2 && tier != 3)) {
		usage(argv[0]);
		return 1;
	}

	if (fips_mode_enabled()) {
		fprintf(stderr,
			"Raw entropy data collection is not permitted in FIPS mode\n");
		return 1;
	}

	nr_cpus = (unsigned int)libbpf_num_possible_cpus();

	/* Open the requested skeleton and locate its configuration */
	if (!strcmp(source, "sched")) {
#ifdef ESDM_ES_SCHED_EBPF
		sched_skel = esdm_es_sched_ebpf_bpf__open();
		if (!sched_skel)
			goto out;
		obj = sched_skel->obj;
		cfg = (struct esdm_ebpf_config *)&sched_skel->rodata
			      ->esdm_ebpf_cfg;
#endif
	} else if (!strcmp(source, "irq")) {
#ifdef ESDM_ES_IRQ_EBPF
		irq_skel = esdm_es_irq_ebpf_bpf__open();
		if (!irq_skel)
			goto out;
		obj = irq_skel->obj;
		cfg = (struct esdm_ebpf_config *)&irq_skel->rodata
			      ->esdm_ebpf_cfg;
#endif
	}

	if (!obj || !cfg) {
		fprintf(stderr, "Unknown or unsupported source: %s\n", source);
		return 1;
	}

	/* Timestamp tier selection */
	if (tier != 3) {
		if (perf_setup(&perf_fds, nr_cpus) == 0) {
			cfg->use_perf_counter = 1;
			effective_tier = 2;
		} else if (tier == 2) {
			fprintf(stderr,
				"Requested tier 2 but the CPU cycle counter is not available\n");
			goto out;
		}
	}

	cfg->raw_sampling = 1;
	cfg->health_enabled = 0;
	cfg->flush_timer_enabled = 0;

	rb_map = bpf_object__find_map_by_name(obj, "esdm_ebpf_rb");
	status_map = bpf_object__find_map_by_name(obj, "esdm_ebpf_status_map");
	perf_map = bpf_object__find_map_by_name(obj, "esdm_ebpf_perf");
	timers_map = bpf_object__find_map_by_name(obj, "esdm_ebpf_timers");
	if (!rb_map || !status_map || !perf_map || !timers_map)
		goto out;

	if (bpf_map__set_max_entries(rb_map, ESDM_COLLECT_RB_SIZE) ||
	    bpf_map__set_max_entries(perf_map, nr_cpus) ||
	    bpf_map__set_max_entries(timers_map, nr_cpus))
		goto out;

	if (bpf_object__load(obj)) {
		fprintf(stderr, "Cannot load the eBPF object\n");
		goto out;
	}

	if (bpf_map__update_elem(status_map, &zero, sizeof(zero), &status,
				 sizeof(status), 0))
		goto out;

	if (perf_fds) {
		uint32_t cpu;

		for (cpu = 0; cpu < nr_cpus; cpu++) {
			if (perf_fds[cpu] < 0)
				continue;
			if (bpf_map__update_elem(perf_map, &cpu, sizeof(cpu),
						 &perf_fds[cpu],
						 sizeof(perf_fds[cpu]), 0)) {
				fprintf(stderr,
					"Cannot set cycle counter for CPU %u\n",
					cpu);
				goto out;
			}
		}
	}

	cctx.out = fopen(outfile, "wx");
	if (!cctx.out) {
		fprintf(stderr, "Cannot create %s: %s\n", outfile,
			strerror(errno));
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(rb_map), handle_record, &cctx, NULL);
	if (!rb)
		goto out;

	/* Attach all programs of the object */
	bpf_object__for_each_program(prog, obj)
	{
		size_t i;

		for (i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
			if (!links[i]) {
				links[i] = bpf_program__attach(prog);
				if (!links[i]) {
					fprintf(stderr,
						"Cannot attach program %s\n",
						bpf_program__name(prog));
					goto out;
				}
				break;
			}
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	fprintf(stderr,
		"Collecting %llu raw %s events (timestamp tier %d) into %s ...\n",
		cctx.limit, source, effective_tier, outfile);

	start = time(NULL);
	while (!stop_requested && cctx.events < cctx.limit) {
		if (ring_buffer__poll(rb, 200) < 0 && errno != EINTR)
			break;
	}

	{
		time_t duration = time(NULL) - start;
		unsigned long long rate =
			duration > 0 ?
				cctx.events / (unsigned long long)duration :
				      cctx.events;

		fprintf(stderr,
			"Collected %llu events in %ld seconds (%llu events/s), %llu write errors\n",
			cctx.events, (long)duration, rate, cctx.write_errors);
	}

	ret = cctx.write_errors ? 1 : 0;

out:
	if (rb)
		ring_buffer__free(rb);
	for (c = 0; c < 2; c++) {
		if (links[c])
			bpf_link__destroy(links[c]);
	}
	if (cctx.out)
		fclose(cctx.out);
	if (perf_fds) {
		unsigned int cpu;

		for (cpu = 0; cpu < nr_cpus; cpu++) {
			if (perf_fds[cpu] >= 0)
				close(perf_fds[cpu]);
		}
		free(perf_fds);
	}
#ifdef ESDM_ES_SCHED_EBPF
	if (sched_skel)
		esdm_es_sched_ebpf_bpf__destroy(sched_skel);
#endif
#ifdef ESDM_ES_IRQ_EBPF
	if (irq_skel)
		esdm_es_irq_ebpf_bpf__destroy(irq_skel);
#endif

	return ret;
}
