/*
 * ESDM eBPF entropy sources: raw time delta collector
 *
 * Standalone tool gathering raw, unconditioned event timing from the eBPF
 * entropy source programs for SP800-90B entropy assessment. It writes the
 * time between successive events of a CPU as decimal ASCII, one delta per
 * line - the format extractlsb(1) of addon/test reads, which turns it into
 * the byte stream the NIST tools assess:
 *
 *     esdm-ebpf-collect --source sched --cpu 0 --out raw.txt --events 1000000
 *     extractlsb raw.txt raw.bin 1000000 FF
 *     ea_non_iid raw.bin 8
 *
 * The eBPF program forms the deltas, each between two events its CPU observed
 * back to back, so a record the ring buffer had no room for costs a sample and
 * distorts nothing.
 *
 * Without --cpu the deltas of all CPUs are written into one stream in arrival
 * order. That is convenient for a quick look, but the CPUs are separate noise
 * sources and the stream carries no way to tell them apart again - assess one
 * CPU at a time.
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
#include <limits.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/*
 * Returned by handle_record() once the requested number of events was
 * collected. libbpf aborts the ring buffer consumption on a negative callback
 * return value and propagates it to ring_buffer__poll(), which lets the
 * collection loop distinguish the completion from an actual polling error.
 */
#define ESDM_COLLECT_DONE (-ECANCELED)

struct collect_ctx {
	FILE *out;
	/* Deltas written, i.e. what the assessment gets */
	unsigned long long deltas;
	unsigned long long limit;
	unsigned long long write_errors;
	/* CPU to write, or -1 for all of them in one stream */
	int only_cpu;
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

	/*
	 * A single ring_buffer__poll() call hands over every record the eBPF
	 * program deposited since the last call, so the collection loop can
	 * only re-check the limit once the whole batch was consumed. Enforce
	 * it here to keep the output file at exactly the requested number of
	 * deltas.
	 */
	if (cctx->deltas >= cctx->limit)
		return ESDM_COLLECT_DONE;

	if (size < sizeof(*rec) || rec->type != esdm_ebpf_rec_raw)
		return 0;

	if (cctx->only_cpu >= 0 && rec->cpu != (uint32_t)cctx->only_cpu)
		return 0;

	if (fprintf(cctx->out, "%llu\n", (unsigned long long)rec->delta) < 0) {
		cctx->write_errors++;
		return 0;
	}

	cctx->deltas++;

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

static int parse_ull(const char *arg, unsigned long long *out)
{
	char *end;
	unsigned long long val;

	errno = 0;
	val = strtoull(arg, &end, 10);
	if (errno || end == arg || *end)
		return -EINVAL;

	*out = val;
	return 0;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s --source sched|irq --out FILE [OPTIONS]\n"
		"\n"
		"Collect raw event time deltas of the eBPF entropy sources as\n"
		"decimal ASCII, one per line - the input format of extractlsb.\n"
		"\n"
		"Options:\n"
		"\t--source, -s sched|irq  Entropy source to collect from\n"
		"\t--out, -o FILE          Output file (one delta per line)\n"
		"\t--events, -e N          Stop after N deltas (default: 10000000)\n"
		"\t--cpu, -c N             Only write the deltas of CPU N. Without\n"
		"\t                        it the deltas of all CPUs go into one\n"
		"\t                        stream in arrival order, which is handy\n"
		"\t                        to look at but mixes what are separate\n"
		"\t                        noise sources - assess one CPU at a\n"
		"\t                        time.\n"
		"\t--help, -h              This help\n"
		"\n"
		"A delta is only written for two events known to be consecutive\n"
		"observations of one CPU, so a sample the eBPF program had to drop\n"
		"ends the run of deltas rather than distorting one.\n"
		"\n"
		"The timer granularity (GCD) is always divided out of the time\n"
		"stamps, exactly as the ESDM server does, so that the assessed\n"
		"signal is the one that enters the entropy pool.\n",
		name);
}

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "source", required_argument, NULL, 's' },
		{ "out", required_argument, NULL, 'o' },
		{ "events", required_argument, NULL, 'e' },
		{ "cpu", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	struct collect_ctx cctx = { .limit = 10000000, .only_cpu = -1 };
	struct bpf_object *obj = NULL;
	struct bpf_map *rb_map, *status_map, *timers_map;
	struct bpf_link **links = NULL;
	struct bpf_program *prog;
	struct ring_buffer *rb = NULL;
	struct esdm_ebpf_status status = { .reset_gen = 1 };
	struct esdm_ebpf_config *cfg = NULL;
	const char *source = NULL, *outfile = NULL;
	size_t nr_progs = 0, nr_links = 0, i;
	time_t start;
	int nr_cpus_ret;
	unsigned int nr_cpus = 0;
	int c, ret = 1;
	uint32_t zero = 0;

#ifdef ESDM_ES_SCHED_EBPF
	struct esdm_es_sched_ebpf_bpf *sched_skel = NULL;
#endif
#ifdef ESDM_ES_IRQ_EBPF
	struct esdm_es_irq_ebpf_bpf *irq_skel = NULL;
#endif

	while ((c = getopt_long(argc, argv, "s:o:e:c:h", opts, NULL)) != -1) {
		switch (c) {
		case 's':
			source = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'e':
			if (parse_ull(optarg, &cctx.limit) || !cctx.limit) {
				fprintf(stderr,
					"Invalid event count: %s (expected a positive number)\n",
					optarg);
				return 1;
			}
			break;
		case 'c': {
			unsigned long long cpu;

			if (parse_ull(optarg, &cpu) || cpu > INT_MAX) {
				fprintf(stderr,
					"Invalid CPU: %s (expected a CPU number)\n",
					optarg);
				return 1;
			}
			cctx.only_cpu = (int)cpu;
			break;
		}
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!source || !outfile) {
		usage(argv[0]);
		return 1;
	}

	if (fips_mode_enabled()) {
		fprintf(stderr,
			"Raw entropy data collection is not permitted in FIPS mode\n");
		return 1;
	}

	nr_cpus_ret = libbpf_num_possible_cpus();
	if (nr_cpus_ret < 1) {
		fprintf(stderr,
			"Cannot determine the number of possible CPUs\n");
		return 1;
	}
	nr_cpus = (unsigned int)nr_cpus_ret;

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
		goto out;
	}

	cfg->raw_sampling = 1;
	cfg->health_enabled = 0;

	rb_map = bpf_object__find_map_by_name(obj, "esdm_ebpf_rb");
	status_map = bpf_object__find_map_by_name(obj, "esdm_ebpf_status_map");
	timers_map = bpf_object__find_map_by_name(obj, "esdm_ebpf_timers");
	if (!rb_map || !status_map || !timers_map)
		goto out;

	if (bpf_map__set_max_entries(rb_map, ESDM_COLLECT_RB_SIZE) ||
	    bpf_map__set_max_entries(timers_map, nr_cpus))
		goto out;

	/*
	 * The zeroization of the ring buffer is of no use to a measurement run
	 * that writes the very same deltas to a file, so it is left out of the
	 * load - which also keeps this tool working on kernels that do not
	 * support the BPF syscall programs it is implemented with.
	 */
	prog = bpf_object__find_program_by_name(obj, ESDM_EBPF_WIPE_PROG_NAME);
	if (prog)
		bpf_program__set_autoload(prog, false);

	if (bpf_object__load(obj)) {
		fprintf(stderr, "Cannot load the eBPF object\n");
		goto out;
	}

	if (bpf_map__update_elem(status_map, &zero, sizeof(zero), &status,
				 sizeof(status), 0))
		goto out;

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
		nr_progs++;
	}

	if (!nr_progs) {
		fprintf(stderr, "The eBPF object contains no program\n");
		goto out;
	}

	links = calloc(nr_progs, sizeof(*links));
	if (!links)
		goto out;

	bpf_object__for_each_program(prog, obj)
	{
		/* A program kept out of the load has nothing to attach */
		if (bpf_program__fd(prog) < 0)
			continue;

		links[nr_links] = bpf_program__attach(prog);
		if (!links[nr_links]) {
			fprintf(stderr, "Cannot attach program %s\n",
				bpf_program__name(prog));
			goto out;
		}
		nr_links++;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	if (cctx.only_cpu >= 0)
		fprintf(stderr,
			"Collecting %llu raw %s deltas of CPU %d into %s ...\n",
			cctx.limit, source, cctx.only_cpu, outfile);
	else
		fprintf(stderr,
			"Collecting %llu raw %s deltas of all CPUs into %s ...\n",
			cctx.limit, source, outfile);

	start = time(NULL);
	while (!stop_requested && cctx.deltas < cctx.limit) {
		int poll_ret = ring_buffer__poll(rb, 200);

		if (poll_ret == ESDM_COLLECT_DONE)
			break;
		if (poll_ret < 0 && errno != EINTR)
			break;
	}

	{
		time_t duration = time(NULL) - start;
		unsigned long long rate =
			duration > 0 ?
				cctx.deltas / (unsigned long long)duration :
				      cctx.deltas;

		/*
		 * The time stamps exceed the deltas by the first one of each
		 * CPU, which has no predecessor to form a delta with, plus one
		 * for every segment a lost sample or a reset started.
		 */
		fprintf(stderr,
			"Collected %llu deltas in %ld seconds (%llu deltas/s), %llu write errors\n",
			cctx.deltas, (long)duration, rate, cctx.write_errors);
	}

	ret = cctx.write_errors ? 1 : 0;

out:
	if (rb)
		ring_buffer__free(rb);
	for (i = 0; i < nr_links; i++)
		bpf_link__destroy(links[i]);
	free(links);
	if (cctx.out) {
		/*
		 * The final buffer flush happens here - a write error at this
		 * point would otherwise escape the accounting above.
		 */
		if (fclose(cctx.out)) {
			fprintf(stderr, "Cannot write %s: %s\n", outfile,
				strerror(errno));
			ret = 1;
		}
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
