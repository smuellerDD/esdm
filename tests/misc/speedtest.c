/*
 * Copyright (C) 2018 - 2026, Stephan Mueller <smueller@chronox.de>
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
 * How fast random data arrives, one request size at a time - out of
 * getrandom(), or out of a device file named with -f.
 *
 * Built three ways, which is what the -DESDM_SPEEDTEST_* defines select: as a
 * plain tool to run by hand against whatever the machine offers, and as the two
 * testers that bring an ESDM of their own up and measure it through the
 * getrandom library and through the CUSE device files respectively.
 */

/*
 * Shall the GLIBC getrandom stub be used (requires GLIBC >= 2.25)
 */
#define USE_GLIBC_GETRANDOM

#ifdef USE_GLIBC_GETRANDOM
#include <sys/random.h>
#else
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __x86_64__
#include <cpuid.h>
#endif

#if defined(ESDM_SPEEDTEST_GETRANDOM_ENV) || defined(ESDM_SPEEDTEST_CUSE_ENV)
#include "env.h"
#endif
#ifdef ESDM_SPEEDTEST_CUSE_ENV
#include "privileges.h"
#endif

/* What one request size costs, and where the data comes from */
struct opts {
	uint64_t exectime;
	size_t buflen;

	/* The device file to read, or NULL for getrandom() */
	const char *devfile;
};

/* As many sources as the CUSE tester measures, and as many sizes as -b takes */
#define MAXSOURCES 2
#define MAXLEN 16

/*
 * This is x86 specific to reduce the CPU jitter
 */
static inline void cpusetup(void)
{
#ifdef __x86_64__
	volatile unsigned int a, b, c, d;

	__cpuid_count(0, 0, a, b, c, d);
	__cpuid_count(0, 0, a, b, c, d);
	__cpuid_count(0, 0, a, b, c, d);
#endif
}

static inline uint64_t ts2u64(struct timespec *ts)
{
	return (uint64_t)((uint64_t)ts->tv_sec * 1000000000 +
			  (uint64_t)ts->tv_nsec);
}

static inline void get_nstime(struct timespec *ts)
{
	clock_gettime(CLOCK_MONOTONIC, ts);
}

static inline void start_time(struct timespec *ts)
{
	cpusetup();
	get_nstime(ts);
}

static inline void end_time(struct timespec *ts)
{
	get_nstime(ts);
}

/*
 * Convert an integer value into a string value that displays the integer
 * in either bytes, kB, or MB
 *
 * @bytes value to convert -- input
 * @str already allocated buffer for converted string -- output
 * @strlen size of str
 */
static void bytes2string(uint64_t bytes, uint64_t ns, char *str, size_t strlen)
{
	long double seconds = (long double)ns / 1000000000;
	long double bytes_per_second;

	if (!ns) {
		snprintf(str, strlen, "unmeasured");
		return;
	}

	bytes_per_second = bytes / seconds;

	if (1000000000 < bytes_per_second) {
		bytes_per_second /= 1000000000;
		snprintf(str, strlen, "%Lf GB", bytes_per_second);
		return;

	} else if (1000000 < bytes_per_second) {
		bytes_per_second /= 1000000;
		snprintf(str, strlen, "%Lf MB", bytes_per_second);
		return;
	} else if (1000 < bytes_per_second) {
		bytes_per_second /= 1000;
		snprintf(str, strlen, "%Lf kB", bytes_per_second);
		return;
	}
	snprintf(str, strlen, "%Lf B", bytes_per_second);
	str[strlen - 1] = '\0';
}

/* What the source under measurement is called in the output */
static const char *source_name(struct opts *opts)
{
	return opts->devfile ? opts->devfile : "getrandom";
}

static int print_status(struct opts *opts, uint64_t processed_bytes,
			uint64_t totaltime)
{
#define VALLEN 20
	char byteseconds[VALLEN + 1];

	memset(byteseconds, 0, sizeof(byteseconds));
	bytes2string(processed_bytes, totaltime, byteseconds, (VALLEN + 1));
	/* Wide enough for the longest device file name, /dev/tst-urandom */
	printf("%-16s |%8zu bytes | %*s/s | %12" PRIu64 " bytes |%12" PRIu64
	       " ns\n",
	       source_name(opts), opts->buflen, VALLEN, byteseconds,
	       processed_bytes, totaltime);

	return 0;
}

/*
 * One request out of the source under measurement. A device file is read the
 * way a caller in the field reads it - one read() per request, held open across
 * all of them, which is what the round trip to the CUSE daemon costs.
 */
static ssize_t speedtest_request(struct opts *opts, int fd, uint8_t *buffer)
{
	if (0 <= fd)
		return read(fd, buffer, opts->buflen);

#ifdef USE_GLIBC_GETRANDOM
	return getrandom(buffer, opts->buflen, 0);
#else
	return syscall(__NR_getrandom, buffer, opts->buflen, 0);
#endif
}

static int speedtest(struct opts *opts)
{
	uint64_t testduration = 0;
	uint64_t totaltime = 0;
	uint64_t bytes = 0;
	uint64_t nano = 1000000000;
	uint8_t *buffer = malloc(opts->buflen);
	int fd = -1;
	int ret;

	if (!buffer)
		return -ENOMEM;

	if (opts->devfile) {
		fd = open(opts->devfile, O_RDONLY | O_CLOEXEC);
		if (0 > fd) {
			printf("Cannot open file %s: %d\n", opts->devfile,
			       errno);
			ret = -errno;
			goto out;
		}
	}

	testduration = nano * opts->exectime;

	while (totaltime < testduration) {
		struct timespec start;
		struct timespec end;
		ssize_t received;

		start_time(&start);
		received = speedtest_request(opts, fd, buffer);
		end_time(&end);
		if (received < 0) {
			if (EINTR == errno)
				continue;
			ret = -errno;
			goto out;
		}
		/* A source that answers nothing would never end the loop */
		if (!received) {
			printf("Source %s delivered no data\n",
			       source_name(opts));
			ret = -EIO;
			goto out;
		}
		totaltime += (ts2u64(&end) - ts2u64(&start));
		bytes += (uint64_t)received;
	}

	ret = print_status(opts, bytes, totaltime);

out:
	if (0 <= fd)
		close(fd);
	free(buffer);
	return ret;
}

/*
 * The sources measured when -f names none. The plain tool has getrandom() and
 * nothing else to go on; the CUSE tester has the two device files its
 * environment just mounted, which is what the shell script this replaces
 * measured with dd.
 */
static unsigned int speedtest_default_sources(const char **sources,
					      char devfiles[MAXSOURCES][32])
{
#ifdef ESDM_SPEEDTEST_CUSE_ENV
	esdm_cuse_dev_file(devfiles[0], sizeof(devfiles[0]), "random");
	esdm_cuse_dev_file(devfiles[1], sizeof(devfiles[1]), "urandom");
	sources[0] = devfiles[0];
	sources[1] = devfiles[1];

	return 2;
#else
	(void)devfiles;

	/* getrandom() */
	sources[0] = NULL;

	return 1;
#endif
}

/*
 * An ESDM to measure. The plain tool takes the machine as it finds it, the two
 * testers bring one up of their own - the fallback to the kernel disabled, so
 * that what is measured is the ESDM and not the kernel behind it.
 */
static int speedtest_env_init(void)
{
#if defined(ESDM_SPEEDTEST_GETRANDOM_ENV)
	return env_init();
#elif defined(ESDM_SPEEDTEST_CUSE_ENV)
	int ret = env_init(1);

	if (ret)
		return ret;

	drop_privileges();

	return 0;
#else
	return 0;
#endif
}

static void speedtest_env_fini(void)
{
#if defined(ESDM_SPEEDTEST_GETRANDOM_ENV) || defined(ESDM_SPEEDTEST_CUSE_ENV)
	env_fini();
#endif
}

int main(int argc, char *argv[])
{
	struct opts opts;
	char devfiles[MAXSOURCES][32];
	const char *sources[MAXSOURCES];
	size_t buflens[MAXLEN];
	unsigned int i, s, lens = 0, nsources = 0;
	int c = 0, ret;

	opts.exectime = 2;
	opts.buflen = 4096;
	opts.devfile = NULL;

	while (1) {
		int opt_index = 0;
		static struct option options[] = { { "exectime", 1, 0, 'e' },
						   { "buflen", 1, 0, 'b' },
						   { "file", 1, 0, 'f' },
						   { 0, 0, 0, 0 } };
		c = getopt_long(argc, argv, "e:b:f:", options, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 'e':
			opts.exectime = strtoul(optarg, NULL, 10);
			if (opts.exectime == ULONG_MAX)
				return EINVAL;
			break;
		case 'b':
			if (lens >= MAXLEN)
				return EINVAL;
			buflens[lens] = strtoul(optarg, NULL, 10);
			lens++;
			break;
		case 'f':
			if (nsources >= MAXSOURCES)
				return EINVAL;
			sources[nsources] = optarg;
			nsources++;
			break;
		default:
			return EINVAL;
		}
	}

	/* The single default size, so that the loops below cover both cases */
	if (!lens) {
		buflens[0] = opts.buflen;
		lens = 1;
	}

	if (!nsources)
		nsources = speedtest_default_sources(sources, devfiles);

	ret = speedtest_env_init();
	if (ret)
		return ret;

	for (s = 0; s < nsources; s++) {
		opts.devfile = sources[s];

		for (i = 0; i < lens; i++) {
			opts.buflen = buflens[i];
			ret = speedtest(&opts);
			if (ret) {
				ret = -ret;
				goto out;
			}
		}
	}

out:
	speedtest_env_fini();

	return ret;
}
