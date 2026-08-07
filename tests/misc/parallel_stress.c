/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
 * Stress test for parallel reads and writes.
 *
 * The device tests next to this one drive one request at a time. This one
 * loads every CPU with a reader and a writer on both device files at once and
 * then reads them again, which is what gets requests to overlap - and what
 * catches a daemon that does not survive the load, checked for at the end.
 *
 * The load is spread over processes rather than threads because the CUSE
 * handlers look at who is asking, so one caller per worker is closer to what
 * they see in the field.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "env.h"
#include "helper.h"
#include "privileges.h"

/*
 * What one worker asks of its device file, per request size. A request count
 * rather than an amount of data, so that the small sizes - the expensive ones,
 * one round trip each - do not decide how long the test takes.
 */
#define STRESS_ROUNDS 64

/* Every worker is spawned per CPU, and there are five of them per round */
#define MAX_WORKERS 4096

/*
 * The request sizes to spread the load over: the small ones cost a round trip
 * each and so keep the daemon busy, the large ones move the data.
 */
static const size_t stress_sizes[] = { 16, 32, 64, 128, 256, 512, 1024, 4096 };

static pid_t workers[MAX_WORKERS];
static size_t worker_count = 0;

static int read_complete(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	if (buflen > INT_MAX)
		return 1;

	do {
		ret = read(fd, buf, buflen);
		if (0 < ret) {
			buflen -= (size_t)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno) && buflen);

	if (buflen)
		printf("Error code from read system call: %d\n", errno);

	return buflen ? 1 : 0;
}

static int write_complete(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	if (buflen > INT_MAX)
		return 1;

	do {
		ret = write(fd, buf, buflen);
		if (0 < ret) {
			buflen -= (size_t)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno) && buflen);

	if (buflen)
		printf("Error code from write system call: %d\n", errno);

	return buflen ? 1 : 0;
}

/*
 * One worker's share of the load: every request size in turn, the device file
 * held open across all of them the way a reader in the field holds it.
 */
static int stress_device(const char *devfile, int write_device)
{
	uint8_t buf[4096];
	unsigned int i;
	int fd, ret = 0;

	fd = open(devfile, (write_device ? O_WRONLY : O_RDONLY) | O_CLOEXEC);
	if (0 > fd) {
		printf("Cannot open file %s: %d\n", devfile, errno);
		return 1;
	}

	memset(buf, 1, sizeof(buf));

	for (i = 0; i < ARRAY_SIZE(stress_sizes); i++) {
		unsigned int round;

		for (round = 0; round < STRESS_ROUNDS; round++) {
			ret = write_device ?
				      write_complete(fd, buf, stress_sizes[i]) :
				      read_complete(fd, buf, stress_sizes[i]);
			if (ret)
				goto out;
		}
	}

out:
	close(fd);
	return ret;
}

static int spawn_worker(const char *devfile, int write_device)
{
	pid_t pid;

	if (worker_count >= ARRAY_SIZE(workers)) {
		printf("More workers than this test holds\n");
		return 1;
	}

	pid = fork();
	if (0 > pid) {
		printf("Cannot fork a worker: %d\n", errno);
		return 1;
	}

	/*
	 * _exit() rather than a return: the environment belongs to the parent
	 * and a worker must not tear it down on its way out.
	 */
	if (pid == 0)
		_exit(stress_device(devfile, write_device) ? 1 : 0);

	workers[worker_count++] = pid;

	return 0;
}

static int wait_workers(void)
{
	size_t i;
	int ret = 0;

	for (i = 0; i < worker_count; i++) {
		int status;

		if (waitpid(workers[i], &status, 0) != workers[i]) {
			printf("Cannot wait for worker PID %u: %d\n",
			       workers[i], errno);
			ret = 1;
			continue;
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status)) {
			printf("Worker PID %u failed\n", workers[i]);
			ret = 1;
		}
	}

	worker_count = 0;

	return ret;
}

int main(int argc, char *argv[])
{
	char random_dev[32], urandom_dev[32];
	long cpus, i;
	int ret;

	(void)argv;

	if (!argc)
		return 1;

	esdm_cuse_dev_file(random_dev, sizeof(random_dev), "random");
	esdm_cuse_dev_file(urandom_dev, sizeof(urandom_dev), "urandom");

	ret = env_init(1);
	if (ret)
		return ret;

	drop_privileges();

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (0 >= cpus)
		cpus = 1;
	if (cpus > (long)(ARRAY_SIZE(workers) / 4))
		cpus = (long)(ARRAY_SIZE(workers) / 4);

	/* Read and write both device files on every CPU at once */
	for (i = 0; i < cpus; i++) {
		if (spawn_worker(urandom_dev, 0) ||
		    spawn_worker(random_dev, 0) ||
		    spawn_worker(urandom_dev, 1) ||
		    spawn_worker(random_dev, 1)) {
			ret = 1;
			goto out;
		}
	}

	ret = wait_workers();
	if (ret)
		goto out;

	/* ... and read again once all that was written is in */
	for (i = 0; i < cpus; i++) {
		if (spawn_worker(random_dev, 0)) {
			ret = 1;
			goto out;
		}
	}

	ret = wait_workers();
	if (ret)
		goto out;

	if (!env_daemons_alive()) {
		printf("Stress testing terminated the ESDM daemons\n");
		ret = 1;
		goto out;
	}

	printf("Stress testing passed\n");

out:
	/* Whatever is still running when the test gives up early */
	wait_workers();
	env_fini();

	return ret;
}
