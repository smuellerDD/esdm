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
 * Test that the configuration of the interrupt and the scheduler entropy
 * source of the kernel add-on belongs to the descriptor of /dev/esdm_es it is
 * set on (see ESDM_IRQ_CONF in esdm_es_ioctl.h).
 *
 * Every ESDM opens the device, and every one sets the entropy rate it credits
 * the sources by whenever it asks how much entropy they hold. The ESDM credits
 * the scheduler source with nothing by default, which it tells the add-on as a
 * rate of U32_MAX. Kept by the add-on for all of its users, that left the
 * sources delivering nothing to an ESDM crediting them until that one set its
 * rate again - and credited for an ESDM crediting them with nothing in the
 * meantime. Running in parallel, the tests of the suite each bringing up an
 * ESDM of their own, the scheduler ES test read nothing in any of its rounds.
 *
 * Two descriptors: A keeps the configuration it was opened with, B credits
 * nothing and asks for a different amount of entropy. The source must hold
 * entropy for A and none for B, and A must read what it asks for; then A sets
 * its rate itself, which must not credit B.
 *
 * Whether a source holds enough for a read is up to the events it collects,
 * which other users of the add-on take as well - the tests running in parallel
 * among them. A read of A that does not deliver in time is therefore reported
 * but no failure: the entropy A finds available while B credits none is what
 * tells the configurations apart, which needs a fraction of the events.
 *
 * Skips (77) without /dev/esdm_es, i.e. everywhere but a machine carrying the
 * patched kernel and its esdm_es module, and without the privileges to open
 * it.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "esdm_es_ioctl.h"
#include "es_irq_events.h"

/* The security strength, which a request of every kernel may ask for */
#define ES_CONF_SECURITY_STRENGTH_BITS 256

/* Rounds of events to wait for the entropy A is after */
#define ES_CONF_ROUNDS 60U

/* The IOCTL numbers of the two sources, see esdm_es_ioctl.h */
struct es_ioctls {
	const char *name;
	unsigned long avail;
	unsigned long buf_size;
	/* ESDM_*_ENT_BUF_IOCTL(type): the size of the buffer goes in at run time */
	unsigned int ent_buf_nr;
	unsigned long conf;
	void (*generate)(void);
};

/* Scheduler events: tasks woken up */
static void es_conf_sched_events(void)
{
	unsigned int i;

	fflush(NULL);
	for (i = 0; i < 200; i++) {
		pid_t pid = fork();

		if (pid == 0)
			_exit(0);
		else if (pid > 0)
			waitpid(pid, NULL, 0);
	}
}

/* Interrupt events: the completions of reads from the disk */
static void es_conf_irq_events(void)
{
	es_irq_events(400);
}

static const struct es_ioctls es_conf_sources[] = {
	{ "Scheduler", ESDM_SCHED_AVAIL_ENTROPY, ESDM_SCHED_ENT_BUF_SIZE,
	  _IOC_NR(ESDM_SCHED_ENT_BUF_IOCTL(uint32_t)), ESDM_SCHED_CONF,
	  es_conf_sched_events },
	{ "Interrupt", ESDM_IRQ_AVAIL_ENTROPY, ESDM_IRQ_ENT_BUF_SIZE,
	  _IOC_NR(ESDM_IRQ_ENT_BUF_IOCTL(uint32_t)), ESDM_IRQ_CONF,
	  es_conf_irq_events },
};

static int es_conf_set(int fd, const struct es_ioctls *es, uint32_t bits,
		       uint32_t rate)
{
	uint32_t conf[2] = { bits, rate };

	if (ioctl(fd, es->conf, conf) < 0) {
		printf("ES %s configuration - fail: setting %u bits, rate %u: %s\n",
		       es->name, bits, rate, strerror(errno));
		return 1;
	}
	return 0;
}

static int64_t es_conf_avail(int fd, const struct es_ioctls *es)
{
	uint32_t ent;

	if (ioctl(fd, es->avail, &ent) < 0) {
		printf("ES %s configuration - fail: available entropy: %s\n",
		       es->name, strerror(errno));
		return -1;
	}
	return ent;
}

/*
 * Read the entropy buffer of @size bytes - struct entropy_buf of the add-on,
 * its seed followed by the entropy it is credited with. Returns the credited
 * bits, -1 on error. @zero tells whether the seed is all zero.
 */
static int64_t es_conf_read(int fd, const struct es_ioctls *es, uint8_t *buf,
			    uint32_t size, int *zero)
{
	uint32_t e_bits, i;

	memset(buf, 0, size);
	if (ioctl(fd, _IOC(_IOC_READ, ESDMIO, es->ent_buf_nr, size), buf) < 0) {
		printf("ES %s configuration - fail: reading the entropy buffer: %s\n",
		       es->name, strerror(errno));
		return -1;
	}

	memcpy(&e_bits, buf + size - sizeof(e_bits), sizeof(e_bits));
	*zero = 1;
	for (i = 0; i < size - sizeof(e_bits); i++) {
		if (buf[i]) {
			*zero = 0;
			break;
		}
	}

	return e_bits;
}

/* B must find nothing available, nor read anything */
static int es_conf_check_b(int fd_b, const struct es_ioctls *es, uint8_t *buf,
			   uint32_t size, const char *when)
{
	int64_t e_bits = es_conf_avail(fd_b, es);
	int zero;

	if (e_bits < 0)
		return 1;
	if (e_bits) {
		printf("ES %s configuration - fail: %s, %u bits available to the descriptor crediting nothing\n",
		       es->name, when, (uint32_t)e_bits);
		return 1;
	}

	e_bits = es_conf_read(fd_b, es, buf, size, &zero);
	if (e_bits < 0)
		return 1;
	if (e_bits || !zero) {
		printf("ES %s configuration - fail: %s, the descriptor crediting nothing read %u bits%s\n",
		       es->name, when, (uint32_t)e_bits,
		       zero ? "" : " and a seed");
		return 1;
	}

	return 0;
}

/*
 * Returns 0 on success, 1 on failure and 77 when the source is not part of
 * the add-on, or its entropy buffer not of a layout this test knows.
 */
static int es_conf_test(const struct es_ioctls *es, int fd_a, int fd_b)
{
	uint32_t size_es[2], requested_a, round;
	int64_t avail_a = 0, e_bits = 0;
	uint8_t *buf;
	int zero, ret = 1;

	if (ioctl(fd_a, es->buf_size, size_es) < 0) {
		if (errno == ENOTTY) {
			printf("ES %s configuration - skip: source not part of the add-on\n",
			       es->name);
			return 77;
		}
		printf("ES %s configuration - fail: buffer size: %s\n",
		       es->name, strerror(errno));
		return 1;
	}

	/* struct entropy_buf: a seed of whole words, then the bits credited */
	if (size_es[0] <= sizeof(uint32_t) || size_es[0] % sizeof(uint32_t) ||
	    size_es[0] > _IOC_SIZEMASK) {
		printf("ES %s configuration - skip: entropy buffer of %u bytes\n",
		       es->name, size_es[0]);
		return 77;
	}

	/* What a descriptor asks for until it is told otherwise */
	requested_a = (uint32_t)(size_es[0] - sizeof(uint32_t)) << 3;

	buf = malloc(size_es[0]);
	if (!buf)
		return 1;

	/*
	 * B credits nothing and asks for the security strength only - which
	 * every kernel accepts, with or without FIPS mode.
	 */
	if (es_conf_set(fd_b, es, ES_CONF_SECURITY_STRENGTH_BITS, UINT32_MAX))
		goto out;

	if (es_conf_check_b(fd_b, es, buf, size_es[0], "B configured"))
		goto out;

	/*
	 * A, left as it was opened, credits by the rate of the module: the
	 * source holds entropy for it once it collected some events, and A
	 * reads what it asks for once it collected enough.
	 */
	for (round = 0; round < ES_CONF_ROUNDS; round++) {
		int64_t avail = es_conf_avail(fd_a, es);

		if (avail < 0)
			goto out;
		if (avail > avail_a)
			avail_a = avail;

		if (avail) {
			e_bits = es_conf_read(fd_a, es, buf, size_es[0], &zero);
			if (e_bits < 0)
				goto out;
			if (e_bits) {
				if (zero) {
					printf("ES %s configuration - fail: %u bits credited to a zero buffer\n",
					       es->name, (uint32_t)e_bits);
					goto out;
				}
				break;
			}
		}

		es->generate();
	}

	if (!avail_a) {
		printf("ES %s configuration - fail: no entropy available to the descriptor crediting the source in %u rounds of events, B's rate applies to it\n",
		       es->name, ES_CONF_ROUNDS);
		goto out;
	}
	printf("ES %s configuration - pass: up to %u bits available to the descriptor crediting the source\n",
	       es->name, (uint32_t)avail_a);

	if (!e_bits) {
		printf("ES %s configuration - info: no read delivered in %u rounds of events, not enough collected\n",
		       es->name, ES_CONF_ROUNDS);
	} else if (e_bits != requested_a) {
		printf("ES %s configuration - fail: %u bits delivered instead of the %u asked for, B's request applies to it\n",
		       es->name, (uint32_t)e_bits, requested_a);
		goto out;
	} else {
		printf("ES %s configuration - pass: %u bits delivered as asked for\n",
		       es->name, (uint32_t)e_bits);
	}

	/*
	 * A sets a rate itself now - 1, which the module raises to the rate
	 * it was loaded with - which B must not be credited by.
	 */
	if (es_conf_set(fd_a, es, 0, 1))
		goto out;
	es->generate();

	if (es_conf_check_b(fd_b, es, buf, size_es[0], "A configured"))
		goto out;
	printf("ES %s configuration - pass: nothing available to or delivered to the descriptor crediting nothing\n",
	       es->name);

	ret = 0;

out:
	free(buf);
	return ret;
}

int main(int argc, char *argv[])
{
	unsigned int i, skipped = 0;
	int fd_a, fd_b, ret = 0;

	(void)argc;
	(void)argv;

	fd_a = open("/dev/esdm_es", O_RDONLY | O_CLOEXEC);
	if (fd_a < 0) {
		printf("ES kernel configuration - skip: /dev/esdm_es: %s\n",
		       strerror(errno));
		return 77;
	}

	fd_b = open("/dev/esdm_es", O_RDONLY | O_CLOEXEC);
	if (fd_b < 0) {
		printf("ES kernel configuration - fail: second open: %s\n",
		       strerror(errno));
		close(fd_a);
		return 1;
	}

	for (i = 0; i < sizeof(es_conf_sources) / sizeof(es_conf_sources[0]);
	     i++) {
		int r = es_conf_test(&es_conf_sources[i], fd_a, fd_b);

		if (r == 77)
			skipped++;
		else if (r)
			ret = 1;
	}

	close(fd_b);
	close(fd_a);

	if (!ret && skipped == i)
		return 77;
	return ret;
}
