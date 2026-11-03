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
 * An example provider of an external entropy source - see libesdm_es_ext(3).
 *
 * It reads a noise device, /dev/hwrng unless built with
 * -DESDM_ES_EXT_EXAMPLE_DEVICE=..., and claims and declares one bit of entropy
 * per byte - a real source claims what the assessment of its noise source
 * supports. Its main() hands the callbacks to esdm_es_ext_provider_main(),
 * which is all it takes:
 *
 *	cc -o esdm-es-ext-example esdm_es_ext_example.c \
 *		$(pkg-config --cflags --libs esdm_es_ext)
 *	esdm-es-ext-example --socket /run/esdm-es-ext-example.socket
 *	esdm-server --es_ext /run/esdm-es-ext-example.socket
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <esdm/esdm_es_ext.h>

#ifndef ESDM_ES_EXT_EXAMPLE_DEVICE
#define ESDM_ES_EXT_EXAMPLE_DEVICE "/dev/hwrng"
#endif

/* A request of the ESDM must not block for long: a DRNG waits for it */
#define EXAMPLE_READ_TIMEOUT_MS 1000
#define EXAMPLE_POLL_SLICE_MS 100

struct example_ctx {
	int fd;
	unsigned long reads;
	unsigned long failures;
};

/* Runs with the privileges the provider was started with */
static int example_init(void **ctx)
{
	struct example_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return -ENOMEM;

	c->fd = open(ESDM_ES_EXT_EXAMPLE_DEVICE,
		     O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (c->fd < 0) {
		int ret = -errno;

		free(c);
		return ret;
	}

	*ctx = c;
	return 0;
}

static void example_fini(void *ctx)
{
	struct example_ctx *c = ctx;

	close(c->fd);
	free(c);
}

static int64_t example_ms_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (int64_t)(now.tv_sec - start->tv_sec) * 1000 +
	       (now.tv_nsec - start->tv_nsec) / 1000000;
}

static int example_get_entropy(void *ctx, uint8_t *buf, size_t buflen,
			       uint32_t *entropy_bits)
{
	const struct timespec pace = { .tv_sec = 0, .tv_nsec = 10000000 };
	struct example_ctx *c = ctx;
	struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
	struct timespec start;
	size_t done = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);

	/* All of the buffer, or a failure: a short block is no block */
	while (done < buflen) {
		ssize_t ret = read(c->fd, buf + done, buflen - done);

		if (ret > 0) {
			done += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		if (!ret || (errno != EAGAIN && errno != EWOULDBLOCK)) {
			c->failures++;
			return ret < 0 ? -errno : -EIO;
		}

		/*
		 * The clock keeps the time, not poll(2): the hwrng device is
		 * ready at once whatever it holds, the pause keeps it from
		 * spinning.
		 */
		if (example_ms_since(&start) >= EXAMPLE_READ_TIMEOUT_MS) {
			c->failures++;
			return -ETIMEDOUT;
		}
		if (poll(&pfd, 1, EXAMPLE_POLL_SLICE_MS) > 0)
			nanosleep(&pace, NULL);
	}

	c->reads++;
	*entropy_bits = (uint32_t)buflen;
	return 0;
}

/* Nothing to test without consuming data - the device is still open */
static int example_selftest(void *ctx)
{
	struct example_ctx *c = ctx;

	return fcntl(c->fd, F_GETFD) < 0 ? -EBADF : 0;
}

/* Bits per 256 bits of data - a source may decide it from what init found */
static uint32_t example_entropy_rate(void *ctx)
{
	(void)ctx;
	return 32;
}

/* The device name needs no JSON escape */
static int example_status_json(void *ctx, char *buf, size_t buflen)
{
	struct example_ctx *c = ctx;
	int len = snprintf(buf, buflen,
			   "{\"device\":\"%s\",\"reads\":%lu,\"failures\":%lu}",
			   ESDM_ES_EXT_EXAMPLE_DEVICE, c->reads, c->failures);

	if (len < 0)
		return -EIO;
	return (size_t)len < buflen ? 0 : -EMSGSIZE;
}

static const struct esdm_es_ext_plugin example_source = {
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.name = "example (" ESDM_ES_EXT_EXAMPLE_DEVICE ")",
	.init = example_init,
	.fini = example_fini,
	.get_entropy = example_get_entropy,
	.selftest = example_selftest,
	.status_json = example_status_json,
	.entropy_rate = example_entropy_rate,
};

int main(int argc, char *argv[])
{
	return esdm_es_ext_provider_main(&example_source, argc, argv);
}
