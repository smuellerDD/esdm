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

#ifndef TEST_WAIT_H
#define TEST_WAIT_H

#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

/*
 * Wait for a daemon the test just forked to be ready, by watching for the path
 * it creates once it is - and for that path to be of the right kind.
 *
 * The type check is the point, not a nicety. A CUSE frontend creates its
 * bind mount target as an ordinary file first and only then mounts the device
 * over it, so a test that waits for mere existence opens the placeholder and
 * every ioctl on it fails with ENOTTY.
 *
 * This replaces a fixed one second sleep per daemon. That sleep was both slower
 * than it needed to be - three of them put a floor of three seconds under every
 * CUSE test, most of a minute across the suite - and less reliable, because a
 * loaded machine can take longer than a second and the test would then race the
 * daemon it just started rather than fail cleanly.
 *
 * Returns 1 once the path exists, 0 if it did not appear within the timeout.
 * The caller carries on either way: the operation that follows produces a far
 * better diagnostic than a bare timeout here would.
 */
static inline int test_wait_for_type(const char *path, mode_t type,
				    unsigned int timeout_ms)
{
	/*
	 * Short enough that startup is not rounded up noticeably, long enough
	 * not to spin on a machine where the daemon needs a moment.
	 */
	static const unsigned int poll_ms = 5;
	struct timespec pause = { .tv_sec = 0,
				  .tv_nsec = poll_ms * 1000L * 1000L };
	unsigned int waited;
	struct stat sb;

	for (waited = 0; waited < timeout_ms; waited += poll_ms) {
		if (!stat(path, &sb) && (sb.st_mode & S_IFMT) == type)
			return 1;
		nanosleep(&pause, NULL);
	}

	/* One last look, so a timeout of zero still checks once */
	if (!stat(path, &sb) && (sb.st_mode & S_IFMT) == type)
		return 1;

	fprintf(stderr,
		"Test environment: %s did not become ready within %u ms\n",
		path, timeout_ms);

	return 0;
}

/* Generous: it only matters when something is wrong */
#define TEST_WAIT_TIMEOUT_MS 30000

#endif /* TEST_WAIT_H */
