/* getrandom system call tester
 *
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
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
#include <sys/random.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "env.h"

static inline ssize_t __getrandom(uint8_t *buffer, size_t bufferlen,
				  unsigned int flags)
{
	ssize_t ret, totallen = 0;

	if (bufferlen > INT_MAX)
		return -EINVAL;

	do {
		ret = getrandom(buffer, bufferlen, flags);
		if (ret > 0) {
			bufferlen -= (size_t)ret;
			buffer += ret;
			totallen += ret;
		}
	} while ((ret > 0 || errno == EINTR) && bufferlen);

	return ((ret < 0) ? -errno : totallen);
}

static inline ssize_t getrandom_urandom(uint8_t *buffer, size_t bufferlen)
{
	return __getrandom(buffer, bufferlen, 0);
}

static inline ssize_t getrandom_random(uint8_t *buffer, size_t bufferlen)
{
	return __getrandom(buffer, bufferlen, GRND_RANDOM);
}

/******************************************************************************/

static char hex_char(unsigned int bin, int u)
{
	static const char hex_char_map_l[] =
				{ '0', '1', '2', '3', '4', '5', '6', '7',
				  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	static const char hex_char_map_u[] =
				{ '0', '1', '2', '3', '4', '5', '6', '7',
				  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

/**
 * Convert binary string into hex representation
 * @bin [in] input buffer with binary data
 * @binlen [in] length of bin
 * @hex [out] output buffer to store hex data
 * @hexlen [in] length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u [in] case of hex characters (0=>lower case, 1=>upper case)
 */
static void bin2hex(const uint8_t *bin, uint32_t binlen,
		    char *hex, uint32_t hexlen, int u)
{
	uint32_t i;
	uint32_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i*2)] = hex_char((bin[i] >> 4), u);
		hex[((i*2)+1)] = hex_char((bin[i] & 0x0f), u);
	}
}

int main(int argc, char *argv[])
{
	uint8_t random[16];
	char hex_random[sizeof(random) + 1];
	int ret;

	(void)argc;
	(void)argv;

	ret = env_init();
	if (ret)
		return ret;

	hex_random[sizeof(hex_random) - 1] = '\0';

	if (getrandom_random(random, sizeof(random)) < 0) {
		printf("getrandom(GRND_RANDOM) call failed\n");
	} else {
		bin2hex(random, sizeof(random),
			hex_random, sizeof(hex_random) - 1, 0);
		printf("random value %s\n", hex_random);
	}

	if (getrandom_urandom(random, sizeof(random)) < 0) {
		printf("getrandom(0) call failed\n");
	} else {
		bin2hex(random, sizeof(random),
			hex_random, sizeof(hex_random) - 1, 0);
		printf("random value %s\n", hex_random);
	}

	env_fini();

	return 0;
}
