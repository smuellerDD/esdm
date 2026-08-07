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
 * Tests for common/binhexbin.c - the hex/binary converters and the RFC 3986
 * percent encoder.
 *
 * Besides the plain round trips these cover the corner cases the converters
 * document but nothing else exercises: odd-length hex input (whose first digit
 * is a lone nibble), destination buffers too small to hold the full conversion,
 * and the percent encoder's rejection of malformed UTF-8 - in particular a
 * multi-byte sequence truncated at the end of the input, which used to
 * underflow the remaining-length counter and read past the buffer.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "binhexbin.h"
#include "common_test.h"

/* Canary the converters must not touch beyond their documented destination. */
#define CANARY 0xa5

static void test_hex2bin(void)
{
	uint8_t bin[8];

	/* Even length, both cases, and a full byte range */
	memset(bin, CANARY, sizeof(bin));
	hex2bin("00ff7Fa5", 8, bin, sizeof(bin));
	CHECK_EQ(bin[0], 0x00);
	CHECK_EQ(bin[1], 0xff);
	CHECK_EQ(bin[2], 0x7f);
	CHECK_EQ(bin[3], 0xa5);
	CHECK_EQ(bin[4], CANARY);

	/*
	 * Odd length: the leading digit is the least significant nibble of the
	 * first output byte, the rest is converted byte-wise behind it.
	 */
	memset(bin, CANARY, sizeof(bin));
	hex2bin("abc", 3, bin, sizeof(bin));
	CHECK_EQ(bin[0], 0x0a);
	CHECK_EQ(bin[1], 0xbc);
	CHECK_EQ(bin[2], CANARY);

	/* Destination smaller than the input: convert a prefix, touch no more */
	memset(bin, CANARY, sizeof(bin));
	hex2bin("0102030405", 10, bin, 2);
	CHECK_EQ(bin[0], 0x01);
	CHECK_EQ(bin[1], 0x02);
	CHECK_EQ(bin[2], CANARY);

	/*
	 * Odd length into a destination that only holds the lone nibble: the
	 * single byte is written and the budget is exhausted afterwards.
	 */
	memset(bin, CANARY, sizeof(bin));
	hex2bin("abc", 3, bin, 1);
	CHECK_EQ(bin[0], 0x0a);
	CHECK_EQ(bin[1], CANARY);

	/* Odd length into a zero-length destination must not write at all */
	memset(bin, CANARY, sizeof(bin));
	hex2bin("abc", 3, bin, 0);
	CHECK_EQ(bin[0], CANARY);

	/* Even length into a zero-length destination */
	memset(bin, CANARY, sizeof(bin));
	hex2bin("ab", 2, bin, 0);
	CHECK_EQ(bin[0], CANARY);

	/* Empty input */
	memset(bin, CANARY, sizeof(bin));
	hex2bin("", 0, bin, sizeof(bin));
	CHECK_EQ(bin[0], CANARY);

	/* Non-hex characters decode as zero nibbles */
	memset(bin, CANARY, sizeof(bin));
	hex2bin("z1", 2, bin, sizeof(bin));
	CHECK_EQ(bin[0], 0x01);
}

static void test_hex2bin_alloc(void)
{
	uint8_t *bin = NULL;
	size_t binlen = 0;

	CHECK_EQ(hex2bin_alloc("", 0, &bin, &binlen), -EINVAL);

	CHECK_EQ(hex2bin_alloc("0a0b", 4, &bin, &binlen), 0);
	CHECK_EQ(binlen, 2);
	if (bin) {
		CHECK_EQ(bin[0], 0x0a);
		CHECK_EQ(bin[1], 0x0b);
	}
	free(bin);
	bin = NULL;

	/* Odd length rounds the allocation up */
	CHECK_EQ(hex2bin_alloc("abc", 3, &bin, &binlen), 0);
	CHECK_EQ(binlen, 2);
	if (bin) {
		CHECK_EQ(bin[0], 0x0a);
		CHECK_EQ(bin[1], 0xbc);
	}
	free(bin);
}

static void test_bin2hex(void)
{
	static const uint8_t bin[] = { 0x00, 0xff, 0x7f, 0xa5 };
	char hex[16];

	/* bin2hex does not NUL terminate - pre-fill and terminate ourselves */
	memset(hex, 0, sizeof(hex));
	bin2hex(bin, sizeof(bin), hex, sizeof(hex), 0);
	CHECK_STR_EQ(hex, "00ff7fa5");

	memset(hex, 0, sizeof(hex));
	bin2hex(bin, sizeof(bin), hex, sizeof(hex), 1);
	CHECK_STR_EQ(hex, "00FF7FA5");

	/* Destination too small: only as many full bytes as fit are converted */
	memset(hex, 0, sizeof(hex));
	bin2hex(bin, sizeof(bin), hex, 4, 0);
	CHECK_STR_EQ(hex, "00ff");

	/* An odd destination length cannot hold the trailing nibble */
	memset(hex, 0, sizeof(hex));
	bin2hex(bin, sizeof(bin), hex, 3, 0);
	CHECK_STR_EQ(hex, "00");

	/* Zero-length destination writes nothing */
	memset(hex, 0, sizeof(hex));
	bin2hex(bin, sizeof(bin), hex, 0, 0);
	CHECK_STR_EQ(hex, "");
}

static void test_bin2hex_alloc(void)
{
	static const uint8_t bin[] = { 0x0a, 0x0b };
	char *hex = NULL;
	size_t hexlen = 0;

	CHECK_EQ(bin2hex_alloc(bin, 0, &hex, &hexlen), -EINVAL);

	CHECK_EQ(bin2hex_alloc(bin, sizeof(bin), &hex, &hexlen), 0);
	CHECK_EQ(hexlen, 4);
	/* The allocation carries the terminating NUL beyond hexlen */
	CHECK_STR_EQ(hex, "0a0b");
	free(hex);
}

static void test_bin2hex_roundtrip(void)
{
	uint8_t bin[64], back[64];
	char hex[sizeof(bin) * 2 + 1];
	unsigned int i;

	for (i = 0; i < sizeof(bin); i++)
		bin[i] = (uint8_t)(i * 7 + 3);

	memset(hex, 0, sizeof(hex));
	bin2hex(bin, sizeof(bin), hex, sizeof(hex) - 1, 0);
	CHECK_EQ(strlen(hex), sizeof(bin) * 2);

	memset(back, 0, sizeof(back));
	hex2bin(hex, strlen(hex), back, sizeof(back));
	CHECK_MEM_EQ(back, bin, sizeof(bin));

	/* The same round trip through the upper case representation */
	memset(hex, 0, sizeof(hex));
	bin2hex(bin, sizeof(bin), hex, sizeof(hex) - 1, 1);
	memset(back, 0, sizeof(back));
	hex2bin(hex, strlen(hex), back, sizeof(back));
	CHECK_MEM_EQ(back, bin, sizeof(bin));
}

static void test_bin2print(void)
{
	static const uint8_t bin[] = { 0xde, 0xad };
	char *out = NULL;
	size_t outlen = 0;
	FILE *stream = open_memstream(&out, &outlen);

	CHECK(stream != NULL, "open_memstream failed");
	if (!stream)
		return;

	bin2print(bin, sizeof(bin), stream, "data");
	/* An empty input still prints the explanation */
	bin2print(bin, 0, stream, "empty");
	fflush(stream);

	CHECK_STR_EQ(out, "data = dead\nempty = \n");

	fclose(stream);
	free(out);
}

static void test_bin2hex_html(void)
{
	char html[64];

	/* Unreserved characters per RFC 3986 pass through unchanged */
	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html("aZ0-._~", 7, html, sizeof(html)), 0);
	CHECK_STR_EQ(html, "aZ0-._~");

	/* Everything else is percent encoded in upper case */
	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html("a b", 3, html, sizeof(html)), 0);
	CHECK_STR_EQ(html, "a%20b");

	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html("a?b=c", 5, html, sizeof(html)), 0);
	CHECK_STR_EQ(html, "a%3Fb%3Dc");

	/* Two, three and four byte UTF-8 sequences are encoded byte-wise */
	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html("\xc3\xa4", 2, html, sizeof(html)), 0);
	CHECK_STR_EQ(html, "%C3%A4");

	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html("\xe2\x82\xac", 3, html, sizeof(html)), 0);
	CHECK_STR_EQ(html, "%E2%82%AC");

	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html("\xf0\x9f\x98\x80", 4, html, sizeof(html)), 0);
	CHECK_STR_EQ(html, "%F0%9F%98%80");

	/* A byte that is no valid UTF-8 lead byte is rejected */
	CHECK_EQ(bin2hex_html("\x80", 1, html, sizeof(html)), -EINVAL);
	CHECK_EQ(bin2hex_html("\xf8", 1, html, sizeof(html)), -EINVAL);

	/*
	 * A multi-byte sequence truncated at the end of the input is rejected
	 * rather than consuming more bytes than the input holds.
	 */
	CHECK_EQ(bin2hex_html("\xc3", 1, html, sizeof(html)), -EINVAL);
	CHECK_EQ(bin2hex_html("\xe2\x82", 2, html, sizeof(html)), -EINVAL);
	CHECK_EQ(bin2hex_html("a\xf0\x9f\x98", 4, html, sizeof(html)), -EINVAL);

	/* Exactly enough room for the encoding plus the NUL terminator */
	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html("a b", 3, html, 6), 0);
	CHECK_STR_EQ(html, "a%20b");

	/* One byte short of that is reported instead of truncating */
	CHECK_EQ(bin2hex_html("a b", 3, html, 5), -ENOMEM);
	CHECK_EQ(bin2hex_html("abc", 3, html, 3), -ENOMEM);

	/* An empty input yields an empty, terminated string */
	memset(html, CANARY, sizeof(html));
	CHECK_EQ(bin2hex_html("", 0, html, sizeof(html)), 0);
	CHECK_STR_EQ(html, "");
}

static void test_bin2hex_html_from_url(void)
{
	char html[64];

	/* The URL variant keeps the characters that carry a query's structure */
	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html_from_url("a?b=c&d[0]:%20", 14, html,
				       sizeof(html)),
		 0);
	CHECK_STR_EQ(html, "a?b=c&d[0]:%20");

	/* while everything outside that set is still encoded */
	memset(html, 0, sizeof(html));
	CHECK_EQ(bin2hex_html_from_url("a b", 3, html, sizeof(html)), 0);
	CHECK_STR_EQ(html, "a%20b");
}

static void test_bin2hex_html_alloc(void)
{
	char *html = NULL;
	size_t htmllen = 0;

	CHECK_EQ(bin2hex_html_alloc("", 0, &html, &htmllen), -EINVAL);

	CHECK_EQ(bin2hex_html_alloc("a b", 3, &html, &htmllen), 0);
	CHECK_STR_EQ(html, "a%20b");
	/* The reported length is the sizing pass' result, NUL included */
	CHECK_EQ(htmllen, 6);
	if (html)
		CHECK_EQ(strlen(html) + 1, htmllen);
	free(html);
	html = NULL;

	/* The sizing pass has to reject malformed input as well */
	CHECK_EQ(bin2hex_html_alloc("\xc3", 1, &html, &htmllen), -EINVAL);

	/* Multi-byte input sizes to three output bytes per input byte */
	CHECK_EQ(bin2hex_html_alloc("\xe2\x82\xac", 3, &html, &htmllen), 0);
	CHECK_STR_EQ(html, "%E2%82%AC");
	CHECK_EQ(htmllen, 10);
	free(html);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_hex2bin();
	test_hex2bin_alloc();
	test_bin2hex();
	test_bin2hex_alloc();
	test_bin2hex_roundtrip();
	test_bin2print();
	test_bin2hex_html();
	test_bin2hex_html_from_url();
	test_bin2hex_html_alloc();

	return common_test_result("binhexbin");
}
