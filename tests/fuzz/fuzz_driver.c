/*
 * Standalone driver for the fuzz harnesses
 *
 * A libFuzzer binary brings its own main(). This one takes its place where no
 * fuzzing engine is available, so the harnesses are built and their seeds are
 * run by the ordinary test suite: a harness that stopped compiling, or an input
 * that starts to crash, is then noticed by a plain "meson test" rather than by
 * the next person who goes fuzzing.
 *
 * It replays inputs - the seeds the harness brings along, or files named on the
 * command line, which is how a crash found by the fuzzer is reproduced against
 * a build without the engine.
 *
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "fuzz.h"

/* Every input a harness accepts fits into this - see ESDM_RPC_MAX_MSG_SIZE */
#define FUZZ_MAX_INPUT (1024 * 1024)

/* Run one file through the harness */
static int fuzz_replay_file(const char *name)
{
	static uint8_t buf[FUZZ_MAX_INPUT];
	FILE *f = fopen(name, "rb");
	size_t len;

	if (!f) {
		fprintf(stderr, "cannot open %s: %s\n", name, strerror(errno));
		return 1;
	}

	len = fread(buf, 1, sizeof(buf), f);
	fclose(f);

	printf("replaying %s (%zu bytes)\n", name, len);
	LLVMFuzzerTestOneInput(buf, len);

	return 0;
}

/*
 * Write the seeds out as files, which is how a corpus directory for the fuzzer
 * is bootstrapped.
 */
static int fuzz_dump_corpus(const char *dir)
{
	const struct fuzz_seed *seeds;
	size_t num = 0, i;

	seeds = fuzz_seed_corpus(&num);
	if (!seeds || !num) {
		fprintf(stderr, "this harness brings no seeds\n");
		return 1;
	}

	for (i = 0; i < num; i++) {
		char path[FILENAME_MAX];
		FILE *f;

		if (snprintf(path, sizeof(path), "%s/%s", dir, seeds[i].name) >=
		    (int)sizeof(path)) {
			fprintf(stderr, "path to %s too long\n", seeds[i].name);
			return 1;
		}

		f = fopen(path, "wb");
		if (!f) {
			fprintf(stderr, "cannot write %s: %s\n", path,
				strerror(errno));
			return 1;
		}

		if (fwrite(seeds[i].data, 1, seeds[i].len, f) != seeds[i].len) {
			fprintf(stderr, "short write on %s\n", path);
			fclose(f);
			return 1;
		}

		fclose(f);
		printf("wrote %s (%zu bytes)\n", path, seeds[i].len);
	}

	return 0;
}

/* Run everything the harness brings along */
static int fuzz_replay_seeds(void)
{
	const struct fuzz_seed *seeds;
	size_t num = 0, i;

	seeds = fuzz_seed_corpus(&num);
	if (!seeds || !num) {
		fprintf(stderr, "this harness brings no seeds\n");
		return 1;
	}

	for (i = 0; i < num; i++) {
		printf("seed %s (%zu bytes)\n", seeds[i].name, seeds[i].len);
		LLVMFuzzerTestOneInput(seeds[i].data, seeds[i].len);
	}

	/*
	 * Nothing is asserted about the return values: a harness answers every
	 * input, and a malformed one being rejected is as much a pass as a
	 * valid one being served.
	 */
	printf("%zu seed(s) replayed\n", num);

	return 0;
}

int main(int argc, char *argv[])
{
	int i, ret;

	LLVMFuzzerInitialize(&argc, &argv);

	if (argc > 1 && !strcmp(argv[1], "--dump-corpus")) {
		if (argc != 3) {
			fprintf(stderr, "usage: %s --dump-corpus <directory>\n",
				argv[0]);
			return 1;
		}
		return fuzz_dump_corpus(argv[2]);
	}

	if (argc == 1)
		return fuzz_replay_seeds();

	for (i = 1; i < argc; i++) {
		ret = fuzz_replay_file(argv[i]);
		if (ret)
			return ret;
	}

	return 0;
}
