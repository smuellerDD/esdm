/*
 * Interface between the fuzz harnesses and the driver running them
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

#ifndef ESDM_FUZZ_H
#define ESDM_FUZZ_H

#include <stddef.h>
#include <stdint.h>

/* The two entry points libFuzzer calls. */
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/*
 * One input a harness brings along: a well formed request, a response, an edge
 * of the wire format.
 */
struct fuzz_seed {
	/* Name of the corpus file this seed is written to */
	const char *name;
	const uint8_t *data;
	size_t len;
};

/**
 * @brief The seeds of the harness in this binary
 * @param [out] num Number of seeds returned
 * @return The seeds, NULL if the harness has none
 */
const struct fuzz_seed *fuzz_seed_corpus(size_t *num);

#endif /* ESDM_FUZZ_H */
