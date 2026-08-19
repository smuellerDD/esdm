/*
 * Interface between the OpenSSL provider harness and the peer behind it
 *
 * The harness in ossl_prov_fuzz.c drives an ESDM OpenSSL RAND provider through
 * the interface libcrypto uses. What that provider talks to differs per
 * variant - the RPC based ones reach an ESDM server, the EGD based ones a Unix
 * domain socket - so the peer is a backend of its own, and the harness stays
 * the same for all of them.
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

#ifndef ESDM_OSSL_PROV_FUZZ_H
#define ESDM_OSSL_PROV_FUZZ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Bring the peer up, once, before the first input
 *
 * @return 0 on success, everything else aborts the run
 */
int fuzz_backend_init(void);

/**
 * @brief Hand the peer the part of the input that is its to interpret
 *
 * A peer that makes up its answers - the EGD impostor - plays these bytes back
 * at the provider; one that serves the real protocol ignores them.
 *
 * @param [in] data Tail of the input, after the script of provider calls
 * @param [in] len Length of that tail
 */
void fuzz_backend_begin(const uint8_t *data, size_t len);

/**
 * @brief The input is done - the peer stops answering and settles
 */
void fuzz_backend_end(void);

/*
 * Whether this provider variant has to refuse a request asking for prediction
 * resistance. The EGD protocol cannot express it, so the provider bound to the
 * ordinary EGD socket refuses rather than quietly serving data without the
 * property that was asked for - which is a promise worth holding it to.
 */
#if defined(ESDM_FUZZ_PROV_EGD) && !defined(ESDM_EGD_PROV_FORCE_PR)
#define FUZZ_PROV_REFUSES_PR true
#else
#define FUZZ_PROV_REFUSES_PR false
#endif

/*
 * Property query selecting this variant's algorithms, and the name the harness
 * registers the provider under.
 */
#ifdef ESDM_FUZZ_PROV_EGD
#ifdef ESDM_EGD_PROV_FORCE_PR
#define FUZZ_PROV_PROPERTY "provider=esdm-egd-pr"
#else
#define FUZZ_PROV_PROPERTY "provider=esdm-egd"
#endif
#else
#define FUZZ_PROV_PROPERTY "provider=esdm"
#endif

#define FUZZ_PROV_MODULE_NAME "esdm-fuzz-provider"

#endif /* ESDM_OSSL_PROV_FUZZ_H */
