/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#include "botan-rng.hpp"
#include <botan/ecdsa.h>
#include <botan/rsa.h>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "env.h"

bool performTest(std::shared_ptr<Botan::RandomNumberGenerator>& rng)
{
    std::vector<uint8_t> bytes(300);
    try {
        rng->randomize(bytes);
        Botan::ECDSA_PrivateKey key_ecdsa(*rng, Botan::EC_Group("secp521r1"));
        Botan::RSA_PrivateKey key_rsa(*rng, 2048);
    } catch(const Botan::System_Error& err) {
        std::cerr << "Got Botan error, ESDM may did not deliver random bits: " << err.what() << std::endl;
        return false;
    } catch(...) {
        return false;
    }

    return true;
}

int main(void)
{
    int ret = env_init();
    if (ret)
        return ret;

    std::shared_ptr<Botan::RandomNumberGenerator> rng_pr;
    std::shared_ptr<Botan::RandomNumberGenerator> rng_full;

    try {
        rng_pr.reset(new ESDM_RNG(true));
        rng_full.reset(new ESDM_RNG(false));
    } catch(const Botan::System_Error& err) {
        std::cerr << "Cannot initialize ESDM connection" << std::endl;
        goto out_err;
    }
    assert(rng_pr->name() == "esdm_pr");
    assert(rng_full->name() == "esdm_full");

    if(!performTest(rng_pr)) {
        goto out_err;
    }
    if(!performTest(rng_full)) {
        goto out_err;
    }

    env_fini();
    return EXIT_SUCCESS;

out_err:
    env_fini();
    return EXIT_FAILURE;
}