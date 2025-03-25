/*
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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
#include "esdm_rpc_client.h"
#include "visibility.h"

std::mutex ESDM_RNG::m_init_lock;
std::size_t ESDM_RNG::m_ref_cnt = 0;

DSO_PUBLIC
ESDM_RNG::ESDM_RNG(bool prediction_resistance)
	: m_prediction_resistance(prediction_resistance)
{
	std::lock_guard lg(m_init_lock);

	if (m_ref_cnt == 0) {
		if (esdm_rpcc_init_unpriv_service(nullptr) != 0) {
			throw Botan::System_Error(
				"unable to initialize ESDM unprivileged service");
		}
	}
	++m_ref_cnt;
}

DSO_PUBLIC
ESDM_RNG::~ESDM_RNG()
{
	std::lock_guard lg(m_init_lock);

	if (m_ref_cnt == 1) {
		esdm_rpcc_fini_unpriv_service();
	}
	--m_ref_cnt;
}

// as long as prediction resistance is the only difference,
// do not introduce multiple classes
DSO_PUBLIC
std::string ESDM_RNG::name() const
{
	if (m_prediction_resistance) {
		return "esdm_pr";
	} else {
		return "esdm_full";
	}
}

// as long as we use only the _full and _pr calls, just return true here
DSO_PUBLIC
bool ESDM_RNG::is_seeded() const
{
	return true;
}

// if this should be changed to false in the future,
// do not handle input in fill_bytes_with_input
DSO_PUBLIC
bool ESDM_RNG::accepts_input() const
{
	return true;
}

// the ESDM RNG does not hold any state outside ESDM, that should be cleared
// here
DSO_PUBLIC
void ESDM_RNG::clear()
{
}

DSO_PUBLIC
void ESDM_RNG::fill_bytes_with_input(std::span<uint8_t> out,
				     std::span<const uint8_t>)
{
	if (out.size() > 0) {
		ssize_t ret = 0;
		if (m_prediction_resistance)
			esdm_invoke(esdm_rpcc_get_random_bytes_pr(out.data(),
								  out.size()));
		else
			esdm_invoke(esdm_rpcc_get_random_bytes_full(
				out.data(), out.size()));
		if (ret != static_cast<ssize_t>(out.size())) {
			throw Botan::System_Error(
				"Fetching random bytes from ESDM failed");
		}
	}
}
