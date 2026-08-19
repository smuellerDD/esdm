/*
* Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_FIPS_INTEGRITY_H
#define ESDM_FIPS_INTEGRITY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Write the reference value of @targetfile to @checkfile
 * @param [in] checkfile File receiving the HMAC, "-" for stdout
 * @param [in] targetfile File to compute the HMAC over
 * @return 0 on success, < 0 on error
 */
int fips_create_checkfile(const char *checkfile, const char *targetfile);

/**
 * @brief Pre-operational integrity test of one file
 * @param [in] pathname File to attest, NULL for the running executable
 * @return 0 if the file matches its reference value, < 0 otherwise
 */
int fips_post_integrity(const char *pathname);

/**
 * @brief Pre-operational integrity test of the object holding @addr
 * @param [in] addr Address of code inside the component to attest
 * @return 0 if the file matches its reference value, < 0 otherwise
 */
int fips_post_integrity_obj(const void *addr);

/**
 * @brief Pre-operational integrity test of a loaded shared object
 * @param [in] soname Start of the file name of the object to attest
 * @return number of objects attested (0 if none is loaded), < 0 if one of them
 * 	does not match its reference value
 */
int fips_post_integrity_loaded(const char *soname);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_FIPS_INTEGRITY_H */
