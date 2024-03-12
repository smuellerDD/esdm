/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_AUX_CLIENT_H
#define ESDM_AUX_CLIENT_H

#include <semaphore.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the semaphore to be notified about inserting entropy
 */
int esdm_aux_init_wait_for_need_entropy(void);

/**
 * @brief Detach from the semaphore waiting to insert entropy
 */
void esdm_aux_fini_wait_for_need_entropy(void);

/**
 * @brief Timed wait for semaphore firing when ESDM server requires entropy
 *
 * When the ESDM server requires entropy, a semaphore is set to notify anybody
 * who is interested that entropy shall be injected into the ESDM.
 *
 * A client that can deliver entropy shall sleep on the semaphore and then
 * insert entropy when this call returns successfully. This API shall be
 * invoked in a recursive loop so that the client injects entropy whenever
 * the ESDM server wants it.
 *
 * This function allows the caller to specify a timeout when this function shall
 * return even though the semaphore did not fire.
 *
 * The API is a wrapper around sem_clockwait([1]) including the purpose of the
 * @param ts as well as the return code and the errno.
 *
 * @param [in] ts See [1]
 *
 * @return See [1]
 *
 * [1] https://www.gnu.org/software/libc/manual/html_node/Waiting-with-Explicit-Clocks.html
 */
int esdm_aux_timedwait_for_need_entropy(struct timespec *ts);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_AUX_CLIENT_H */
