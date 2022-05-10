/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_RPC_CLIENT_H
#define ESDM_RPC_CLIENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Maximum number of allowed dispatchers
 *
 * @param mask [in] Maximum value
 */
void esdm_disp_set_max_online_nodes(uint32_t mask);

/******************************************************************************
 * Unprivileged RPC
 ******************************************************************************/

/**
 * @brief Deallocate all resources for connection handles and dispatcher queues.
 *
 * Use this call to clean up the connection to the unprivileged RPC endpoint
 * of the ESDM server.
 */
void esdm_disp_fini_unpriv(void);

/**
 * @brief Allocate all resources for connection handles and dispatcher queues.
 *
 * This call must be used to initialize the connection to the unprivileged RPC
 * endpoint of the ESDM server before any RPC service calls are performed.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_disp_init_unpriv(void);

/******************************************************************************
 * Privileged RPC
 ******************************************************************************/

/**
 * @brief Deallocate all resources for connection handles and dispatcher queues.
 *
 *  Use this call to clean up the connection to the privileged RPC endpoint
 * of the ESDM server.
 */
void esdm_disp_fini_priv(void);

/**
 * @brief Allocate all resources for connection handles and dispatcher queues.
 *
 * This call must be used to initialize the connection to the privileged RPC
 * endpoint of the ESDM server before any RPC service calls are performed.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_disp_init_priv(void);

/******************************************************************************
 * RPC Service Call APIs
 ******************************************************************************/

/**
 * @brief RPC-version of esdm_status
 *
 * This call uses the unprivileged RPC endpoint of the ESDM server. It therefore
 * can be invoked by any user.
 *
 * @param buf [out] Buffer to be filled with human-readable status information.
 *		    The string will be NULL-terminated.
 * @param buflen [in] Size of the buffer provided by the caller.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_status(char *buf, size_t buflen);

/**
 * @brief RPC-version of esdm_get_random_bytes_full
 *
 * This call uses the unprivileged RPC endpoint of the ESDM server. It therefore
 * can be invoked by any user.
 *
 * This function blocks until the ESDM is fully seeded.
 *
 * @param buf [out] Buffer to be filled with random bits.
 * @param buflen [in] Size of the buffer to be filled.
 *
 * @return: read data length on success, < 0 on error (-EINTR means connection
 *	    was interrupted and the caller may try again)
 */
ssize_t esdm_rpcc_get_random_bytes_full(uint8_t *buf, size_t buflen);

/**
 * @brief RPC-version of esdm_get_random_bytes_min
 *
 * This call uses the unprivileged RPC endpoint of the ESDM server. It therefore
 * can be invoked by any user.
 *
 * This function blocks until the ESDM is minimally seeded. The call provides
 * no guarantee whether the DRNG initial seed level stipulated by SP800-90C is
 * reached.
 *
 * @param buf [out] Buffer to be filled with random bits.
 * @param buflen [in] Size of the buffer to be filled.
 *
 * @return: read data length on success, < 0 on error (-EINTR means connection
 *	    was interrupted and the caller may try again)
 */
ssize_t esdm_rpcc_get_random_bytes_min(uint8_t *buf, size_t buflen);

/**
 * @brief RPC-version of esdm_get_random_bytes
 *
 * This call uses the unprivileged RPC endpoint of the ESDM server. It therefore
 * can be invoked by any user.
 *
 * This function never blocks and therefore provides no guarantee whether the
 * DRNG is seeded or the initial seed level stipulated by SP800-90C is reached.
 *
 * @param buf [out] Buffer to be filled with random bits.
 * @param buflen [in] Size of the buffer to be filled.
 *
 * @return: read data length on success, < 0 on error (-EINTR means connection
 *	    was interrupted and the caller may try again)
 */
ssize_t esdm_rpcc_get_random_bytes(uint8_t *buf, size_t buflen);

/**
 * @brief RPC-version of writing data into ESDM auxiliary pool
 *
 * This call uses the unprivileged RPC endpoint of the ESDM server. It therefore
 * can be invoked by any user.
 *
 * @param data_buf [in] Buffer with data
 * @param data_buf_len [in] Length of data buffer
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_write_data(const uint8_t *data_buf, size_t data_buf_len);

/******************************************************************************
 * IOCTL handlers
 ******************************************************************************/
/**
 * @brief RNDGETENTCNT IOCTL
 *
 * This call uses the unprivileged RPC endpoint of the ESDM server. It therefore
 * can be invoked by any user.
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_rnd_get_ent_cnt(unsigned int *entcnt);

/**
 * @brief RNDADDTOENTCNT IOCTL
 *
 * This call uses the privileged RPC endpoint of the ESDM server. It therefore
 * can only be used by a user that can open the privileged Unix domain socket.
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_rnd_add_to_ent_cnt(unsigned int entcnt);

/**
 * @brief RNDADDENTROPY IOCTL
 *
 * This call uses the privileged RPC endpoint of the ESDM server. It therefore
 * can only be used by a user that can open the privileged Unix domain socket.
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_rnd_add_entropy(const uint8_t *entropy_buf,
			      size_t entropy_buf_len, uint32_t entropy_cnt);

/**
 * @brief RNDCLEARPOOL / RNDZAPENTCNT IOCTL
 *
 * This call uses the privileged RPC endpoint of the ESDM server. It therefore
 * can only be used by a user that can open the privileged Unix domain socket.
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_rnd_clear_pool(void);

/**
 * @brief RNDRESEEDCRNG IOCTL
 *
 * This call uses the privileged RPC endpoint of the ESDM server. It therefore
 * can only be used by a user that can open the privileged Unix domain socket.
 *
 * NOTE: The requirement for the privilege is kept to be ABI-compliant to the
 *	 Linux kernel /dev/random IOCTL. Yet, a reseed is triggered also with
 *	 esdm_rpcc_write_data() which can be called by any user.
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_rnd_reseed_crng(void);

/**
 * @brief Invoke a function up to 5 times if EINTR was returned
 *
 * This macro is intended to be used with the RPC calls above to repeat a call
 * when the connection cannot be initially established.
 */
#define esdm_invoke(x)							       \
	do {								       \
		unsigned int __ctr = 0;					       \
									       \
		do {							       \
			ret = x;					       \
		} while (ret == -EINTR && __ctr < 5);			       \
	} while(0)

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_H */
