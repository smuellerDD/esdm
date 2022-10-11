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

#include <protobuf-c/protobuf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "atomic.h"
#include "bool.h"
#include "mutex_w.h"
#include "queue.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum {
	esdm_rpcc_uninitialized,
	esdm_rpcc_in_initialization,
	esdm_rpcc_initialized,
	esdm_rpcc_in_termination,
};

typedef bool (*esdm_rpcc_interrupt_func_t)(void *interrupt_data);

struct esdm_rpc_client_connection {
	ProtobufCService service;
	char socketname[FILENAME_MAX];
	int fd;

	/*
	 * Caller can register function that is invoked to check whether call
	 * should be interrupted.
	 */
	esdm_rpcc_interrupt_func_t interrupt_func;
	void *interrupt_data;

	mutex_w_t lock;
	atomic_t ref_cnt;
	atomic_t state;
	struct thread_wait_queue completion;
};

/* Sleep time for poll operations */
static const struct timespec esdm_client_poll_ts = { .tv_sec = 1,
						     .tv_nsec = 0 };

/******************************************************************************
 * General service handlers
 ******************************************************************************/

/**
 * @brief Set maximum number of online nodes
 *
 * The number of online nodes imply the number of parallel service requests.
 * During initialization of the services with esdm_rpcc_init_unpriv_service
 * and esdm_rpcc_init_priv_service, the memory allowing as many parallel
 * requests to be processed as CPUs are available to be allocated. To limit
 * this, set maximum number of online nodes here.
 *
 * @param nodes [in] Number of maximum online nodes
 *
 * @return 0 on success, 0 < on error
 */
int esdm_rpcc_set_max_online_nodes(uint32_t nodes);

/******************************************************************************
 * Unprivileged ESDM interface
 ******************************************************************************/

/**
 * @brief Initiate connection
 *
 * It will be transparently initialized if it does not exist before. terminate
 * the connection with esdm_rpc_client_fini_unpriv_service. Release the
 * connection with esdm_rpcc_put_unpriv_service.
 *
 * @param rpc_conn [in] Connection handle that shall be used. This handle can be
 *		   	located on the stack.
 * @param int_data [in] Opaque data pointer used when invoking the interrupt
 *			function. This may be NULL.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_rpcc_get_unpriv_service(struct esdm_rpc_client_connection **rpc_conn,
				 void *int_data);

/**
 * @brief Release the client connection handle
 *
 * Release for the next service request.
 *
 * @param rpc_conn [in] Connection handle that shall be used. This handle can be
 *		    	located on the stack.
 */
void esdm_rpcc_put_unpriv_service(struct esdm_rpc_client_connection *rpc_conn);

/**
 * @brief Initiate the memory for accessing the unprivileged RPC connection.
 *
 * @param interrupt_func [in] Function pointer invoked to check when the
 *			      operation shall be interrupted.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_rpcc_init_unpriv_service(esdm_rpcc_interrupt_func_t interrupt_func);

/**
 * @brief Release all resources around the RPC connection.
 */
void esdm_rpcc_fini_unpriv_service(void);

/******************************************************************************
 * Privileged ESDM interface
 ******************************************************************************/

/**
 * @brief Get the client connection handle
 *
 * It will be transparently initialized if it does not exist before. Terminate
 * the connection with esdm_rpc_client_fini_priv_service. Release the
 * connection with esdm_rpcc_put_priv_service.
 *
 * @param rpc_conn [in] Connection handle that shall be used. This handle can be
 *		    	located on the stack.
 * @param int_data [in] Opaque data pointer used when invoking the interrupt
 *			function. This may be NULL.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_rpcc_get_priv_service(struct esdm_rpc_client_connection **rpc_conn,
			       void *int_data);

/**
 * @brief Release the client connection handle
 *
 * Release for the next service request.
 *
 * @param rpc_conn [in] Connection handle that shall be used. This handle can be
 *		    	located on the stack.
 */
void esdm_rpcc_put_priv_service(struct esdm_rpc_client_connection *rpc_conn);

/**
 * @brief Initiate the memory for accessing the privileged RPC connection.
 *
 * @param interrupt_func [in] Function pointer invoked to check when the
 *			      operation shall be interrupted.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_rpcc_init_priv_service(esdm_rpcc_interrupt_func_t interrupt_func);

/**
 * @brief Release all resources around the RPC connection.
 */
void esdm_rpcc_fini_priv_service(void);

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
 * @brief See esdm_rpcc_status
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_status_int(char *buf, size_t buflen, void *int_data);

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
 * @brief See esdm_rpcc_get_random_bytes_full
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
ssize_t esdm_rpcc_get_random_bytes_full_int(uint8_t *buf, size_t buflen,
					    void *int_data);

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
 * @brief See esdm_rpcc_get_random_bytes_min
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
ssize_t esdm_rpcc_get_random_bytes_min_int(uint8_t *buf, size_t buflen,
					   void *int_data);

/**
 * @brief RPC-version of esdm_get_random_bytes_pr
 *
 * This call uses the unprivileged RPC endpoint of the ESDM server. It therefore
 * can be invoked by any user.
 *
 * This function blocks until the ESDM is fully seeded. It causes a reseed of
 * the ESDM and only returns at most the amount of data equal to the entropy
 * gathered from the entropy sources.
 *
 * @param buf [out] Buffer to be filled with random bits.
 * @param buflen [in] Size of the buffer to be filled.
 *
 * @return: read data length on success, < 0 on error (-EINTR means connection
 *	    was interrupted and the caller may try again)
 */
ssize_t esdm_rpcc_get_random_bytes_pr(uint8_t *buf, size_t buflen);

/**
 * @brief See esdm_rpcc_get_random_bytes_pr
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
ssize_t esdm_rpcc_get_random_bytes_pr_int(uint8_t *buf, size_t buflen,
					  void *int_data);

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
 * @brief See esdm_rpcc_get_random_bytes
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
ssize_t esdm_rpcc_get_random_bytes_int(uint8_t *buf, size_t buflen,
				       void *int_data);

enum esdm_get_seed_flags {
	ESDM_GET_SEED_NONBLOCK = 0x0001, /**< Do not block the call */
	ESDM_GET_SEED_FULLY_SEEDED = 0x0002, /**< DRNG is fully seeded */
};

/**
 * @brief RPC-version of esdm_get_seed
 *
 * This call uses the unprivileged RPC endpoint of the ESDM server. It therefore
 * can be invoked by any user.
 *
 * See esdm_get_seed for details.
 *
 * @param buf [out] Buffer to be filled with random bits.
 * @param buflen [in] Size of the buffer to be filled.
 * @param flags [in] Flags information
 *
 * @return: read data length on success, < 0 on error (-EINTR means connection
 *	    was interrupted and the caller may try again)
 */
ssize_t esdm_rpcc_get_seed(uint8_t *buf, size_t buflen, unsigned int flags);

/**
 * @brief See esdm_rpcc_get_seed_int
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
ssize_t esdm_rpcc_get_seed_int(uint8_t *buf, size_t buflen, unsigned int flags,
			       void *int_data);

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

/**
 * @brief See esdm_rpcc_write_data
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_write_data_int(const uint8_t *data_buf, size_t data_buf_len,
			     void *int_data);

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
 * @brief See esdm_rpcc_rnd_get_ent_cnt
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_rnd_get_ent_cnt_int(unsigned int *entcnt, void *int_data);

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
 * @brief See esdm_rpcc_rnd_add_to_ent_cnt
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_rnd_add_to_ent_cnt_int(unsigned int entcnt, void *int_data);

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
 * @brief See esdm_rpcc_rnd_add_entropy
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_rnd_add_entropy_int(const uint8_t *entropy_buf,
				  size_t entropy_buf_len, uint32_t entropy_cnt,
				  void *int_data);

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
 * @brief See esdm_rpcc_rnd_clear_pool
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_rnd_clear_pool_int(void *int_data);

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
 * @brief See esdm_rpcc_rnd_reseed_crng
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_rnd_reseed_crng_int(void *int_data);

/******************************************************************************
 * /proc handlers
 ******************************************************************************/

/**
 * @brief poolsize /proc handler
 *
 * The call returns the poolsize of the ESDM that can be filled by callers
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_get_poolsize(unsigned int *poolsize);

/**
 * @brief See esdm_rpcc_get_poolsize
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_get_poolsize_int(unsigned int *poolsize, void *int_data);

/**
 * @brief write_wakeup_thresh /proc read handler
 *
 * The call returns the write_wakeup_thresh of the ESDM
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_get_write_wakeup_thresh(unsigned int *write_wakeup_thresh);

/**
 * @brief See esdm_rpcc_get_write_wakeup_thresh
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_get_write_wakeup_thresh_int(unsigned int *write_wakeup_thresh,
					  void *int_data);

/**
 * @brief write_wakeup_thresh /proc write handler
 *
 * The call sets the write_wakeup_thresh of the ESDM to the given bit value
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_set_write_wakeup_thresh(unsigned int write_wakeup_thresh);

/**
 * @brief See esdm_rpcc_set_write_wakeup_thresh
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_set_write_wakeup_thresh_int(unsigned int write_wakeup_thresh,
					  void *int_data);

/**
 * @brief urandom_min_reseed_secs /proc read handler
 *
 * The call returns the urandom_min_reseed_secs of the ESDM
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_get_min_reseed_secs(unsigned int *seconds);

/**
 * @brief See urandom_min_reseed_secs
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_get_min_reseed_secs_int(unsigned int *seconds, void *int_data);

/**
 * @brief urandom_min_reseed_secs /proc write handler
 *
 * The call sets the urandom_min_reseed_secs of the ESDM to the given bit value
 *
 * See random(4) for documentation.
 *
 * @return: 0 on success, < 0 on error (-EINTR means connection was interrupted
 *	    and the caller may try again)
 */
int esdm_rpcc_set_min_reseed_secs(unsigned int seconds);

/**
 * @brief See esdm_rpcc_set_min_reseed_secs
 *
 * The function allows specifying an interrupt callback data structure that
 * is used when invoking the interrupt check function registered with
 * esdm_rpcc_init_priv_service / esdm_rpcc_init_unpriv_service
 */
int esdm_rpcc_set_min_reseed_secs_int(unsigned int seconds, void *int_data);

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
		} while (ret == -EINTR && __ctr++ < 5);			       \
	} while(0)

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_H */
