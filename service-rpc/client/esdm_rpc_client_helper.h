/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_RPC_CLIENT_HELPER_H
#define ESDM_RPC_CLIENT_HELPER_H

#ifdef __cplusplus
extern "C" {
#endif

#define esdm_rpcc_error_check(response, buffer)                                \
	if (!response) {                                                       \
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "missing data\n");     \
		buffer->ret = -EFAULT;                                         \
		return;                                                        \
	} else if (IS_ERR(response)) {                                         \
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,                        \
			    "missing data - connection interrupted\n");        \
		buffer->ret = (int)PTR_ERR(response);                          \
		return;                                                        \
	}

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_HELPER_H */
