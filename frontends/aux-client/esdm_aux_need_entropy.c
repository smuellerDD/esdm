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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <string.h>
#include <time.h>

#include "esdm_aux_client.h"
#include "esdm_logger.h"
#include "esdm_rpc_service.h"
#include "visibility.h"

static sem_t *esdm_semid_need_entropy_level = SEM_FAILED;

static int esdm_cuse_shm_status_down(struct timespec *ts)
{
	if (esdm_semid_need_entropy_level == SEM_FAILED) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot use semaphore\n");
		errno = EINVAL;
		return -1;
	}

	/*
	 * sem_timedwait uses CLOCK_REALTIME, which is subject to
	 * clock adjustments, use sem_clockwait instead here.
	 */
	return sem_clockwait(esdm_semid_need_entropy_level, CLOCK_MONOTONIC,
			     ts);
}

static void esdm_cuse_shm_status_close_sem(void)
{
	if (esdm_semid_need_entropy_level != SEM_FAILED) {
		sem_t *tmp = esdm_semid_need_entropy_level;

		esdm_semid_need_entropy_level = SEM_FAILED;
		sem_close(tmp);
	}
}

static int esdm_cuse_shm_status_create_sem(void)
{
	int errsv;

	esdm_semid_need_entropy_level = sem_open(ESDM_SEM_NEED_ENTROPY_LEVEL,
						 O_CREAT | O_EXCL, 0644, 0);
	if (esdm_semid_need_entropy_level == SEM_FAILED) {
		if (errno == EEXIST) {
			esdm_semid_need_entropy_level =
				sem_open(ESDM_SEM_NEED_ENTROPY_LEVEL, O_CREAT,
					 0644, 0);
			if (esdm_semid_need_entropy_level == SEM_FAILED)
				goto err;
		} else {
			goto err;
		}
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "ESDM change indicator semaphore initialized\n");

	return 0;

err:
	errsv = errno;
	esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
		    "ESDM change indicator semaphore creation failed: %s\n",
		    strerror(errsv));
	return -errsv;
}

DSO_PUBLIC
int esdm_aux_init_wait_for_need_entropy(void)
{
	return esdm_cuse_shm_status_create_sem();
}

DSO_PUBLIC
void esdm_aux_fini_wait_for_need_entropy(void)
{
	esdm_cuse_shm_status_close_sem();
}

DSO_PUBLIC
int esdm_aux_timedwait_for_need_entropy(struct timespec *ts)
{
	return esdm_cuse_shm_status_down(ts);
}
