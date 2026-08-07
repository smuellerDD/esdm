/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <sys/shm.h>
#include <time.h>

#include "esdm_aux_client.h"
#include "esdm_logger.h"
#include "esdm_rpc_service.h"
#include "ret_checkers.h"
#include "visibility.h"

/******************************************************************************
 * Shared memory segment
 ******************************************************************************/
static struct esdm_shm_status *esdm_cuse_shm_status = NULL;

static int esdm_cuse_shm_status_avail(void)
{
	static int initialized = 0;
	int ret = (esdm_cuse_shm_status &&
		   esdm_cuse_shm_status->version == ESDM_SHM_STATUS_VERSION);

	if (ret && !initialized) {
		initialized = 1;
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_CUSE,
			"A client started detected ESDM server with properties:\n%.*s\n",
			(int)sizeof(esdm_cuse_shm_status->info),
			esdm_cuse_shm_status->info);
	}

	return ret;
}

static void esdm_cuse_shm_status_close_shm(void)
{
	if (esdm_cuse_shm_status) {
		shmdt(esdm_cuse_shm_status);
		esdm_cuse_shm_status = NULL;
	}
}

static int esdm_cuse_shm_status_create_shm(void)
{
	int esdm_cuse_shmid = -1;
	int errsv, create_shm;
	void *tmp;

	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);

	esdm_cuse_shmid = shmget(key, sizeof(struct esdm_shm_status),
				 S_IRUSR | S_IRGRP | S_IROTH);
	create_shm = (errno == ENOENT) ? 1 : 0;

	/* Check whether the SHM segment is stale */
	if (esdm_cuse_shmid >= 0) {
		struct shmid_ds buf;

		if (shmctl(esdm_cuse_shmid, IPC_STAT, &buf) < 0) {
			errsv = errno;
			esdm_cuse_shm_status_close_shm();
			if (esdm_cuse_shmid >= 0) {
				shmctl(esdm_cuse_shmid, IPC_RMID, NULL);
			}
			return -errsv;
		}

		/*
		 * Ownership is not enforced here: a client cannot know the
		 * server's uid (it may run unprivileged), so rejecting on owner
		 * would break legitimate cross-uid deployments and could strand
		 * a client whose segment the server later re-creates. The primary
		 * defense against a planted status segment is server-side: the
		 * server evicts any foreign-owned segment when it (re)creates the
		 * segment. Note this only covers segments planted before the
		 * server runs its create path; a client that attaches while no
		 * server is running has no way to authenticate the segment, so it
		 * relies on the version gate and the server's eventual eviction.
		 */

		/* SHM exists, but has no attachments -> stale */
		if (buf.shm_nattch == 0) {
			esdm_cuse_shm_status_close_shm();
			if (esdm_cuse_shmid >= 0) {
				shmctl(esdm_cuse_shmid, IPC_RMID, NULL);
				esdm_cuse_shmid = -1;
				create_shm = 1;
			}
		}
	}

	if (esdm_cuse_shmid < 0) {
		if (create_shm) {
			esdm_cuse_shmid =
				shmget(key, sizeof(struct esdm_shm_status),
				       IPC_CREAT | S_IRUSR | S_IWUSR | S_IRGRP |
					       S_IROTH);
			if (esdm_cuse_shmid < 0) {
				errsv = errno;
				esdm_logger(
					LOGGER_ERR, LOGGER_C_ANY,
					"ESDM shared memory segment creation failed: %s\n",
					strerror(errsv));
				return -errsv;
			}
		}
	}

	tmp = shmat(esdm_cuse_shmid, NULL, 0);
	if (tmp == (void *)-1) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Attaching to shared memory segment failed: %s\n",
			    strerror(errsv));
		esdm_cuse_shm_status_close_shm();
		return -errsv;
	}
	esdm_cuse_shm_status = tmp;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
		    "ESDM shared memory segment successfully attached to\n");

	return 0;
}

/******************************************************************************
 * Semaphore for shared memory segment
 ******************************************************************************/

static sem_t *esdm_semid_need_entropy_level = SEM_FAILED;

static int esdm_cuse_shm_status_down(struct timespec *ts)
{
	static const long poll_nsec = 50 * 1000 * 1000;
	struct timespec ts_init = { .tv_sec = 0, .tv_nsec = poll_nsec };

	if (esdm_semid_need_entropy_level == SEM_FAILED) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY, "Cannot use semaphore\n");
		errno = EINVAL;
		return -1;
	}

	/*
	 * Wait for the SHM segment to become available - i.e. for a server to
	 * have published its status in it - but no longer than the caller
	 * allowed. Waiting here without a bound would make the timeout this
	 * function documents unreachable whenever no server is running yet,
	 * which is exactly when a caller needs it: an entropy provider started
	 * alongside the ESDM rather than after it would never come back to
	 * report that, and never retry.
	 *
	 * @ts is the absolute CLOCK_MONOTONIC deadline sem_clockwait() below
	 * is given, so the same deadline applies here, and the timeout is
	 * reported the way sem_clockwait() would report it.
	 */
	while (!esdm_cuse_shm_status_avail()) {
		struct timespec now;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > ts->tv_sec ||
		    (now.tv_sec == ts->tv_sec && now.tv_nsec >= ts->tv_nsec)) {
			errno = ETIMEDOUT;
			return -1;
		}

		nanosleep(&ts_init, NULL);
	}

	/*
	 * If the ESDM server already indicates it needs entropy, return
	 * immediately.
	 */
	if (atomic_load(&esdm_cuse_shm_status->need_entropy))
		return 0;

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
			esdm_semid_need_entropy_level = sem_open(
				ESDM_SEM_NEED_ENTROPY_LEVEL, O_CREAT, 0644, 0);
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
	int ret;

	CKINT(esdm_cuse_shm_status_create_sem());
	CKINT(esdm_cuse_shm_status_create_shm());

out:
	return ret;
}

DSO_PUBLIC
void esdm_aux_fini_wait_for_need_entropy(void)
{
	esdm_cuse_shm_status_close_shm();
	esdm_cuse_shm_status_close_sem();
}

DSO_PUBLIC
int esdm_aux_timedwait_for_need_entropy(struct timespec *ts)
{
	return esdm_cuse_shm_status_down(ts);
}
