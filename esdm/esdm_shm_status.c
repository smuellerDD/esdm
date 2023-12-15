/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <poll.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/shm.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_es_mgr.h"
#include "esdm_interface_dev_common.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "esdm_shm_status.h"
#include "helper.h"
#include "esdm_logger.h"
#include "ret_checkers.h"

static struct esdm_shm_status *esdm_shm_status = NULL;
static int esdm_shmid = -1;
static sem_t *esdm_semid_random = SEM_FAILED;
static sem_t *esdm_semid_urandom = SEM_FAILED;

static void _esdm_shm_status_up(sem_t *sem)
{
	int semval = 0;

	if (sem == SEM_FAILED)
		return;

	/*
	 * The purpose of the semaphore is to notify clients. If one
	 * notification is sent out, a client must answer. We do not increment
	 * the semaphore again if the client did not "consume" the notification.
	 * The reason is that "consuming" a notification implies that the
	 * event is not present any more for others. Hence the semaphore shall
	 * only toggle between 0 and 1.
	 */
	sem_getvalue(sem, &semval);
	if (semval > 0)
		return;

	if (sem_post(sem))
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot unlock semaphore\n");
}

static void esdm_shm_status_up(void)
{
	_esdm_shm_status_up(esdm_semid_random);
	_esdm_shm_status_up(esdm_semid_urandom);
}

void esdm_shm_status_set_operational(bool enabled)
{
	if (!esdm_shm_status)
		return;

	if (atomic_bool_read(&esdm_shm_status->operational) != enabled) {
		atomic_bool_set(&esdm_shm_status->operational, enabled);
		esdm_shm_status_up();
	}
}

void esdm_shm_status_set_need_entropy(void)
{
	bool new, curr;

	if (!esdm_shm_status)
		return;

	curr = atomic_bool_read(&esdm_shm_status->need_entropy);

	new = esdm_need_entropy();

	if (curr != new) {
		atomic_bool_set(&esdm_shm_status->need_entropy, new);
		esdm_shm_status_up();
	}
}

static void esdm_shm_status_set_suspend(void)
{
	if (!esdm_shm_status)
		return;

	atomic_bool_set(&esdm_shm_status->suspend_trigger, true);
	esdm_shm_status_up();
}

static void esdm_shm_status_server_exit(void)
{
	/* The exit notification is the same as the suspend notification */
	esdm_shm_status_set_suspend();
}

static void esdm_shm_status_signal_suspend(int sig)
{
	(void)sig;
	esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER, "Suspend signal received\n");

	esdm_shm_status_set_suspend();
}

static void esdm_shm_status_install_signal_suspend(void)
{
	esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		    "Install suspend signal handler\n");
	signal(SIGUSR1, esdm_shm_status_signal_suspend);
}

static void _esdm_shm_status_delete_sem(sem_t **sem)
{
	if (*sem != SEM_FAILED) {
		sem_t *tmp = *sem;

		*sem = SEM_FAILED;
		sem_close(tmp);
	}

	/*
	 * TODO: we do not clean up the SEM as there could be a CUSE client that
	 * looks at it. IF the server starts again, we want to attach to the
	 * existing shared memory segment to ensure the client does not need
	 * to be restarted too.
	 */
#if 0
	if (sem_unlink(ESDM_SEM_NAME)) {
		if (errno != ENOENT) {
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "Cannot unlink semaphore: %s\n",
			       strerror(errno));
		}
	}
#endif
}

static void esdm_shm_status_delete_sem(void)
{
	_esdm_shm_status_delete_sem(&esdm_semid_random);
	_esdm_shm_status_delete_sem(&esdm_semid_urandom);
}

static int esdm_shm_status_create_sem(const char *semname, sem_t **sem)
{
	sem_t *tmp;
	int errsv;

	tmp = sem_open(semname, O_CREAT | O_EXCL, 0644, 0);
	if (tmp == SEM_FAILED) {
		if (errno == EEXIST) {
			tmp = sem_open(semname, O_CREAT, 0644, 0);
			if (tmp == SEM_FAILED)
				goto err;

			/* Re-synchronize */
			sem_post(tmp);
		} else {
			goto err;
		}
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "ESDM change indicator semaphore %s initialized\n",
		    semname);
	*sem = tmp;

	return 0;

err:
	errsv = errno;
	esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
		    "ESDM change indicator semaphore creation failed: %s\n",
		    strerror(errsv));
	return -errsv;
}

static void esdm_shm_status_delete_shm(void)
{
	if (esdm_shm_status) {
		shmdt(esdm_shm_status);
		esdm_shm_status = NULL;
	}

	/*
	 * TODO: we do not clean up the SHM as there could be a CUSE client that
	 * looks at it. IF the server starts again, we want to attach to the
	 * existing shared memory segment to ensure the client does not need
	 * to be restarted too.
	 */
#if 0
	if (esdm_shmid >= 0) {
		shmctl(esdm_shmid, IPC_RMID, NULL);
		esdm_shmid = -1;
	}
#endif
}

static int esdm_shm_status_create_shm(void)
{
	int errsv;
	void *tmp;
	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);

	esdm_shmid = shmget(key, sizeof(struct esdm_shm_status),
			    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	errsv = errno;

	/* If we received EINVAL, the memory is too small, force a deletion. */
	if (esdm_shmid < 0 && errsv == EINVAL) {
		/* Try to get it with smallest size possible. */
		esdm_shmid =
			shmget(key, 1, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (esdm_shmid >= 0) {
			if (shmctl(esdm_shmid, IPC_RMID, NULL) < 0) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_SERVER,
					"ESDM shared memory segment cannot be deleted: %s\n",
					strerror(errno));
			} else {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_SERVER,
					"ESDM shared memory segment deleted\n");

				/* Create SHM with the next code block. */
				esdm_shmid = -1;
			}
		}
	}

	/* Create the SHM segment. */
	if (esdm_shmid < 0) {
		esdm_shmid = shmget(key, sizeof(struct esdm_shm_status),
				    IPC_CREAT | S_IRUSR | S_IWUSR | S_IRGRP |
					    S_IROTH);
		if (esdm_shmid < 0) {
			errsv = errno;
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"ESDM shared memory segment creation failed: %s\n",
				strerror(errsv));
			return -errsv;
		}
	}

	tmp = shmat(esdm_shmid, NULL, 0);
	if (tmp == (void *)-1) {
		errsv = errno;
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"Attaching to ESDM shared memory segment failed: %s\n",
			strerror(errsv));
		esdm_shm_status_delete_shm();
		return -errsv;
	}
	esdm_shm_status = tmp;
	esdm_shm_status->version = ESDM_SHM_STATUS_VERSION;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "ESDM shared memory segment initialized\n");

	return 0;
}

int esdm_shm_status_init(void)
{
	int ret = esdm_shm_status_create_shm();

	if (ret)
		return ret;

	ret = esdm_shm_status_create_sem(ESDM_SEM_RANDOM_NAME,
					 &esdm_semid_random);
	if (ret) {
		esdm_shm_status_delete_shm();
		return ret;
	}

	ret = esdm_shm_status_create_sem(ESDM_SEM_URANDOM_NAME,
					 &esdm_semid_urandom);
	if (ret) {
		esdm_shm_status_exit();
		return ret;
	}

	esdm_status(esdm_shm_status->info, sizeof(esdm_shm_status->info));
	esdm_shm_status->infolen = strlen(esdm_shm_status->info);
	esdm_shm_status->unpriv_threads = esdm_config_online_nodes();

	esdm_shm_status_set_operational(esdm_state_operational());
	esdm_shm_status_set_need_entropy();
	esdm_shm_status_install_signal_suspend();

	return 0;
}

void esdm_shm_status_exit(void)
{
	/* Notify the client to inform that the server exists */
	esdm_shm_status_server_exit();
	esdm_shm_status_delete_shm();
	esdm_shm_status_delete_sem();
}

int esdm_shm_status_reinit(void)
{
	int ret;

	esdm_shm_status_exit();
	CKINT(esdm_shm_status_init());

out:
	return ret;
}
