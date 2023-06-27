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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/shm.h>
#include <unistd.h>

#include "esdm_rpc_service.h"
#include "helper.h"
#include "logger.h"
#include "ret_checkers.h"
#include "test_pertubation.h"

uint32_t seed_entropy[7];
atomic_t seed_entropy_ptr = ATOMIC_INIT(-1);

void esdm_test_seed_entropy(uint32_t ent)
{
	if (atomic_read(&seed_entropy_ptr) >=
	    ((int)ARRAY_SIZE(seed_entropy) - 1))
		return;

	seed_entropy[atomic_inc(&seed_entropy_ptr)] = ent;
}

/******************************************************************************/

static int disable_fallback = 0;

void esdm_test_disable_fallback(int disable)
{
	disable_fallback = disable;
}

int esdm_test_fallback_fd(int fd)
{
	if (fd < 0 || !disable_fallback)
		return fd;

	return -1;
}

/******************************************************************************/

struct esdm_test_shm_status {
	size_t rpc_data_client_written;
	size_t rpc_data_server_written;
};

static struct esdm_test_shm_status *esdm_test_shm_status = NULL;
static int esdm_test_shmid = -1;

#define ESDM_TEST_SHM_NAME "/"
#define ESDM_TEST_SHM_STATUS 99887766

static void esdm_test_shm_status_delete_shm(void)
{
	if (esdm_test_shm_status) {
		shmdt(esdm_test_shm_status);
		esdm_test_shm_status = NULL;
	}

	if (esdm_test_shmid >= 0) {
		shmctl(esdm_test_shmid, IPC_RMID, NULL);
		esdm_test_shmid = -1;
	}
}

static int esdm_test_shm_status_create_shm(void)
{
	int errsv;
	void *tmp;
	key_t key = esdm_ftok(ESDM_TEST_SHM_NAME, ESDM_TEST_SHM_STATUS);
	int ret = 0;

	if (esdm_test_shm_status)
		return 0;

	esdm_test_shmid = shmget(key, sizeof(struct esdm_test_shm_status),
				 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
				 S_IROTH | S_IWOTH);
	if (esdm_test_shmid < 0) {
		if (errno == ENOENT) {
			esdm_test_shmid =
				shmget(key, sizeof(struct esdm_test_shm_status),
				       IPC_CREAT | S_IRUSR | S_IWUSR | S_IRGRP |
				       S_IWGRP | S_IROTH | S_IWOTH);
			errsv = errno;

			if (esdm_test_shmid) {
				esdm_test_shm_status_reset();
				logger(LOGGER_DEBUG, LOGGER_C_ANY,
				       "ESDM test shared memory segment created\n");
			}
		}
		CKNULL_LOG(esdm_test_shmid, -errsv,
		           "ESDM test shared memory segment creation failed\n");
	}

	tmp = shmat(esdm_test_shmid, NULL, 0);
	if (tmp == (void *)-1) {
		errsv = errno;
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Attaching to ESDM shared memory segment failed: %s\n",
		       strerror(errsv));
		esdm_test_shm_status_delete_shm();
		return -errsv;
	}
	esdm_test_shm_status = tmp;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "ESDM test shared memory segment initialized\n");

out:
	return ret;
}

void esdm_test_shm_status_reset(void)
{
	if (!esdm_test_shm_status)
		return;

	esdm_test_shm_status->rpc_data_client_written = 0;
	esdm_test_shm_status->rpc_data_server_written = 0;
}

int esdm_test_shm_status_init(void)
{
	int ret = esdm_test_shm_status_create_shm();

	if (ret)
		return ret;

	return 0;
}

void esdm_test_shm_status_fini(void)
{
	esdm_test_shm_status_delete_shm();
}

void esdm_test_shm_status_add_rpc_client_written(size_t written)
{
	if (esdm_test_shm_status)
		esdm_test_shm_status->rpc_data_client_written += written;
}

size_t esdm_test_shm_status_get_rpc_client_written(void)
{
	if (esdm_test_shm_status)
		return esdm_test_shm_status->rpc_data_client_written;
	return 0;
}

void esdm_test_shm_status_add_rpc_server_written(size_t written)
{
	if (esdm_test_shm_status)
		esdm_test_shm_status->rpc_data_server_written += written;
}

size_t esdm_test_shm_status_get_rpc_server_written(void)
{
	if (esdm_test_shm_status)
		return esdm_test_shm_status->rpc_data_server_written;
	return 0;
}
