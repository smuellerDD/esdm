/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <linux/random.h>
#include <poll.h>
#include <semaphore.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>

#include "atomic_64.h"
#include "bool.h"
#include "cuse_device.h"
#include "cuse_helper.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "linux_support.h"
#include "esdm_logger.h"
#include "math_helper.h"
#include "memset_secure.h"
#include "mutex.h"
#include "mutex_w.h"
#include "privileges.h"
#include "queue.h"
#include "ret_checkers.h"
#include "threading_support.h"

/******************************************************************************
 * Bind mount handling code
 ******************************************************************************/

static char *mount_src = NULL;
static char *mount_dst = NULL;

/******************************************************************************
 * Shared memory segment
 ******************************************************************************/

static struct esdm_shm_status *esdm_cuse_shm_status = NULL;
static atomic_64_t next_fh = ATOMIC_64_INIT(1);

static int esdm_cuse_shm_status_avail(void)
{
	static int initialized = 0;
	int ret = (esdm_cuse_shm_status &&
		   esdm_cuse_shm_status->version == ESDM_SHM_STATUS_VERSION);

	if (ret && !initialized)
		initialized = 1;

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
		 * a client whose segment the server later re-creates. The server
		 * evicts any foreign-owned segment on startup, which is the
		 * authoritative defense against a planted status segment.
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

static atomic_bool_t esdm_cuse_poll_thread_shutdown = ATOMIC_BOOL_INIT(false);
/*
 * Predicate for the init handshake below: without it, the checker's
 * thread_wake_all() can fire before esdm_cuse_init() reaches its wait, losing
 * the wakeup and hanging startup.
 */
static atomic_bool_t esdm_cuse_poll_checker_ready = ATOMIC_BOOL_INIT(false);

/*
 * Active FUSE session, published by main_common() while the session loop runs.
 * The termination signal handler reads it to request a clean loop exit via the
 * async-signal-safe fuse_session_exit(). volatile so the handler sees the
 * current value; pointer-sized loads/stores are atomic on supported platforms.
 */
static struct fuse_session *volatile esdm_cuse_session;
static sem_t *esdm_cuse_semid = SEM_FAILED;
static const char *esdm_sem_name = NULL;

static void esdm_cuse_shm_status_down(void)
{
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

	if (esdm_cuse_semid == SEM_FAILED) {
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Cannot use semaphore\n");
		return;
	}

	/* Wait and block until the SHM-Segment becomes available */
	while (!esdm_cuse_shm_status_avail())
		nanosleep(&ts, NULL);

	/* The server is terminating, do not block any more */
	if (atomic_bool_read(&esdm_cuse_poll_thread_shutdown))
		return;

	if (sem_wait(esdm_cuse_semid))
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Cannot use semaphore\n");
}

static void esdm_cuse_shm_status_close_sem(void)
{
	if (esdm_cuse_semid != SEM_FAILED) {
		sem_t *tmp = esdm_cuse_semid;

		esdm_cuse_semid = SEM_FAILED;
		sem_close(tmp);
	}
}

static int esdm_cuse_shm_status_create_sem(void)
{
	int errsv;

	if (!esdm_sem_name)
		return -EFAULT;

	esdm_cuse_semid = sem_open(esdm_sem_name, O_CREAT | O_EXCL, 0644, 0);
	if (esdm_cuse_semid == SEM_FAILED) {
		if (errno == EEXIST) {
			esdm_cuse_semid =
				sem_open(esdm_sem_name, O_CREAT, 0644, 0);
			if (esdm_cuse_semid == SEM_FAILED)
				goto err;
		} else {
			goto err;
		}
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
		    "ESDM change indicator semaphore initialized\n");

	return 0;

err:
	errsv = errno;
	esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
		    "ESDM change indicator semaphore creation failed: %s\n",
		    strerror(errsv));
	return -errsv;
}

/******************************************************************************
 * Signal handler
 ******************************************************************************/

static DECLARE_WAIT_QUEUE(esdm_cuse_poll_checker_wait);

static void esdm_cuse_term(void)
{
	atomic_bool_set(&esdm_cuse_poll_thread_shutdown, true);
	thread_wake_all(&esdm_cuse_poll_checker_wait);
	if (esdm_cuse_semid != SEM_FAILED)
		sem_post(esdm_cuse_semid);

	thread_stop_spawning();

	/*
	 * We forcefully kill the SHM monitor thread as most likely it is
	 * waiting in sem_wait.
	 */
	thread_release(true, true);

	esdm_rpcc_fini_priv_service();
	esdm_rpcc_fini_unpriv_service();

	esdm_cuse_shm_status_close_shm();
	esdm_cuse_shm_status_close_sem();

	/* Return code is irrelevant here */
	esdm_cuse_bind_unmount(&mount_src, &mount_dst);
}

/* terminate the daemon cleanly */
static void esdm_cuse_sig_handler(int sig)
{
	struct fuse_session *se = esdm_cuse_session;

	(void)sig;

	/*
	 * Async-signal-safe only. fuse_session_exit() merely sets the session's
	 * exit flag, which makes fuse_session_loop() return so the real teardown
	 * (esdm_cuse_term) runs in normal context in main_common(). We must NOT
	 * call esdm_cuse_term(), esdm_logger(), free(), thread join/cancel,
	 * shmdt/sem_close, umount, or exit() from here: none are
	 * async-signal-safe and several could self-deadlock against an
	 * interrupted worker (e.g. holding the malloc arena or a mutex).
	 */
	if (se)
		fuse_session_exit(se);
}

static int esdm_cuse_install_sig_handler(void)
{
	/*
	 * Only asynchronous termination signals get the graceful handler: it
	 * makes the FUSE loop return so teardown (incl. bind-unmount) runs in
	 * normal context. Synchronous fault signals (SIGSEGV/SIGBUS/SIGILL/
	 * SIGFPE/SIGABRT/SIGSYS/SIGTRAP) are deliberately left at their default
	 * disposition - a "set flag and return" handler would loop forever on
	 * the faulting instruction, and running teardown from a fault context is
	 * unsafe; a core dump is more useful there.
	 */
	static const int term_signals[] = {
		SIGHUP,	  SIGINT,  SIGQUIT,   SIGTERM, SIGALRM,
		SIGIO,	  SIGPOLL, SIGPROF,   SIGPWR,  SIGUSR1,
		SIGUSR2,  SIGVTALRM, SIGXCPU, SIGXFSZ,
	};
	struct sigaction sa;
	size_t i;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
		    "Install termination signal handler\n");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = esdm_cuse_sig_handler;
	sigemptyset(&sa.sa_mask);
	/*
	 * No SA_RESTART: the FUSE loop's read() must return EINTR so the loop
	 * observes the exit flag set by fuse_session_exit() above. (glibc's
	 * signal() defaults to SA_RESTART, which would suppress that.)
	 * SIGPIPE is intentionally left untouched (control mechanism for
	 * Protobuf-C-RPC).
	 */
	sa.sa_flags = 0;

	for (i = 0; i < sizeof(term_signals) / sizeof(term_signals[0]); i++)
		sigaction(term_signals[i], &sa, NULL);

	return 0;
}

/******************************************************************************
 * CUSE helper
 ******************************************************************************/

#if 0
static bool esdm_cuse_fips_enabled(void)
{
	static char fipsflag[1] = { 'A' };
	size_t n = 0;

	if (fipsflag[0] == 'A') {
#ifdef HAVE_SECURE_GETENV
		if (secure_getenv("ESDM_SERVER_FORCE_FIPS")) {
#else
		if (getenv("ESDM_SERVER_FORCE_FIPS")) {
#endif
			fipsflag[0] = 1;
		} else {
			FILE *fipsfile = NULL;

			fipsfile = fopen("/proc/sys/crypto/fips_enabled", "r");
			if (!fipsfile) {
				if (errno == ENOENT) {
					/* FIPS support not enabled in kernel */
					return 0;
				} else {
					esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
						"FIPS: Cannot open fips_enabled file: %s\n",
						strerror(errno));
					return -EIO;
				}
			}

			n = fread((void *)fipsflag, 1, 1, fipsfile);
			fclose(fipsfile);
			if (n != 1) {
				esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
				       "FIPS: Cannot read FIPS flag\n");
				return false;
			}
		}
	}

	return (fipsflag[0] == '1');
}
#endif

static const char *esdm_cuse_unprivileged_user = "nobody";
static void esdm_cuse_drop_privileges(void)
{
	static bool dropped = false;

	if (dropped)
		return;

	if (linux_isolate_namespace() == 0 &&
	    drop_privileges_transient(esdm_cuse_unprivileged_user) == 0)
		dropped = true;
}

static bool esdm_cuse_client_privileged(fuse_req_t req)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);

	/*
	 * We are not checking the GID as we expect a root user to use any
	 * GID.
	 *
	 * WARNING: as documented for struct fuse_ctx, the CUSE daemon
	 * MUST NOT run in a PID or user namespace.
	 */
	if (ctx->uid == 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
			    "CUSE caller privileged\n");
		return true;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE, "CUSE caller unprivileged\n");
	return false;
}

/*
 * When a privilege level is changed, the write lock must be taken to ensure
 * that no other caller is executing at the same time. If the privilege level
 * remains, a reader lock can be taken allowing concurrent unprivileged
 * operations.
 */
/*
 * Writer-preferring: the unprivileged read/write paths hold the reader lock
 * across a full server RPC, so with the default reader-preferring rwlock a
 * flood of concurrent unprivileged read()/write() calls could starve the
 * writer lock indefinitely and block every privileged ioctl (RNDADDENTROPY,
 * RNDRESEEDCRNG, RNDCLEARPOOL) - an unprivileged denial of service against the
 * admin control path.
 */
static mutex_t esdm_cuse_priv = MUTEX_UNLOCKED_PREFER_WRITER;
static void esdm_cuse_raise_privilege_transient(fuse_req_t req)
{
	mutex_lock(&esdm_cuse_priv);
	if (esdm_cuse_client_privileged(req))
		raise_privilege_transient(0, 0);
}

static void esdm_cuse_drop_privilege_transient(void)
{
	drop_privileges_transient(esdm_cuse_unprivileged_user);
	mutex_unlock(&esdm_cuse_priv);
}

static void esdm_cuse_unpriv_call_start(void)
{
	mutex_reader_lock(&esdm_cuse_priv);
}

static void esdm_cuse_unpriv_call_end(void)
{
	mutex_reader_unlock(&esdm_cuse_priv);
}

/******************************************************************************
 * CUSE callback handler
 ******************************************************************************/
void esdm_cuse_open(fuse_req_t req, struct fuse_file_info *fi)
{
	fi->fh = (uint64_t)atomic_inc_64(&next_fh);
	fuse_reply_open(req, fi);
}

static int esdm_cuse_interrupt(void *data)
{
	fuse_req_t req = (fuse_req_t)data;

	if (!req)
		return 0;
	return !!fuse_req_interrupted(req);
}

void esdm_cuse_read_internal(fuse_req_t req, size_t size, off_t off,
			     struct fuse_file_info *fi, get_func_t get,
			     int fallback_fd)
{
	uint8_t tmpbuf_s[64] = { 0 }, *tmpbuf_p = tmpbuf_s, *tmpbuf = NULL;
	size_t read_bytes = 0;
	ssize_t ret = 0;

	(void)off;

	/*
	 * size is limited by fuse to its maximum request size, mostly
	 * 131072 byte
	 */
	if (size > sizeof(tmpbuf_s)) {
		tmpbuf = calloc(1, size);
		CKNULL(tmpbuf, -ENOMEM);
		tmpbuf_p = tmpbuf;
	}

	fallback_fd = esdm_test_fallback_fd(fallback_fd);

	if (fi->flags & O_SYNC)
		get = esdm_rpcc_get_random_bytes_pr_int;

	/*
	 * fuse automatically chunks requests, e.g. for a 1MB read
	 * multiple <= 131072 byte reads are typically performed, try to fill
	 * them up.
	 */
	while (read_bytes < size) {
		size_t todo = min_size(ESDM_RPC_MAX_DATA, size - read_bytes);

		esdm_cuse_unpriv_call_start();
		esdm_invoke(get(tmpbuf_p + read_bytes, todo, req));
		esdm_cuse_unpriv_call_end();

		/*
		 * If call to the ESDM server failed, let us fall back to the
		 * fallback file descriptor. Yet, we do not cover for short
		 * reads as this entire CUSE handling is prone to short reads
		 * as outlined below. Thus, the caller needs to handle this
		 * appropriately.
		 */
		if (ret < 0 && fallback_fd > -1) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_CUSE,
				"Use fallback to provide data due to RPC error code %zd\n",
				ret);
			ret = read(fallback_fd, tmpbuf_p + read_bytes, todo);
		}

		if (ret < 0)
			goto out;
		read_bytes += (size_t)ret;
	}
	ret = fuse_reply_buf(req, (const char *)tmpbuf_p, size);

out:
	if (tmpbuf) {
		memset_secure(tmpbuf, 0, size);
		free(tmpbuf);
	} else {
		memset_secure(tmpbuf_s, 0, sizeof(tmpbuf_s));
	}

	if (ret < 0)
		fuse_reply_err(req, (int)-ret);
}

void esdm_cuse_write_internal(fuse_req_t req, const char *buf, size_t size,
			      off_t off, struct fuse_file_info *fi,
			      int fallback_fd)
{
	size_t written = 0;
	/*
	 * Default to success so a zero-length write (size == 0, loop body never
	 * runs) is reported as a successful 0-byte write rather than EFAULT.
	 */
	ssize_t ret = 0;

	(void)fi;
	(void)off;

	fallback_fd = esdm_test_fallback_fd(fallback_fd);

	while (written < size) {
		size_t todo = min_size(ESDM_RPC_MAX_DATA, size - written);

		esdm_cuse_unpriv_call_start();
		esdm_invoke(esdm_rpcc_write_data_int(
			(const uint8_t *)buf + written, todo, req));
		esdm_cuse_unpriv_call_end();
		if (ret == 0)
			written += todo;
		else
			goto err;
	}

	goto out;

err:
	/*
	 * If call to the ESDM server failed, let us fall back to the
	 * fallback file descriptor. It writes the entire buffer into the
	 * fallback as we do not consider a mix-n-match of data written to
	 * ESDM and data written to the fallback as appropriate.
	 */
	if (ret < 0 && fallback_fd > -1) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_CUSE,
			"Use fallback to provide data due to RPC error code %zd\n",
			ret);
		written = 0;
		do {
			ret = write(fallback_fd, buf + written, size - written);
			if (ret > 0)
				written += (size_t)ret;
		} while (ret > 0 && written < size);

		/*
		 * A short fallback write (e.g. write() returning 0) must not be
		 * reported to the caller as a successful full write.
		 */
		if (ret >= 0 && written < size)
			ret = -EIO;
	}

out:
	if (ret < 0)
		fuse_reply_err(req, (int)-ret);
	else
		fuse_reply_write(req, written);
}

void esdm_cuse_ioctl(int backend_fd, fuse_req_t req, unsigned long cmd,
		     void *arg, struct fuse_file_info *fi, unsigned flags,
		     const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	const struct rand_pool_info *rpi;
	uint32_t ent_count_bits;
	int ret;

	(void)fi;

	backend_fd = esdm_test_fallback_fd(backend_fd);

	if (flags & FUSE_IOCTL_COMPAT) {
		fuse_reply_err(req, ENOSYS);
		return;
	}

	switch (cmd) {
	case RNDGETENTCNT:
		if (!out_bufsz) {
			struct iovec iov = { arg, sizeof(ent_count_bits) };

			fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
		} else {
			esdm_cuse_unpriv_call_start();
			esdm_invoke(esdm_rpcc_rnd_get_ent_cnt_int(
				&ent_count_bits, req));
			esdm_cuse_unpriv_call_end();
			if (ret)
				fuse_reply_err(req, -ret);
			else
				fuse_reply_ioctl(req, 0, &ent_count_bits,
						 sizeof(ent_count_bits));
		}
		break;
	case RNDADDTOENTCNT:
		if (!in_bufsz || in_bufsz < sizeof(ent_count_bits)) {
			struct iovec iov = { arg, sizeof(ent_count_bits) };
			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else {
			ent_count_bits = *(uint32_t *)in_buf;

			/*
			 * This operation requires privileges. Thus, raise the
			 * privilege level to the same level as the caller has.
			 */
			if (!esdm_cuse_client_privileged(req)) {
				fuse_reply_err(req, EPERM);
				return;
			}
			esdm_cuse_raise_privilege_transient(req);
			esdm_invoke(esdm_rpcc_rnd_add_to_ent_cnt_int(
				ent_count_bits, req));
			/* In case of an error, update the kernel */
			if (ret) {
				if (backend_fd >= 0 &&
				    ioctl(backend_fd, RNDADDTOENTCNT,
					  &ent_count_bits) == -1)
					ret = -errno;
				else
					ret = 0;
			}
			esdm_cuse_drop_privilege_transient();
			if (ret)
				fuse_reply_err(req, -ret);
			else
				fuse_reply_ioctl(req, 0, NULL, 0);
		}
		break;
	case RNDADDENTROPY:
		rpi = (const struct rand_pool_info *)in_buf;

		if (in_bufsz < sizeof(struct rand_pool_info)) {
			struct iovec iov = { arg,
					     sizeof(struct rand_pool_info) };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else if (rpi->buf_size < 0) {
			fuse_reply_err(req, EINVAL);
		} else if ((size_t)rpi->buf_size !=
			   in_bufsz - sizeof(struct rand_pool_info)) {
			struct iovec iov = { arg,
					     sizeof(struct rand_pool_info) +
						     (size_t)rpi->buf_size };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else if (rpi->entropy_count < 0 ||
			   (uint64_t)rpi->entropy_count >
				   (uint64_t)rpi->buf_size * 8) {
			/*
			 * Reject a negative entropy_count (which would otherwise
			 * become a huge value once cast to uint32_t) and any
			 * claim of more entropy bits than the supplied buffer
			 * can hold, mirroring the kernel's RNDADDENTROPY check.
			 */
			fuse_reply_err(req, EINVAL);
		} else {
			/*
			 * This operation requires privileges. Thus, raise the
			 * privilege level to the same level as the caller has.
			 */
			if (!esdm_cuse_client_privileged(req)) {
				fuse_reply_err(req, EPERM);
				return;
			}
			esdm_cuse_raise_privilege_transient(req);

			esdm_invoke(esdm_rpcc_rnd_add_entropy_int(
				(const uint8_t *)rpi->buf,
				(size_t)rpi->buf_size,
				(uint32_t)rpi->entropy_count, req));

			/* In case of an error, update the kernel */
			if (ret) {
				if (backend_fd >= 0 &&
				    ioctl(backend_fd, RNDADDENTROPY, rpi) == -1)
					ret = -errno;
				else
					ret = 0;
			}
			esdm_cuse_drop_privilege_transient();
			if (ret)
				fuse_reply_err(req, -ret);
			else
				fuse_reply_ioctl(req, 0, NULL, 0);
		}
		break;
	case RNDZAPENTCNT:
	case RNDCLEARPOOL:
		/*
		 * This operation requires privileges. Thus, raise the
		 * privilege level to the same level as the caller has.
		 */
		if (!esdm_cuse_client_privileged(req)) {
			fuse_reply_err(req, EPERM);
			return;
		}
		esdm_cuse_raise_privilege_transient(req);
		esdm_invoke(esdm_rpcc_rnd_clear_pool_int(req));
		if (!ret) {
			if (backend_fd >= 0 &&
			    ioctl(backend_fd, RNDCLEARPOOL) == -1)
				ret = -errno;
		}
		esdm_cuse_drop_privilege_transient();
		if (ret)
			fuse_reply_err(req, -ret);
		else
			fuse_reply_ioctl(req, 0, NULL, 0);
		break;
	case RNDRESEEDCRNG:
		/*
		 * This operation requires privileges. Thus, raise the
		 * privilege level to the same level as the caller has.
		 */
		if (!esdm_cuse_client_privileged(req)) {
			fuse_reply_err(req, EPERM);
			return;
		}
		esdm_cuse_raise_privilege_transient(req);
		esdm_invoke(esdm_rpcc_rnd_reseed_crng_int(req));
		if (!ret) {
			if (backend_fd >= 0 &&
			    ioctl(backend_fd, RNDRESEEDCRNG) == -1)
				ret = -errno;
		}
		esdm_cuse_drop_privilege_transient();
		if (ret)
			fuse_reply_err(req, -ret);
		else
			fuse_reply_ioctl(req, 0, NULL, 0);
		break;

	/* ESDM-specific IOCTL: get ESDM information */
	case 42: {
		size_t infolen;

		if (!esdm_cuse_shm_status) {
			fuse_reply_err(req, EAGAIN);
			break;
		}

		/* Clamp infolen to buffer bounds to prevent overread */
		infolen = esdm_cuse_shm_status->infolen;
		if (infolen > ESDM_SHM_STATUS_INFO_SIZE)
			infolen = ESDM_SHM_STATUS_INFO_SIZE;

		if (out_bufsz < infolen) {
			struct iovec iov = { arg, infolen };

			fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
		} else {
			fuse_reply_ioctl(req, 0, esdm_cuse_shm_status->info,
					 infolen);
		}
		break;
	}

	/* ESDM-specific IOCTL: Reseed kernel directly */
	case 43:
		rpi = (const struct rand_pool_info *)in_buf;

		if (in_bufsz < sizeof(struct rand_pool_info)) {
			struct iovec iov = { arg,
					     sizeof(struct rand_pool_info) };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else if (rpi->buf_size < 0) {
			fuse_reply_err(req, EINVAL);
		} else if ((size_t)rpi->buf_size !=
			   in_bufsz - sizeof(struct rand_pool_info)) {
			struct iovec iov = { arg,
					     sizeof(struct rand_pool_info) +
						     (size_t)rpi->buf_size };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else {
			/*
			 * This operation requires privileges. Thus, raise the
			 * privilege level to the same level as the caller has.
			 */
			if (!esdm_cuse_client_privileged(req)) {
				fuse_reply_err(req, EPERM);
				return;
			}
			esdm_cuse_raise_privilege_transient(req);
			if (backend_fd >= 0 &&
			    ioctl(backend_fd, RNDADDENTROPY, rpi) == -1)
				ret = -errno;
			else
				ret = 0;
			esdm_cuse_drop_privilege_transient();
			if (ret)
				fuse_reply_err(req, -ret);
			else
				fuse_reply_ioctl(req, 0, NULL, 0);
		}
		break;

	/* ESDM-specific IOCTL: force reseed of kernel CRNG directly */
	case 44:
		/*
		* This operation requires privileges. Thus, raise the
		* privilege level to the same level as the caller has.
		*/
		if (!esdm_cuse_client_privileged(req)) {
			fuse_reply_err(req, EPERM);
			return;
		}
		esdm_cuse_raise_privilege_transient(req);
		if (backend_fd >= 0 && ioctl(backend_fd, RNDRESEEDCRNG) == -1)
			ret = -errno;
		else
			ret = 0;
		esdm_cuse_drop_privilege_transient();
		if (ret)
			fuse_reply_err(req, -ret);
		else
			fuse_reply_ioctl(req, 0, NULL, 0);
		break;

	default:
		fuse_reply_err(req, EINVAL);
	}
}

/******************************************************************************
 * Poll system call handler
 ******************************************************************************/

#define ESDM_CUSE_MAX_PH 16
struct esdm_cuse_poll {
	uint64_t fh;
	struct fuse_pollhandle *ph;
	uint32_t poll_events;
};
static struct esdm_cuse_poll esdm_cuse_polls[ESDM_CUSE_MAX_PH];
static DEFINE_MUTEX_W_UNLOCKED(esdm_cuse_ph_lock);

static void esdm_cuse_get_pollmask(unsigned int *outmask)
{
#define ESDM_POLL_READER (POLLIN | POLLRDNORM)
#define ESDM_POLL_WRITER (POLLOUT | POLLWRNORM)

	*outmask = 0;

	/*
	 * Guard against a not-yet-attached status segment, mirroring the other
	 * consumers (e.g. ioctl case 42). Init failure exits the process, so
	 * this is normally unreachable, but keep the access symmetric and safe.
	 */
	if (!esdm_cuse_shm_status)
		return;

	if (atomic_bool_read(&esdm_cuse_shm_status->operational))
		*outmask |= ESDM_POLL_READER;
	if (atomic_bool_read(&esdm_cuse_shm_status->need_entropy))
		*outmask |= ESDM_POLL_WRITER;

	/* Simply wake the poller no matter what it waits for. */
	if (atomic_bool_read(&esdm_cuse_shm_status->suspend_trigger)) {
		atomic_bool_set(&esdm_cuse_shm_status->suspend_trigger, false);
		*outmask |= ESDM_POLL_READER | ESDM_POLL_WRITER;
	}

	/* Simply wake the poller no matter what it waits for. */
	if (atomic_bool_read(&esdm_cuse_poll_thread_shutdown))
		*outmask |= ESDM_POLL_READER | ESDM_POLL_WRITER;
}

/* *outmask is already filled with output of esdm_cuse_get_pollmask */
static void esdm_cuse_set_pollmask(unsigned int request_events,
				   unsigned int *outmask)
{
	*outmask &= request_events;
}

/* when extending this function, always check and return error
 * codes first, as they may originate from an interrupted poll/select
 * which causes many bogus events if answered with notify_poll or reply_poll
 */
void esdm_cuse_poll(fuse_req_t req, struct fuse_file_info *fi,
		    struct fuse_pollhandle *ph)
{
	unsigned int i, mask;
	int err_code;

	if (!fi->poll_events) {
		err_code = EINVAL;
		goto err;
	}

	/*
	 * Check current status and return it if it complies with requested
	 * status.
	 */
	esdm_cuse_get_pollmask(&mask);
	esdm_cuse_set_pollmask(fi->poll_events, &mask);
	fuse_reply_poll(req, mask);

	/* cleanup first, as we may have an interrupted poll/select */
	mutex_w_lock(&esdm_cuse_ph_lock);
	{
		unsigned int free_slot = ESDM_CUSE_MAX_PH;

		/*
		 * First pass: drop any stale handle for this fh and remember the
		 * first free slot. Doing the cleanup as a full pass - rather than
		 * merging it with the insert and breaking early - preserves the
		 * one-handle-per-fh invariant even when a free slot has a lower
		 * index than the stale entry (which would otherwise leave a
		 * duplicate registration behind).
		 */
		for (i = 0; i < ESDM_CUSE_MAX_PH; i++) {
			if (esdm_cuse_polls[i].fh == fi->fh) {
				if (esdm_cuse_polls[i].ph)
					fuse_pollhandle_destroy(
						esdm_cuse_polls[i].ph);
				esdm_cuse_polls[i].fh = 0;
				esdm_cuse_polls[i].ph = NULL;
				esdm_cuse_polls[i].poll_events = 0;
			}

			if (free_slot == ESDM_CUSE_MAX_PH &&
			    !esdm_cuse_polls[i].ph)
				free_slot = i;
		}

		if (mask || free_slot == ESDM_CUSE_MAX_PH) {
			/*
			 * Events are already available (already replied above)
			 * or there is no free slot: notify if ready and destroy
			 * ph, as the callee owns it when it is not stored.
			 */
			if (mask)
				fuse_notify_poll(ph);
			fuse_pollhandle_destroy(ph);
		} else {
			esdm_cuse_polls[free_slot].fh = fi->fh;
			esdm_cuse_polls[free_slot].ph = ph;
			esdm_cuse_polls[free_slot].poll_events =
				fi->poll_events;
		}
	}
	mutex_w_unlock(&esdm_cuse_ph_lock);

	return;

err:
	fuse_reply_err(req, err_code);
}

/* Poll checker handler executed in separate thread */
static int esdm_cuse_poll_checker(void __unused *unused)
{
	unsigned int i;

	thread_set_name(cuse_poll, 0);

	/* Clean out the poll status */
	for (i = 0; i < ESDM_CUSE_MAX_PH; i++) {
		esdm_cuse_polls[i].fh = 0;
		esdm_cuse_polls[i].ph = NULL;
		esdm_cuse_polls[i].poll_events = 0;
	}
	atomic_bool_set_true(&esdm_cuse_poll_checker_ready);
	thread_wake_all(&esdm_cuse_poll_checker_wait);

	while (!atomic_bool_read(&esdm_cuse_poll_thread_shutdown)) {
		unsigned int sysmask, mask;
		bool sysmask_set = false;

		mutex_w_lock(&esdm_cuse_ph_lock);
		for (i = 0; i < ESDM_CUSE_MAX_PH; i++) {
			if (!esdm_cuse_polls[i].ph)
				continue;

			/* Get the mask once for this loop */
			if (!sysmask_set) {
				esdm_cuse_get_pollmask(&sysmask);
				sysmask_set = true;
			}

			mask = sysmask;
			esdm_cuse_set_pollmask(esdm_cuse_polls[i].poll_events,
					       &mask);

			if (!mask)
				continue;

			fuse_notify_poll(esdm_cuse_polls[i].ph);
			fuse_pollhandle_destroy(esdm_cuse_polls[i].ph);
			esdm_cuse_polls[i].fh = 0;
			esdm_cuse_polls[i].ph = NULL;
			esdm_cuse_polls[i].poll_events = 0;
		}
		mutex_w_unlock(&esdm_cuse_ph_lock);
		esdm_cuse_shm_status_down();
	}

	return 0;
}

void esdm_cuse_release(fuse_req_t req, struct fuse_file_info *fi)
{
	unsigned int i;

	mutex_w_lock(&esdm_cuse_ph_lock);
	for (i = 0; i < ESDM_CUSE_MAX_PH; i++) {
		if (esdm_cuse_polls[i].fh == fi->fh) {
			fuse_notify_poll(esdm_cuse_polls[i].ph);
			fuse_pollhandle_destroy(esdm_cuse_polls[i].ph);

			esdm_cuse_polls[i].fh = 0;
			esdm_cuse_polls[i].ph = NULL;
			esdm_cuse_polls[i].poll_events = 0;
		}
	}
	mutex_w_unlock(&esdm_cuse_ph_lock);

	fuse_reply_err(req, 0);
}

/******************************************************************************
 * CUSE daemon
 ******************************************************************************/

void esdm_cuse_init_done(void *userdata)
{
	int ret;

	(void)userdata;

	if (mount_src) {
		if (chmod(mount_src, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
					     S_IROTH | S_IWOTH) < 0) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_CUSE,
				"Changing permissions to world-writeable failed: %s",
				strerror(errno));
		}
	}

	CKINT(esdm_cuse_bind_mount(mount_src, mount_dst));

	CKINT(esdm_cuse_shm_status_create_sem());
	CKINT(esdm_cuse_shm_status_create_shm());

	esdm_cuse_drop_privileges();

	CKINT_LOG(thread_start(esdm_cuse_poll_checker, NULL,
			       ESDM_THREAD_CUSE_POLL_GROUP, NULL),
		  "Starting poll-in-reset thread failed: %d\n", ret);

	/* Wait until thread is fully initialized */
	thread_wait_event(&esdm_cuse_poll_checker_wait,
			  atomic_bool_read(&esdm_cuse_poll_checker_ready) ||
				  atomic_bool_read(
					  &esdm_cuse_poll_thread_shutdown));

	return;

out:
	esdm_cuse_term();
	exit(-ret);
}

struct esdm_cuse_param {
	unsigned int major;
	unsigned int minor;
	char *dev_name;
	char *username;
	unsigned int verbosity;
	int is_help;
	int disable_fallback;
	int syslog;
};

#define ESDM_CUSE_OPT(t, p) { t, offsetof(struct esdm_cuse_param, p), 1 }

static const char *usage =
	"usage: esdm_cuse [options]\n"
	"\n"
	"options:\n"
	"    --help|-h               print this help message\n"
	"    --maj=MAJ|-M MAJ        device major number\n"
	"    --min=MIN|-m MIN        device minor number\n"
	"    --name=NAME|-n NAME     device name (mandatory)\n"
	"    --verbosity=NUM|-v NUM  verbosity level\n"
	"    --username=USER|-u USER unprivileged user name (default: \"nobody\")\n"
	"    -d   -o debug           enable debug output (implies -f)\n"
	"    -f                      foreground operation\n"
	"    -s                      disable multi-threaded operation\n"
	"    -S                      log via syslog\n"
	"\n";

/* The CUSE code seems to have a conversion issue with FUSE_OPT_KEY */
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wimplicit-int-conversion"
#endif
static const struct fuse_opt esdm_cuse_opts[] = {
	ESDM_CUSE_OPT("-M %u", major),
	ESDM_CUSE_OPT("--maj=%u", major),
	ESDM_CUSE_OPT("-m %u", minor),
	ESDM_CUSE_OPT("--min=%u", minor),
	ESDM_CUSE_OPT("-n %s", dev_name),
	ESDM_CUSE_OPT("--name=%s", dev_name),
	ESDM_CUSE_OPT("-v %u", verbosity),
	ESDM_CUSE_OPT("--verbosity=%u", verbosity),
	ESDM_CUSE_OPT("-u %s", username),
	ESDM_CUSE_OPT("--username %s", username),
#ifdef ESDM_TESTMODE
	ESDM_CUSE_OPT("--disable_fallback=%d", disable_fallback),
#endif
	FUSE_OPT_KEY("-h", 0),
	FUSE_OPT_KEY("--help", 0),
	FUSE_OPT_KEY("-S", 1),
	FUSE_OPT_KEY("--syslog", 1),
	FUSE_OPT_END
};
#pragma GCC diagnostic pop

static int esdm_cuse_process_arg(void *data, const char *arg, int key,
				 struct fuse_args *outargs)
{
	struct esdm_cuse_param *param = data;

	(void)outargs;
	(void)arg;

	switch (key) {
	case 0:
		param->is_help = 1;
		fprintf(stderr, "%s", usage);
		return fuse_opt_add_arg(outargs, "-ho");
	case 1:
		param->syslog = 1;
		return 0;
	default:
		return 1;
	}
}

int main_common(const char *_devname, const char *target, const char *semname,
		const struct cuse_lowlevel_ops *clop, int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct esdm_cuse_param param = { 0, 0, NULL, NULL, 1, 0, 0, 0 };
	char dev_name[128] = "DEVNAME=";
	char devname[20];
	const char *dev_info_argv[] = { dev_name };
	struct cuse_info ci;
	int ret = 1;

	if (fuse_opt_parse(&args, &param, esdm_cuse_opts,
			   esdm_cuse_process_arg)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "failed to parse option\n");
		free(param.dev_name);
		goto out;
	}

	esdm_logger_set_verbosity(param.verbosity);

	if (param.syslog) {
		esdm_logger_enable_syslog("esdm-cuse");
	}

	esdm_test_disable_fallback(param.disable_fallback);

	CKINT(esdm_cuse_file_name(devname, sizeof(devname), _devname));

	if (!param.is_help) {
		const char *dev_name_p = param.dev_name;

		/*
		 * The param.username is not freed - we allow this slight
		 * imprecise programming for now as the user name must be
		 * available for the duration of this process. Thus, let the
		 * kernel clean it up during program termination. Yet, we
		 * do not leak memory.
		 */
		if (param.username)
			esdm_cuse_unprivileged_user = param.username;

		if (!param.dev_name)
			dev_name_p = devname;

		strncat(dev_name, dev_name_p,
			sizeof(dev_name) - sizeof("DEVNAME="));

		if (target) {
			char devfile[128] = "/dev/";

			strncat(devfile, dev_name_p,
				sizeof(devfile) - sizeof("/dev/"));
			mount_src = strndup(devfile, sizeof(devfile));
			if (!mount_src)
				return -errno;
			mount_dst = strdup(target);
			if (!mount_dst) {
				int errsv = errno;

				free(mount_src);
				mount_src = NULL;
				return -errsv;
			}
		}

		if (param.dev_name)
			free(param.dev_name);
	}

	/*
	 * Clear supplemental groups once, while still running as (e)uid 0 and
	 * before the CUSE device is reachable by clients. See
	 * drop_supplemental_groups() for why this cannot be done during the
	 * transient privilege drop.
	 */
	if (geteuid() == 0)
		drop_supplemental_groups();

	CKINT_LOG(esdm_rpcc_init_unpriv_service(esdm_cuse_interrupt),
		  "Initialization of dispatcher failed\n");
	CKINT_LOG(esdm_rpcc_init_priv_service(esdm_cuse_interrupt),
		  "Initialization of dispatcher failed\n");

	/* Enter PID namespace */
	CKINT(linux_isolate_namespace_prefork());

	/* One thread group */
	CKINT(thread_init(1));

	esdm_sem_name = semname;

	memset(&ci, 0, sizeof(ci));
	ci.dev_major = 0;
	ci.dev_minor = 0;
	ci.dev_info_argc = 1;
	ci.dev_info_argv = dev_info_argv;
	ci.flags = CUSE_UNRESTRICTED_IOCTL;

	esdm_cuse_install_sig_handler();

	/*
	 * Open-code cuse_lowlevel_main() so the session handle is reachable by
	 * the signal handler (via esdm_cuse_session), which exits the loop
	 * cleanly instead of running teardown from signal context. On loop
	 * return the ESDM-specific teardown runs below at out: in normal
	 * context.
	 */
	{
		int multithreaded = 0;
		struct fuse_session *se = cuse_lowlevel_setup(
			args.argc, args.argv, &ci, clop, &multithreaded, NULL);

		if (se == NULL) {
			ret = 1;
		} else {
			esdm_cuse_session = se;

			if (multithreaded)
				ret = fuse_session_loop_mt(se, 0);
			else
				ret = fuse_session_loop(se);

			esdm_cuse_session = NULL;
			cuse_lowlevel_teardown(se);
			ret = ret ? 1 : 0;
		}
	}

out:
	esdm_cuse_term();
	fuse_opt_free_args(&args);
	return ret;
}
