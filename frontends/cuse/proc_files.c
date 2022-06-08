/* ESDM /proc/sys/kernel/random interface
 *
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

#define FUSE_USE_VERSION 31

#include <errno.h>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "binhexbin.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "privileges.h"
#include "ret_checkers.h"
#include "selinux.h"

#define ESDM_PROC_UUID_LEN		38
#define ESDM_PROC_BUF_LEN		1024
struct esdm_proc_file {
	const char *filename;
	size_t filename_len;
	mode_t perm;
	int (*fill_data)(struct esdm_proc_file *file);
	int (*write_data)(struct esdm_proc_file *file,
			  const char *buf, size_t buflen);
	size_t vallen;
	char valdata[ESDM_PROC_BUF_LEN];
};

/******************************************************************************
 * Helper
 ******************************************************************************/
static const char *esdm_proc_unprivileged_user = "nobody";
static void esdm_proc_drop_privileges(void)
{
	static bool dropped = false;

	if (dropped)
		return;

	if (drop_privileges_transient(esdm_proc_unprivileged_user) == 0)
		dropped = true;
}

static bool esdm_proc_client_privileged(void)
{
	/*
	 * We are not checking the GID as we expect a root user to use any
	 * GID.
	 *
	 * WARNING: as documented for struct fuse_ctx, the FUSE daemon
	 * MUST NOT run in a PID or user namespace.
	 */
	if (fuse_get_context()->uid == 0) {
		logger(LOGGER_DEBUG, LOGGER_C_CUSE, "PROC caller privileged\n");
		return true;
	}

	logger(LOGGER_DEBUG, LOGGER_C_CUSE, "PROC caller unprivileged\n");
	return false;
}

static void esdm_proc_raise_privilege(void)
{
	if (esdm_proc_client_privileged())
		raise_privilege_transient(0, 0);
}

/******************************************************************************
 * Data access functions
 ******************************************************************************/
static void esdm_proc_uuid_bin2hex(uint8_t uuid[16], char uuid_str[37])
{
	bin2hex(uuid, 4, uuid_str, 8, 0);
	uuid_str[8] = '-';

	bin2hex(uuid + 4, 2, uuid_str + 9, 4, 0);
	uuid_str[13] = '-';

	bin2hex(uuid + 6, 2, uuid_str + 14, 4, 0);
	uuid_str[18] = '-';

	bin2hex(uuid + 8, 2, uuid_str + 19, 4, 0);
	uuid_str[23] = '-';

	bin2hex(uuid + 10, 6, uuid_str + 24, 12, 0);

	uuid_str[36] = '\0';
}

static int esdm_proc_uuid(struct esdm_proc_file *file)
{
	uint8_t uuid[16];
	ssize_t ret;

	esdm_invoke(esdm_rpcc_get_random_bytes_full(uuid, sizeof(uuid)));
	if (ret < 0)
		return (int)ret;
	if (ret != sizeof(uuid))
		return -EFAULT;

	/* UUID version is set to 4 denominating a random generation */
	uuid[6] = (uuid[6] & 0x0F) | 0x40;
	uuid[8] = (uuid[8] & 0x3F) | 0x80;

	esdm_proc_uuid_bin2hex(uuid, file->valdata);
	file->valdata[ESDM_PROC_UUID_LEN - 2] = '\n';
	file->valdata[ESDM_PROC_UUID_LEN - 1] = '\0';
	file->vallen = ESDM_PROC_UUID_LEN - 1;
	logger(LOGGER_DEBUG, LOGGER_C_CUSE, "uuid: %s\n", file->valdata);

	return 0;
}

static int esdm_proc_data(struct esdm_proc_file *file,
			  int (*content)(unsigned int *entcnt))
{
	unsigned int val = 0;
	int ret;

	esdm_invoke(content(&val));
	if (!ret) {
		snprintf(file->valdata, ESDM_PROC_BUF_LEN, "%u\n", val);
		file->vallen = strlen(file->valdata);
	}

	return ret;
}

static int esdm_proc_poolsize(struct esdm_proc_file *file)
{
	return esdm_proc_data(file, esdm_rpcc_get_poolsize);
}

static int esdm_proc_get_ent(struct esdm_proc_file *file)
{
	return esdm_proc_data(file, esdm_rpcc_rnd_get_ent_cnt);
}

static int esdm_proc_get_write_wakeup_thresh(struct esdm_proc_file *file)
{
	return esdm_proc_data(file, esdm_rpcc_get_write_wakeup_thresh);
}

static int esdm_proc_set_write_wakeup_thresh(struct esdm_proc_file *file,
					     const char *buf, size_t buflen)
{
	unsigned long thresh = strtoul(buf, NULL, 0);
	int ret;

	(void)file;
	(void)buflen;

	if (thresh >= UINT32_MAX)
		return -ERANGE;

	esdm_proc_raise_privilege();
	esdm_invoke(esdm_rpcc_set_write_wakeup_thresh((uint32_t)thresh));
	drop_privileges_transient(esdm_proc_unprivileged_user);

	return ret;
}

static int esdm_proc_get_min_reseed_secs(struct esdm_proc_file *file)
{
	return esdm_proc_data(file, esdm_rpcc_get_min_reseed_secs);
}

static int esdm_proc_set_min_reseed_secs(struct esdm_proc_file *file,
					 const char *buf, size_t buflen)
{
	unsigned long thresh = strtoul(buf, NULL, 0);
	int ret;

	(void)file;
	(void)buflen;

	if (thresh >= UINT32_MAX)
		return -ERANGE;

	esdm_proc_raise_privilege();
	esdm_invoke(esdm_rpcc_set_min_reseed_secs((uint32_t)thresh));
	drop_privileges_transient(esdm_proc_unprivileged_user);

	return ret;
}

static int esdm_proc_get_status(struct esdm_proc_file *file)
{
	int ret;

	esdm_invoke(esdm_rpcc_status(file->valdata, ESDM_PROC_BUF_LEN));
	if (!ret)
		file->vallen = strlen(file->valdata);

	return ret;
}

static struct esdm_proc_file esdm_proc_files[] = {
	{
		/* Must be first entry! */
		.filename = "boot_id",
		.filename_len = 7,
		.perm = 0444,
		.fill_data = NULL,
		.write_data = NULL,
		.vallen = 0,
		.valdata[0] = '\0',
	}, {
		.filename = "uuid",
		.filename_len = 4,
		.perm = 0444,
		.fill_data = esdm_proc_uuid,
		.write_data = NULL,
		.vallen = 0,
		.valdata[0] = '\0',
	}, {
		.filename = "entropy_avail",
		.filename_len = 13,
		.perm = 0444,
		.fill_data = esdm_proc_get_ent,
		.write_data = NULL,
		.vallen = 0,
		.valdata[0] = '\0',
	}, {
		.filename = "poolsize",
		.filename_len = 8,
		.perm = 0444,
		.fill_data = esdm_proc_poolsize,
		.write_data = NULL,
		.vallen = 0,
		.valdata[0] = '\0',
	}, {
		.filename = "write_wakeup_threshold",
		.filename_len = 22,
		.perm = 0644,
		.fill_data = esdm_proc_get_write_wakeup_thresh,
		.write_data = esdm_proc_set_write_wakeup_thresh,
		.vallen = 0,
		.valdata[0] = '\0',
	}, {
		.filename = "urandom_min_reseed_secs",
		.filename_len = 23,
		.perm = 0644,
		.fill_data = esdm_proc_get_min_reseed_secs,
		.write_data = esdm_proc_set_min_reseed_secs,
		.vallen = 0,
		.valdata[0] = '\0',
	}, {
		.filename = "esdm_type",
		.filename_len = 9,
		.perm = 0444,
		.fill_data = esdm_proc_get_status,
		.write_data = NULL,
		.vallen = 0,
		.valdata[0] = '\0',
	},
};

/******************************************************************************
 * FUSE hander functions
 ******************************************************************************/

static void esdm_proc_term(void)
{
	thread_release(true, true);

	esdm_rpcc_fini_priv_service();
	esdm_rpcc_fini_unpriv_service();
}

static int esdm_proc_pre_init(void)
{
	struct esdm_proc_file *file = &esdm_proc_files[0];
	char buf[ESDM_RPC_MAX_MSG_SIZE];
	size_t data_read = 0;
	ssize_t rc;
	int ret, fd;

	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
	if (fd < 0) {
		logger(LOGGER_ERR, LOGGER_C_CUSE,
		       "Cannot read boot_id (%s) - generating a new boot_id\n",
		       strerror(errno));
		esdm_proc_uuid(file);
	} else {
		do {
			rc = read(fd, file->valdata, ESDM_PROC_UUID_LEN);
			if (rc <= 0)
				break;
			data_read += (size_t)rc;
		} while (data_read < (ESDM_PROC_UUID_LEN - 1));
		file->valdata[ESDM_PROC_UUID_LEN - 1] = '\0';
		file->vallen = ESDM_PROC_UUID_LEN - 1;
	}

	logger(LOGGER_DEBUG, LOGGER_C_CUSE, "boot_id: %s\n", file->valdata);

	CKINT(esdm_rpcc_status(buf, sizeof(buf)));
	logger_status(LOGGER_C_CUSE,
		      "PROC client started with ESDM server properties:\n%s\n",
		      buf);

out:
	return ret;
}

static void *esdm_proc_init(struct fuse_conn_info *conn,
			    struct fuse_config *cfg)
{
	(void)conn;
	cfg->kernel_cache = 0;

	esdm_proc_drop_privileges();

	return NULL;
}

static int esdm_proc_getattr(const char *path, struct stat *stbuf,
			     struct fuse_file_info *fi)
{
	size_t pathlen;
	int ret = 0;
	(void)fi;

	CKNULL(path, -ENOENT);
	pathlen = strlen(path);

	memset(stbuf, 0, sizeof(struct stat));
	if (pathlen == 1 && !strncmp(path, "/", 1)) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
		goto out;
	} else if (pathlen > 1) {
		unsigned int i;

		pathlen--;

		for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
			struct esdm_proc_file *file = &esdm_proc_files[i];

			logger(LOGGER_DEBUG, LOGGER_C_CUSE,
			       "Getattr for file %s\n", file->filename);
			/* pathlen is one longer than file name due to / */
			if (pathlen == file->filename_len &&
			    !strncmp(path + 1, file->filename,
				     file->filename_len)) {
				if (file->fill_data) {
					CKINT(file->fill_data(file));
				}

				stbuf->st_mode = S_IFREG | file->perm;
				stbuf->st_nlink = 1;
				stbuf->st_size = (off_t)file->vallen;
				goto out;
			}
		}
	}

	ret = -ENOENT;

out:
	return ret;
}

static int esdm_proc_readdir(const char *path, void *buf,
			     fuse_fill_dir_t filler,
			     off_t offset, struct fuse_file_info *fi,
			     enum fuse_readdir_flags flags)
{
	unsigned int i;
	int ret = 0;

	(void) offset;
	(void) fi;
	(void) flags;

	CKNULL(path, -ENOENT);

	if (strncmp(path, "/", 1) != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++)
		filler(buf, esdm_proc_files[i].filename, NULL, 0, 0);

out:
	return ret;
}

static int esdm_proc_open(const char *path, struct fuse_file_info *fi)
{
	size_t pathlen;
	unsigned int i;
	int ret = 0;

	CKNULL(path, -ENOENT);
	pathlen = strlen(path);
	if (pathlen <= 1)
		return -ENOENT;
	pathlen--;

	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
		struct esdm_proc_file *file = &esdm_proc_files[i];

		/* pathlen is one longer than file name due to / */
		if (pathlen == file->filename_len &&
		    !strncmp(path + 1, file->filename, file->filename_len)) {

			/* Read-access is always granted */
			if ((fi->flags & O_ACCMODE) == O_RDONLY)
				goto out;

			/*
			 * Write access is only granted for root and then only
			 * for the files that are marked with 0644.
			 */
			if ((((fi->flags & O_ACCMODE) == O_WRONLY) ||
			     ((fi->flags & O_ACCMODE) == O_RDWR)) &&
			    (file->perm & S_IWUSR) &&
			    (fuse_get_context()->uid == 0))
				goto out;

			/* All other access requests are denied. */
			return -EACCES;
		}
	}

	ret = -ENOENT;

out:
	return ret;
}

static int esdm_proc_read(const char *path, char *buf, size_t size,
			  off_t offset, struct fuse_file_info *fi)
{
	size_t pathlen;
	unsigned int i;
	int ret = 0;

	(void) fi;

	CKNULL(path, -ENOENT);
	pathlen = strlen(path);
	if (pathlen <= 1)
		return -ENOENT;
	pathlen--;
	if (offset < 0)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
		struct esdm_proc_file *file = &esdm_proc_files[i];

		/* pathlen is one longer than file name due to / */
		if (pathlen == file->filename_len &&
		    !strncmp(path + 1, file->filename, file->filename_len)) {
			if ((size_t)offset < file->vallen) {
				if ((size_t)offset + size > file->vallen) {
					size = file->vallen - (size_t)offset;
				}
				memcpy(buf, file->valdata + offset, size);
				return (int)size;
			} else {
				return 0;
			}
		}
	}

out:
	return ret;
}

static int esdm_proc_write(const char *path, const char *buf, size_t size,
			   off_t offset, struct fuse_file_info *fi)
{
	size_t pathlen;
	unsigned int i;
	int ret = 0;

	(void) fi;

	CKNULL(path, -ENOENT);
	pathlen = strlen(path);
	if (pathlen <= 1)
		return -ENOENT;
	pathlen--;
	if (offset < 0)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
		struct esdm_proc_file *file = &esdm_proc_files[i];

		/* pathlen is one longer than file name due to / */
		if (pathlen == file->filename_len &&
		    !strncmp(path + 1, file->filename, file->filename_len)) {
			if (!file->write_data)
				return -EOPNOTSUPP;

			CKINT(file->write_data(file, buf + offset, size));
			return (int)size;
		}
	}

out:
	return ret;
}

static const struct fuse_operations esdm_proc_oper = {
	.init           = esdm_proc_init,
	.getattr	= esdm_proc_getattr,
	.readdir	= esdm_proc_readdir,
	.open		= esdm_proc_open,
	.read		= esdm_proc_read,
	.write		= esdm_proc_write,
};

static struct esdm_proc_options {
	int show_help;
	int relabel;
	unsigned int verbosity;
} esdm_proc_options;

#define OPTION(t, p)							\
	{ t, offsetof(struct esdm_proc_options, p), 1 }
static const struct fuse_opt esdm_proc_options_spec[] = {
	OPTION("-v %u", verbosity),
	OPTION("--verbosity=%u", verbosity),
	OPTION("--relabel", relabel),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
	       "    --verbosity=<u>     Verbosity level\n"
	       "    --relabel           Perform automatic SELinux relabeling"
	       "\n");
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	int ret;

	/* Parse options */
	if (fuse_opt_parse(&args, &esdm_proc_options, esdm_proc_options_spec,
			   NULL) == -1) {
		ret = EFAULT;
		goto out;
	}

	logger_set_verbosity(esdm_proc_options.verbosity);

	/*
	 * When --help is specified, first print our own file-system
	 * specific *help text, then signal fuse_main to show
	 * additional help (by adding `--help` to the options again)
	 * without usage: line (by setting argv[0] to the empty
	 * string)
	 */
	if (esdm_proc_options.show_help) {
		show_help(argv[0]);
		fuse_opt_add_arg(&args, "--help");
		args.argv[0][0] = '\0';
	}

	if (esdm_proc_options.relabel) {
		CKINT(esdm_cuse_add_label("/proc/sys/kernel/random/poolsize",
					  &args));
	}

	CKINT_LOG(esdm_rpcc_init_unpriv_service(),
                  "Initialization of dispatcher failed\n");
	CKINT_LOG(esdm_rpcc_init_priv_service(),
                  "Initialization of dispatcher failed\n");

	CKINT(esdm_proc_pre_init());

	ret = fuse_main(args.argc, args.argv, &esdm_proc_oper, NULL);

out:
	fuse_opt_free_args(&args);
	esdm_proc_term();

	return ret;
}
