/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
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

/*
 * Tests for the esdm-proc filesystem handlers.
 *
 * Mounting it needs root and /dev/fuse, but the handlers themselves are
 * ordinary functions of a path and a mode - what they decide does not depend on
 * a session being up. The one that matters most is esdm_proc_open(): it is what
 * stands between an arbitrary user and the ESDM's tunables, and the answer must
 * come out the same whether the caller is root or not, and whether the file is
 * one of the writable ones or not.
 *
 * The rest of the file is reached without a server as well, because that is
 * what the handlers have to survive: every one that produces content asks the
 * ESDM for it, and with nothing answering they must report an empty file rather
 * than a stale or an uninitialized one. The values a caller writes are refused
 * before any of that, so the whole input validation is reachable too.
 *
 * The translation unit is compiled into the test so the static handlers can be
 * called directly. Its main() is renamed out of the way by the build, and
 * fuse_get_context() is provided here - the real one returns nothing useful
 * outside a session, and controlling the caller's uid is the whole point of the
 * permission tests below.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"

/*
 * The unit under test. Its main() is renamed by the build; declare the renamed
 * one so it does not trip -Wmissing-prototypes, and put the name back
 * afterwards for our own.
 */
int esdm_proc_main_unused(int argc, char *argv[]);
#include "proc_files.c"

/* ... and put the name back for our own */
#undef main

/* The uid esdm_proc_open() sees; set per case below */
static uid_t test_ctx_uid;
static struct fuse_context test_ctx;

struct fuse_context *fuse_get_context(void)
{
	memset(&test_ctx, 0, sizeof(test_ctx));
	test_ctx.uid = test_ctx_uid;

	return &test_ctx;
}

static void test_uuid_bin2hex(void)
{
	uint8_t uuid[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
			     0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
			     0x76, 0x54, 0x32, 0x10 };
	char str[37];

	memset(str, 0x5a, sizeof(str));
	esdm_proc_uuid_bin2hex(uuid, str);

	/* The canonical 8-4-4-4-12 form, terminated */
	CHECK_STR_EQ(str, "01234567-89ab-cdef-fedc-ba9876543210");
}

static void test_getattr(void)
{
	struct stat sb;

	/* The mount point itself is a directory nobody may write */
	memset(&sb, 0xff, sizeof(sb));
	CHECK_EQ(esdm_proc_getattr("/", &sb, NULL), 0);
	CHECK(S_ISDIR(sb.st_mode), "the root of the mount is not a directory");
	CHECK_EQ(sb.st_mode & 07777, 0555);

	/* A name that is not one of ours */
	CHECK_EQ(esdm_proc_getattr("/no_such_file", &sb, NULL), -ENOENT);

	/* A path is required */
	CHECK_EQ(esdm_proc_getattr(NULL, &sb, NULL), -ENOENT);

	/*
	 * "uuid" reports a fixed size, so stat() answers without generating
	 * one - a bare stat must not consume DRNG output.
	 */
	memset(&sb, 0, sizeof(sb));
	CHECK_EQ(esdm_proc_getattr("/uuid", &sb, NULL), 0);
	CHECK(S_ISREG(sb.st_mode), "uuid is not a regular file");
	CHECK_EQ(sb.st_mode & 07777, 0444);
	CHECK_EQ(sb.st_size, ESDM_PROC_UUID_LEN - 1);
}

static unsigned int filler_calls;
static char filler_seen[4096];

static int test_filler(void *buf, const char *name, const struct stat *stbuf,
		       off_t off, enum fuse_fill_dir_flags flags)
{
	(void)buf;
	(void)stbuf;
	(void)off;
	(void)flags;

	filler_calls++;
	strncat(filler_seen, name,
		sizeof(filler_seen) - strlen(filler_seen) - 2);
	strncat(filler_seen, "|", 2);

	return 0;
}

static void test_readdir(void)
{
	unsigned int i;

	filler_calls = 0;
	filler_seen[0] = '\0';

	CHECK_EQ(esdm_proc_readdir("/", NULL, test_filler, 0, NULL, 0), 0);

	/* Every file the table declares is listed, plus . and .. */
	CHECK_EQ(filler_calls, ARRAY_SIZE(esdm_proc_files) + 2);
	CHECK(strstr(filler_seen, ".|") != NULL, "the listing has no .");
	CHECK(strstr(filler_seen, "..|") != NULL, "the listing has no ..");

	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
		char needle[64];

		snprintf(needle, sizeof(needle), "%s|",
			 esdm_proc_files[i].filename);
		CHECK(strstr(filler_seen, needle) != NULL,
		      "the listing does not contain %s",
		      esdm_proc_files[i].filename);
	}

	/* Only the root directory can be listed */
	CHECK_EQ(esdm_proc_readdir("/uuid", NULL, test_filler, 0, NULL, 0),
		 -ENOENT);
	CHECK_EQ(esdm_proc_readdir(NULL, NULL, test_filler, 0, NULL, 0),
		 -ENOENT);
}

static int open_as(uid_t uid, const char *path, int flags)
{
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = flags;
	test_ctx_uid = uid;

	return esdm_proc_open(path, &fi);
}

static void test_open_permissions(void)
{
	unsigned int i;

	/* Reading is open to everybody, for every file the table declares */
	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
		char path[64];

		snprintf(path, sizeof(path), "/%s",
			 esdm_proc_files[i].filename);

		CHECK(!open_as(1000, path, O_RDONLY),
		      "an unprivileged reader was refused %s", path);
		CHECK(!open_as(0, path, O_RDONLY),
		      "root was refused reading %s", path);
	}

	/*
	 * Writing is for root, and only where the table says the file is
	 * writable at all. Both halves matter: an unprivileged user must not
	 * be able to move the ESDM's thresholds, and even root must not write
	 * a file that only reports.
	 */
	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
		struct esdm_proc_file *file = &esdm_proc_files[i];
		bool writable = !!(file->perm & S_IWUSR);
		char path[64];

		snprintf(path, sizeof(path), "/%s", file->filename);

		CHECK_EQ(open_as(1000, path, O_WRONLY), -EACCES);
		CHECK_EQ(open_as(1000, path, O_RDWR), -EACCES);

		if (writable) {
			CHECK(!open_as(0, path, O_WRONLY),
			      "root was refused writing the writable %s", path);
			CHECK(!open_as(0, path, O_RDWR),
			      "root was refused writing the writable %s", path);
		} else {
			CHECK_EQ(open_as(0, path, O_WRONLY), -EACCES);
			CHECK_EQ(open_as(0, path, O_RDWR), -EACCES);
		}
	}

	/* Names that are not ours are absent rather than forbidden */
	CHECK_EQ(open_as(0, "/no_such_file", O_RDONLY), -ENOENT);
	CHECK_EQ(open_as(0, "/", O_RDONLY), -ENOENT);
	CHECK_EQ(open_as(0, NULL, O_RDONLY), -ENOENT);
}

/* The file the read and write cases work on, by name */
static struct esdm_proc_file *file_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
		if (!strcmp(esdm_proc_files[i].filename, name))
			return &esdm_proc_files[i];
	}

	CHECK(0, "the file table has no %s", name);

	return NULL;
}

/*
 * Reading serves whatever the last fill_data() left behind, which is what makes
 * a partial read - the second `cat` of a file larger than the buffer - come
 * back with the rest rather than with the beginning again.
 */
static void test_read(void)
{
	struct esdm_proc_file *file = file_by_name("poolsize");
	char buf[64];

	if (!file)
		return;

	snprintf(file->valdata, sizeof(file->valdata), "1024\n");
	file->vallen = strlen(file->valdata);

	memset(buf, 0, sizeof(buf));
	CHECK_EQ(esdm_proc_read("/poolsize", buf, sizeof(buf), 0, NULL), 5);
	CHECK_STR_EQ(buf, "1024\n");

	/* A short read is not padded, and the rest picks up where it left off */
	memset(buf, 0, sizeof(buf));
	CHECK_EQ(esdm_proc_read("/poolsize", buf, 2, 0, NULL), 2);
	CHECK_MEM_EQ(buf, "10", 2);

	memset(buf, 0, sizeof(buf));
	CHECK_EQ(esdm_proc_read("/poolsize", buf, sizeof(buf), 2, NULL), 3);
	CHECK_MEM_EQ(buf, "24\n", 3);

	/* At and past the end there is nothing left to deliver */
	CHECK_EQ(esdm_proc_read("/poolsize", buf, sizeof(buf), 5, NULL), 0);
	CHECK_EQ(esdm_proc_read("/poolsize", buf, sizeof(buf), 4096, NULL), 0);

	/* A negative offset is a caller error, an absent path is not a file */
	CHECK_EQ(esdm_proc_read("/poolsize", buf, sizeof(buf), -1, NULL),
		 -EINVAL);
	CHECK_EQ(esdm_proc_read("/", buf, sizeof(buf), 0, NULL), -ENOENT);
	CHECK_EQ(esdm_proc_read(NULL, buf, sizeof(buf), 0, NULL), -ENOENT);
}

/*
 * Writing is refused for everything the table has no setter for. The permission
 * check in esdm_proc_open() is the first gate; this is the second one, and it
 * has to hold on its own - open() and write() are separate requests, and only
 * the handler knows whether the file can take a value at all.
 */
static void test_write_dispatch(void)
{
	const char *val = "42";

	CHECK_EQ(esdm_proc_write("/poolsize", val, 2, 0, NULL), -EOPNOTSUPP);
	CHECK_EQ(esdm_proc_write("/boot_id", val, 2, 0, NULL), -EOPNOTSUPP);

	/* Neither a negative offset nor one past the data can be honoured */
	CHECK_EQ(esdm_proc_write("/write_wakeup_threshold", val, 2, -1, NULL),
		 -EINVAL);
	CHECK_EQ(esdm_proc_write("/write_wakeup_threshold", val, 2, 3, NULL),
		 -EINVAL);

	CHECK_EQ(esdm_proc_write("/", val, 2, 0, NULL), -ENOENT);
	CHECK_EQ(esdm_proc_write(NULL, val, 2, 0, NULL), -ENOENT);
}

/*
 * What a caller may put into the two writable files. All of it is rejected
 * before the value reaches the ESDM, which is the point: an unusable number
 * must not travel to the server to be refused there.
 */
static void test_write_values_rejected(void)
{
	static const struct {
		const char *desc;
		const char *val;
		size_t len;
		int expected;
	} cases[] = {
		{ "an empty write", "", 0, -EINVAL },
		{ "a value longer than any number",
		  "000000000000000000000000000000000000", 36, -EINVAL },
		{ "a number beyond the interface's range", "4294967296", 10,
		  -ERANGE },
		{ "a number beyond what fits at all",
		  "99999999999999999999999", 23, -ERANGE },
	};
	struct esdm_proc_file *thresh = file_by_name("write_wakeup_threshold");
	struct esdm_proc_file *secs = file_by_name("urandom_min_reseed_secs");
	size_t i;

	if (!thresh || !secs)
		return;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		CHECK(esdm_proc_set_write_wakeup_thresh(
			      thresh, cases[i].val, cases[i].len) ==
			      cases[i].expected,
		      "the write wakeup threshold accepted %s", cases[i].desc);
		CHECK(esdm_proc_set_min_reseed_secs(secs, cases[i].val,
						    cases[i].len) ==
			      cases[i].expected,
		      "the reseed interval accepted %s", cases[i].desc);
	}
}

/*
 * Every file that produces content asks the ESDM for it. With no server there
 * is nothing to report, and what must not happen is that the file keeps
 * whatever it held before - a reader would take that for the current state.
 */
static void test_fill_data_without_server(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(esdm_proc_files); i++) {
		struct esdm_proc_file *file = &esdm_proc_files[i];
		char path[64];
		struct stat sb;

		if (!file->fill_data)
			continue;

		/* Something a stale answer could be mistaken for */
		snprintf(file->valdata, sizeof(file->valdata), "stale");
		file->vallen = strlen(file->valdata);

		CHECK(file->fill_data(file) == 0,
		      "%s reported a failure rather than an empty file",
		      file->filename);
		CHECK_EQ(file->vallen, 0);
		CHECK(file->valdata[0] == '\0',
		      "%s kept its previous content", file->filename);

		/*
		 * And the same through getattr(), which is what a stat() of the
		 * file runs - except for the ones that report a fixed size.
		 */
		if (file->getattr_size)
			continue;

		snprintf(path, sizeof(path), "/%s", file->filename);
		memset(&sb, 0xff, sizeof(sb));
		CHECK_EQ(esdm_proc_getattr(path, &sb, NULL), 0);
		CHECK_EQ(sb.st_size, 0);
		CHECK_EQ(sb.st_mode & 07777, file->perm);
	}
}

/*
 * The boot_id is read once at startup and served from there. It is the one file
 * whose content does not come from the ESDM, so it is also the one that still
 * has an answer when no server does.
 */
static void test_pre_init(void)
{
	struct esdm_proc_file *file = &esdm_proc_files[0];
	struct stat sb;

	CHECK_STR_EQ(file->filename, "boot_id");

	CHECK_EQ(esdm_proc_pre_init(), 0);

	/*
	 * Either the kernel's boot_id was readable or a fresh UUID was
	 * generated for it - and without a server the latter cannot be, so an
	 * empty file is a legitimate outcome as well. What must hold is that
	 * whatever is there is served as the file's size.
	 */
	CHECK(file->vallen == 0 || file->vallen == ESDM_PROC_UUID_LEN - 1,
	      "the boot_id has an unexpected length %zu", file->vallen);

	memset(&sb, 0xff, sizeof(sb));
	CHECK_EQ(esdm_proc_getattr("/boot_id", &sb, NULL), 0);
	CHECK_EQ(sb.st_size, (off_t)file->vallen);
}

/*
 * The parts that change the process' credentials, in a child of their own.
 *
 * Setting one of the writable files raises to root for the duration of the RPC
 * and drops to "nobody" afterwards, and esdm_proc_init() drops for good. Run as
 * root - which is how the coverage run executes the suite - that would leave
 * everything after it running as nobody, so it happens where it cannot: in a
 * process that exits right after.
 */
static int privileged_transitions(void)
{
	struct esdm_proc_file *thresh = file_by_name("write_wakeup_threshold");
	struct esdm_proc_file *secs = file_by_name("urandom_min_reseed_secs");
	struct fuse_conn_info conn;
	struct fuse_config cfg;

	if (!thresh || !secs)
		return 1;

	/*
	 * A value that passes validation reaches the ESDM, which is not there -
	 * so the answer is a failure, and the interest here is the raise and
	 * drop around it. Both callers are exercised: one seen as root, which
	 * raises, and one seen as an ordinary user, which must not.
	 */
	test_ctx_uid = 0;
	CHECK(esdm_proc_set_write_wakeup_thresh(thresh, "1024", 4) != 0,
	      "the write wakeup threshold was set without a server");

	test_ctx_uid = 1000;
	CHECK(esdm_proc_set_min_reseed_secs(secs, "60", 2) != 0,
	      "the reseed interval was set without a server");

	/* The one-time drop the FUSE session does when it comes up */
	memset(&conn, 0, sizeof(conn));
	memset(&cfg, 0, sizeof(cfg));
	cfg.kernel_cache = 1;
	CHECK(esdm_proc_init(&conn, &cfg) == NULL,
	      "the init handler returned private data it does not have");
	CHECK_EQ(cfg.kernel_cache, 0);

	return common_test_result("proc_files privileged");
}

/*
 * The coverage counters are normally written by the exit handlers, and those
 * are exactly what the child must not run: it has dropped to "nobody" by then,
 * and LeakSanitizer - which a coverage build carries - cannot stop the threads
 * of a process that changed its credentials, so it aborts the child instead of
 * letting it exit. Write the counters explicitly and leave without running
 * anything else. __gcov_dump is only there in a coverage build, hence the weak
 * declaration.
 */
__attribute__((weak)) void __gcov_dump(void);

static void child_exit(int status)
{
	if (__gcov_dump)
		__gcov_dump();

	_exit(status);
}

static void test_privileged_transitions(void)
{
	pid_t pid = fork();
	int status;

	if (pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return;
	}

	if (!pid)
		child_exit(privileged_transitions());

	CHECK(waitpid(pid, &status, 0) == pid, "waitpid() failed: %s",
	      strerror(errno));
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status),
	      "the privileged transitions failed (status %d)", status);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_uuid_bin2hex();
	test_getattr();
	test_readdir();
	test_open_permissions();
	test_read();
	test_write_dispatch();
	test_write_values_rejected();
	test_fill_data_without_server();
	test_pre_init();
	test_privileged_transitions();

	/* The usage, which is all main() prints before it hands over to FUSE */
	show_help("esdm-proc");

	return common_test_result("proc_files");
}
