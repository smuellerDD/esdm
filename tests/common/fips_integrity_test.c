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
 * Tests for common/fips_integrity.c - the power-on self test that verifies the
 * HMAC of the running binary against the .<name>.hmac file next to it.
 *
 * The point of this code is to say no, so the tests concentrate on the failure
 * paths: a modified target, an HMAC file of the wrong length, an empty one, and
 * a target that cannot be read. Each has to be distinguishable - a self test
 * reporting success for a file it never hashed is worse than none.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common_test.h"
#include "fips_integrity.h"

/* SHA-256 HMAC: 32 bytes, written as 64 hex characters plus a newline */
#define EXPECTED_HMAC_FILE_LEN (64 + 1)

static const char payload[] = "ESDM FIPS integrity test payload\n";

static char tmpdir[512];
static char target[640];
static char hmacfile[768];

static bool write_file(const char *path, const void *data, size_t len)
{
	FILE *f = fopen(path, "w");

	if (!f) {
		CHECK(0, "cannot create %s: %s", path, strerror(errno));
		return false;
	}

	if (len && fwrite(data, 1, len, f) != len) {
		CHECK(0, "cannot write %s", path);
		fclose(f);
		return false;
	}

	fclose(f);
	return true;
}

/* Read a whole file; returns the length, or -1 when it cannot be read. */
static ssize_t read_file(const char *path, char *buf, size_t buflen)
{
	FILE *f = fopen(path, "r");
	size_t rd;

	if (!f)
		return -1;

	rd = fread(buf, 1, buflen - 1, f);
	buf[rd] = '\0';
	fclose(f);

	return (ssize_t)rd;
}

static bool file_exists(const char *path)
{
	struct stat sb;

	return stat(path, &sb) == 0;
}

/* Build "<dir>/.<base>.hmac" the way fips_integrity.c derives it */
static void hmac_name_of(const char *path, char *out, size_t outlen)
{
	const char *slash = strrchr(path, '/');

	if (slash)
		snprintf(out, outlen, "%.*s.%s.hmac",
			 (int)(slash - path + 1), path, slash + 1);
	else
		snprintf(out, outlen, ".%s.hmac", path);
}

static void setup_paths(void)
{
	const char *tmp = getenv("TMPDIR");

	snprintf(tmpdir, sizeof(tmpdir), "%s", tmp ? tmp : "/tmp");
	snprintf(target, sizeof(target), "%s/esdm_fips_target_%u.bin", tmpdir,
		 (unsigned int)getpid());
	hmac_name_of(target, hmacfile, sizeof(hmacfile));
}

static void test_create_checkfile(void)
{
	char content[256];
	ssize_t len;
	size_t i;

	if (!write_file(target, payload, sizeof(payload) - 1))
		return;
	unlink(hmacfile);

	CHECK_EQ(fips_create_checkfile(hmacfile, target), 0);

	len = read_file(hmacfile, content, sizeof(content));
	CHECK_EQ(len, EXPECTED_HMAC_FILE_LEN);

	if (len == EXPECTED_HMAC_FILE_LEN) {
		CHECK_EQ(content[64], '\n');
		for (i = 0; i < 64; i++) {
			if (!strchr("0123456789abcdefABCDEF", content[i])) {
				CHECK(0, "non-hex character at offset %zu of "
					 "the HMAC file", i);
				break;
			}
		}
	}

	/*
	 * An existing HMAC file is never overwritten: silently replacing it
	 * would turn a detected modification into a fresh, matching digest.
	 */
	CHECK_EQ(fips_create_checkfile(hmacfile, target), -EEXIST);

	/* The digest is deterministic for the same content */
	{
		char again[256];
		char other[800];

		snprintf(other, sizeof(other), "%s.second", hmacfile);
		unlink(other);
		CHECK_EQ(fips_create_checkfile(other, target), 0);
		CHECK_EQ(read_file(other, again, sizeof(again)),
			 EXPECTED_HMAC_FILE_LEN);
		CHECK_STR_EQ(again, content);
		unlink(other);
	}
}

static void test_create_checkfile_stdout(void)
{
	char expected[256], produced[256];
	char out[800];
	int saved_stdout;
	int fd;

	if (read_file(hmacfile, expected, sizeof(expected)) < 0) {
		CHECK(0, "the HMAC file of the previous test is missing");
		return;
	}

	snprintf(out, sizeof(out), "%s.stdout", hmacfile);
	unlink(out);

	/*
	 * "-" writes the digest to stdout. Capture it so the test output stays
	 * readable and the bytes can be compared against the file variant.
	 */
	fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (saved_stdout < 0 || fd < 0) {
		CHECK(0, "cannot redirect stdout: %s", strerror(errno));
		if (saved_stdout >= 0)
			close(saved_stdout);
		if (fd >= 0)
			close(fd);
		return;
	}
	dup2(fd, STDOUT_FILENO);
	close(fd);

	CHECK_EQ(fips_create_checkfile("-", target), 0);

	fflush(stdout);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdout);

	CHECK_EQ(read_file(out, produced, sizeof(produced)),
		 EXPECTED_HMAC_FILE_LEN);
	CHECK_STR_EQ(produced, expected);
	unlink(out);
}

static void test_post_integrity(void)
{
	/* The HMAC file written above is accepted */
	CHECK_EQ(fips_post_integrity(target), 0);

	/*
	 * Without one there is nothing to verify against, which is a failed
	 * integrity test. The reference value is established when the module is
	 * built and installed; computing it here would attest a modified file
	 * just as happily as an intact one.
	 */
	unlink(hmacfile);
	CHECK_EQ(fips_post_integrity(target), -ENOENT);
	CHECK(!file_exists(hmacfile),
	      "the self test wrote the reference value it was missing");

	/* Restore it for the tests that follow */
	CHECK_EQ(fips_create_checkfile(hmacfile, target), 0);
	CHECK_EQ(fips_post_integrity(target), 0);
}

static void test_post_integrity_relative_path(void)
{
	char cwd[512];
	const char *base = strrchr(target, '/');

	if (!getcwd(cwd, sizeof(cwd))) {
		CHECK(0, "getcwd() failed: %s", strerror(errno));
		return;
	}

	if (chdir(tmpdir) < 0) {
		CHECK(0, "cannot change to %s: %s", tmpdir, strerror(errno));
		return;
	}

	/* A bare file name resolves the HMAC file in the current directory */
	CHECK_EQ(fips_post_integrity(base + 1), 0);

	if (chdir(cwd) < 0)
		CHECK(0, "cannot change back to %s: %s", cwd, strerror(errno));
}

static void test_modified_target(void)
{
	char modified[sizeof(payload) + 8];

	/* One changed byte has to be caught */
	memcpy(modified, payload, sizeof(payload) - 1);
	modified[0] = 'e';
	if (!write_file(target, modified, sizeof(payload) - 1))
		return;
	CHECK_EQ(fips_post_integrity(target), -EBADMSG);

	/* A changed length as well */
	memcpy(modified, payload, sizeof(payload) - 1);
	memcpy(modified + sizeof(payload) - 1, "tail", 4);
	if (!write_file(target, modified, sizeof(payload) - 1 + 4))
		return;
	CHECK_EQ(fips_post_integrity(target), -EBADMSG);

	/* Restore the original content so the digest matches again */
	if (!write_file(target, payload, sizeof(payload) - 1))
		return;
	CHECK_EQ(fips_post_integrity(target), 0);
}

static void test_malformed_checkfile(void)
{
	/* A digest of the wrong length is a violation, not a mismatch */
	if (!write_file(hmacfile, "00112233445566778899aabbccddeeff\n", 33))
		return;
	CHECK_EQ(fips_post_integrity(target), -EINVAL);

	/* An empty HMAC file means nothing was verified at all */
	if (!write_file(hmacfile, "", 0))
		return;
	CHECK_EQ(fips_post_integrity(target), -EBADF);

	/* A file holding only a line terminator is no digest either */
	if (!write_file(hmacfile, "\n", 1))
		return;
	CHECK_EQ(fips_post_integrity(target), -EINVAL);

	unlink(hmacfile);
}

static void test_unreadable_target(void)
{
	char missing[640];
	char missing_hmac[768];

	snprintf(missing, sizeof(missing), "%s/esdm_fips_absent_%u.bin", tmpdir,
		 (unsigned int)getpid());
	hmac_name_of(missing, missing_hmac, sizeof(missing_hmac));
	unlink(missing);
	unlink(missing_hmac);

	/*
	 * A target that was never attested has no reference value next to it,
	 * which is what the self test reports - it does not get as far as
	 * finding out that the target cannot be opened either.
	 */
	CHECK_EQ(fips_post_integrity(missing), -ENOENT);
	CHECK(!file_exists(missing_hmac),
	      "the self test created a reference value for a missing target");

	/*
	 * Creating one is the operation that opens the target, and it leaves
	 * the empty HMAC file it started to write behind - so it has to go
	 * before the next call, which would otherwise stop at the refusal to
	 * overwrite an existing HMAC file.
	 */
	CHECK_EQ(fips_create_checkfile(missing_hmac, missing), -EIO);
	unlink(missing_hmac);

	/* Neither can something that is not a regular file */
	CHECK_EQ(fips_create_checkfile(missing_hmac, tmpdir), -EINVAL);
	unlink(missing_hmac);

	/* An HMAC file that cannot be created is reported as such */
	CHECK_EQ(fips_create_checkfile("/nonexistent-directory/x.hmac", target),
		 -EEXIST);
}

static void test_empty_target(void)
{
	char empty[640];
	char empty_hmac[768];

	snprintf(empty, sizeof(empty), "%s/esdm_fips_empty_%u.bin", tmpdir,
		 (unsigned int)getpid());
	hmac_name_of(empty, empty_hmac, sizeof(empty_hmac));
	unlink(empty_hmac);

	/* A zero-sized target is hashed as the empty message, not refused */
	if (!write_file(empty, "", 0))
		return;

	CHECK_EQ(fips_create_checkfile(empty_hmac, empty), 0);
	CHECK_EQ(fips_post_integrity(empty), 0);

	unlink(empty_hmac);
	unlink(empty);
}

static void test_overlong_pathname(void)
{
	char *huge = malloc(FILENAME_MAX + 64);

	if (!huge) {
		CHECK(0, "out of memory");
		return;
	}

	/* A name that cannot have an HMAC file is rejected up front */
	memset(huge, 'a', FILENAME_MAX + 62);
	huge[0] = '/';
	huge[FILENAME_MAX + 62] = '\0';
	CHECK_EQ(fips_post_integrity(huge), -ENOMEM);

	free(huge);
}

static void test_post_integrity_self(void)
{
	char self[4096];
	char self_hmac[4200];
	ssize_t len;
	int ret;

	/* Without a path the self test attests the running binary */
	len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (len <= 0) {
		CHECK(0, "cannot read /proc/self/exe: %s", strerror(errno));
		return;
	}
	self[len] = '\0';

	hmac_name_of(self, self_hmac, sizeof(self_hmac));
	unlink(self_hmac);

	/* An unattested binary does not pass */
	CHECK_EQ(fips_post_integrity(NULL), -ENOENT);

	/*
	 * Attest it the way an installation would and the self test accepts it.
	 */
	ret = fips_create_checkfile(self_hmac, self);
	if (ret) {
		CHECK_EQ(ret, -EEXIST);
		return;
	}

	CHECK_EQ(fips_post_integrity(NULL), 0);
	unlink(self_hmac);
}

static void test_post_integrity_obj(void)
{
	char self[4096];
	char self_hmac[4200];
	ssize_t len;

	/* There is no object to attest without an address in one */
	CHECK_EQ(fips_post_integrity_obj(NULL), -EINVAL);

	len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (len <= 0) {
		CHECK(0, "cannot read /proc/self/exe: %s", strerror(errno));
		return;
	}
	self[len] = '\0';
	hmac_name_of(self, self_hmac, sizeof(self_hmac));
	unlink(self_hmac);

	/*
	 * This test links the integrity code statically, so an address inside
	 * it resolves to the executable - which the caller attests through
	 * fips_post_integrity(NULL).
	 */
	CHECK_EQ(fips_post_integrity_obj(payload), 0);
	CHECK(!file_exists(self_hmac),
	      "attesting the running object created an HMAC file");
}

struct loaded_name {
	char *buf;
	size_t len;
};

static int first_loaded_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct loaded_name *name = data;
	const char *base;

	(void)size;

	/* The main executable, and the vdso, which has no file behind it */
	if (!info->dlpi_name || !strchr(info->dlpi_name, '/'))
		return 0;

	base = strrchr(info->dlpi_name, '/') + 1;
	snprintf(name->buf, name->len, "%s", base);

	return 1;
}

/* File name of one shared object loaded into this process, empty if none is */
static void first_loaded_object(char *out, size_t outlen)
{
	struct loaded_name name = { .buf = out, .len = outlen };

	out[0] = '\0';
	dl_iterate_phdr(first_loaded_cb, &name);
}

static void test_post_integrity_loaded(void)
{
	char base[256];
	int ret;

	/* Without a name there is nothing to look for */
	CHECK_EQ(fips_post_integrity_loaded(NULL), -EINVAL);
	CHECK_EQ(fips_post_integrity_loaded(""), -EINVAL);

	/* An object that is not loaded is not attested, and not an error */
	CHECK_EQ(fips_post_integrity_loaded("libnothing-esdm-test.so"), 0);

	first_loaded_object(base, sizeof(base));
	if (!base[0])
		return; /* a fully static build has none to look at */

	/*
	 * One that is loaded is picked up and attested. The libraries of the
	 * system have no reference value next to them, so the attempt says so -
	 * which is what tells "found it and could not attest it" apart from
	 * "found nothing", the answer a broken lookup would give.
	 */
	ret = fips_post_integrity_loaded(base);
	CHECK(ret == -ENOENT || ret > 0,
	      "the loaded object %s was not picked up (%d)", base, ret);

	/* The same object is found through a prefix of its name */
	base[strlen(base) / 2] = '\0';
	if (base[0]) {
		ret = fips_post_integrity_loaded(base);
		CHECK(ret == -ENOENT || ret > 0,
		      "the prefix %s did not match the object it names (%d)",
		      base, ret);
	}
}

static void cleanup(void)
{
	unlink(hmacfile);
	unlink(target);
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	setup_paths();

	test_create_checkfile();
	test_create_checkfile_stdout();
	test_post_integrity();
	test_post_integrity_relative_path();
	test_modified_target();
	test_malformed_checkfile();
	test_unreadable_target();
	test_empty_target();
	test_overlong_pathname();
	test_post_integrity_self();
	test_post_integrity_obj();
	test_post_integrity_loaded();

	ret = common_test_result("fips_integrity");
	cleanup();
	return ret;
}
