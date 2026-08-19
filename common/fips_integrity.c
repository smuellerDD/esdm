/*
 * Copyright (C) 2018 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <dlfcn.h>
#include <link.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include "binhexbin.h"
#include "fips_integrity.h"
#include "esdm_hmac.h"
#include "esdm_sha256.h"

static const char fipscheck_hmackey[] = "orboDeJITITejsirpADONivirpUkvarP";
#define FIPS_INTEGRITY_LOGGER_PREFIX "FIPS Integrity POST: "

/*
 * GCC v8.1.0 introduced -Wstringop-truncation but it is not smart enough to
 * find that cursor string will be NULL-terminated after all paste() calls and
 * warns with:
 * error: 'strncpy' destination unchanged after copying no bytes [-Werror=stringop-truncation]
 * error: 'strncpy' output truncated before terminating nul copying 5 bytes from a string of the same length [-Werror=stringop-truncation]
 */
#pragma GCC diagnostic push
#ifndef __clang__
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
static char *paste(char *dst, const char *src, size_t size)
{
	strncpy(dst, src, size);
	return dst + size;
}

/*
 * Convert a given file name into its respective HMAC file name
 *
 * return: NULL when malloc failed, a pointer that the caller must free
 * otherwise.
 */
#define CHECK_PREFIX "."
#define CHECK_SUFFIX "hmac"
static char *get_hmac_file(const char *filename)
{
	size_t i, filelen, pathlen, namelen, basenamestart = 0;
	size_t prefixlen = strlen(CHECK_PREFIX);
	size_t suffixlen = strlen(CHECK_SUFFIX);
	char *cursor, *checkfile = NULL;

	filelen = strlen(filename);
	if (filelen > FILENAME_MAX) {
		fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX "File too long\n");
		return NULL;
	}
	for (i = 0; i < filelen; i++) {
		if (!strncmp(filename + i, "/", 1))
			basenamestart = i + 1;
	}

	namelen = filelen - basenamestart;
	pathlen = basenamestart;

	checkfile = malloc(pathlen + namelen + prefixlen + 1 /* "." */ +
			   suffixlen + 1 /* null character */);
	if (!checkfile)
		return NULL;

	cursor = checkfile;
	if (pathlen > 0)
		cursor = paste(cursor, filename, pathlen);
	cursor = paste(cursor, CHECK_PREFIX, prefixlen);
	cursor = paste(cursor, filename + basenamestart, namelen);
	cursor = paste(cursor, "." CHECK_SUFFIX, 1 + suffixlen);
	strncpy(cursor, "\0", 1);
	return checkfile;
}
#pragma GCC diagnostic pop /* -Wstringop-truncation */

static int check_filetype(int fd, struct stat *sb)
{
	int ret = fstat(fd, sb);

	if (ret)
		return -errno;

	/* Do not return an error in case we cannot validate the data. */
	if ((sb->st_mode & S_IFMT) != S_IFREG &&
	    (sb->st_mode & S_IFMT) != S_IFLNK) {
		return -EINVAL;
	}

	return 0;
}

static int mmap_file(const char *filename, uint8_t **memory, size_t *size)
{
	int fd = -1;
	int ret = 0;
	struct stat sb;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr,
			FIPS_INTEGRITY_LOGGER_PREFIX
			"Cannot open file %s: %s\n",
			filename, strerror(errno));
		return -EIO;
	}

	ret = check_filetype(fd, &sb);
	if (ret)
		goto out;

	*memory = NULL;
	*size = (size_t)sb.st_size;

	if (sb.st_size) {
		*memory = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED,
			       fd, 0);
		if (*memory == MAP_FAILED) {
			*memory = NULL;
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Use of mmap failed\n");
			ret = -ENOMEM;
			goto out;
		}
	}
out:
	close(fd);
	return ret;
}

static int process_checkfile(const char *checkfile, const char *targetfile)
{
	ESDM_HMAC_CTX_ON_STACK(hmac_ctx, esdm_sha256);
	FILE *file = NULL;
	int ret = 0, checked_any = 0;
	size_t size = 0;
	uint8_t *memblock = NULL;

	/*
	 * A file can have up to 4096 characters, so a complete line has at most
	 * 4096 bytes (file name) + 128 bytes (SHA512 hex value) + 2 spaces +
	 * one byte for the CR.
	 */
	char buf[(4096 + 128 + 2 + 1)];

	file = strcmp(checkfile, "-") ? fopen(checkfile, "r") : stdin;
	if (!file) {
		/*
		 * The reference value is established by whoever builds and
		 * installs the module, and the integrity test verifies against
		 * it.
		 */
		fprintf(stderr,
			FIPS_INTEGRITY_LOGGER_PREFIX
			"No reference value for %s: cannot open %s (%s) - create it at installation time with: esdm-tool --fips-targetfile %s --fips-checkfile %s\n",
			targetfile, checkfile, strerror(errno), targetfile,
			checkfile);
		ret = -ENOENT;
		goto out;
	}

	ret = mmap_file(targetfile, &memblock, &size);
	if (ret)
		goto out;

	while (fgets(buf, sizeof(buf), file)) {
		char *hexhash = NULL; // parsed hex value of hash
		uint8_t *binhash = NULL;
		size_t binhashlen;
		size_t hexhashlen = 0; // length of hash hex value
		size_t linelen = strlen(buf);
		size_t i;
		unsigned char calculated[ESDM_SHA_MAX_SIZE_DIGEST];

		if (linelen == 0)
			break;

		/* remove trailing CR and reduce buffer length */
		for (i = linelen - 1; i > 0; i--) {
			if (!isprint(buf[i])) {
				buf[i] = '\0';
				linelen--;
			} else
				break;
		}

		hexhash = buf;
		hexhashlen = linelen;

		if (!hexhash || !hexhashlen) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Invalid checkfile format\n");
			ret = -EINVAL;
			goto out;
		}

		ret = hex2bin_alloc(hexhash, hexhashlen, &binhash, &binhashlen);
		if (ret < 0)
			goto out;

		esdm_hmac_init(hmac_ctx, (uint8_t *)fipscheck_hmackey,
			       sizeof(fipscheck_hmackey) - 1);
		esdm_hmac_update(hmac_ctx, memblock, size);
		esdm_hmac_final(hmac_ctx, calculated);

		if (esdm_hmac_macsize(hmac_ctx) != binhashlen) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Calculated MAC length has unexpected length - integrity violation\n");
			free(binhash);
			ret = -EINVAL;
			goto out;
		}

		if (memcmp(calculated, binhash, binhashlen)) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Message mismatch - integrity violation\n");
			free(binhash);
			ret = -EBADMSG;
			goto out;
		}

		free(binhash);

		checked_any = 1;
	}

	if (!checked_any)
		ret = -EBADF;

out:
	esdm_hmac_zero(hmac_ctx);
	if (file && file != stdin)
		fclose(file);
	if (memblock)
		munmap(memblock, size);

	return ret;
}

static FILE *fopen_if_not_exists(const char *filename, const char *mode)
{
	if (mode[0] != 'w' && mode[0] != 'a') {
		errno = EINVAL; // only creation modes make sense
		return NULL;
	}

	int flags = O_CREAT | O_EXCL | O_WRONLY;
	int fd = open(filename, flags, 0644);
	if (fd == -1) {
		// file exists or other error
		return NULL;
	}

	// Now convert to FILE*
	FILE *fp = fdopen(fd, mode);
	if (!fp) {
		close(fd);
		return NULL;
	}

	return fp;
}

int fips_create_checkfile(const char *checkfile, const char *targetfile)
{
	ESDM_HMAC_CTX_ON_STACK(hmac_ctx, esdm_sha256);
	uint8_t *memblock = NULL;
	size_t hexhashlen = 0;
	char *hexhash = NULL;
	FILE *file = NULL;
	int ret = 0;
	size_t size = 0;
	uint8_t calculated[ESDM_SHA_MAX_SIZE_DIGEST];
	size_t written;

	file = strcmp(checkfile, "-") ? fopen_if_not_exists(checkfile, "w") :
					stdout;
	if (!file) {
		ret = -EEXIST;
		goto out;
	}

	ret = mmap_file(targetfile, &memblock, &size);
	if (ret)
		goto out;

	esdm_hmac_init(hmac_ctx, (uint8_t *)fipscheck_hmackey,
		       sizeof(fipscheck_hmackey) - 1);
	esdm_hmac_update(hmac_ctx, memblock, size);
	esdm_hmac_final(hmac_ctx, calculated);

	ret = bin2hex_alloc(calculated, esdm_hmac_macsize(hmac_ctx), &hexhash,
			    &hexhashlen);
	esdm_hmac_zero(hmac_ctx);
	if (ret)
		goto out;

	written = fwrite(hexhash, 1, hexhashlen, file);
	free(hexhash);
	fwrite("\n", 1, 1, file);

	if (written != hexhashlen) {
		fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
			"Failed to write hash to HMAC control file\n");
		ret = -EFAULT;
		goto out;
	}

out:
	esdm_hmac_zero(hmac_ctx);
	if (file && file != stdout)
		fclose(file);
	if (memblock)
		munmap(memblock, size);

	return ret;
}

int fips_post_integrity(const char *pathname)
{
	char *checkfile = NULL;
	int ret = -EINVAL;
#define BUFSIZE 4096
	char selfname[BUFSIZE];
	const char *selfname_p;
	ssize_t selfnamesize = 0;

	if (pathname) {
		selfname_p = pathname;
	} else {
		/* Integrity check of our application. */
		memset(selfname, 0, sizeof(selfname));

		selfnamesize =
			readlink("/proc/self/exe", selfname, BUFSIZE - 1);

		if (selfnamesize >= BUFSIZE || selfnamesize < 0) {
			fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
				"Cannot obtain my filename\n");
			ret = -EFAULT;
			goto out;
		}

		selfname_p = selfname;
	}

	checkfile = get_hmac_file(selfname_p);
	if (!checkfile) {
		ret = -ENOMEM;
		goto out;
	}

	ret = process_checkfile(checkfile, selfname_p);

out:
	if (checkfile)
		free(checkfile);
	return ret;
}

/* Are the two paths the same file? */
static bool fips_same_file(const char *a, const char *b)
{
	struct stat sa, sb;

	if (stat(a, &sa) == -1 || stat(b, &sb) == -1)
		return false;

	return (sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino);
}

int fips_post_integrity_obj(const void *addr)
{
	char selfname[BUFSIZE];
	ssize_t selfnamesize;
	Dl_info info;

	if (!addr)
		return -EINVAL;

	/* Which file the code at @addr was loaded from. */
	memset(&info, 0, sizeof(info));
	if (!dladdr(addr, &info) || !info.dli_fname || !info.dli_fname[0]) {
		fprintf(stderr, FIPS_INTEGRITY_LOGGER_PREFIX
			"Cannot determine the file the module was loaded from\n");
		return -EFAULT;
	}

	/*
	 * A statically linked module resolves to the executable, which the
	 * caller attests with fips_post_integrity(NULL) - do not ask for a
	 * second reference value for the same file.
	 */
	memset(selfname, 0, sizeof(selfname));
	selfnamesize = readlink("/proc/self/exe", selfname, BUFSIZE - 1);
	if (selfnamesize > 0 && selfnamesize < BUFSIZE &&
	    fips_same_file(selfname, info.dli_fname))
		return 0;

	return fips_post_integrity(info.dli_fname);
}

struct fips_loaded_ctx {
	const char *soname;
	size_t sonamelen;
	unsigned int attested;
	int ret;
};

static int fips_loaded_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct fips_loaded_ctx *ctx = data;
	const char *base;

	(void)size;

	/* The main executable, which the caller attests on its own */
	if (!info->dlpi_name || !info->dlpi_name[0])
		return 0;

	base = strrchr(info->dlpi_name, '/');
	base = base ? base + 1 : info->dlpi_name;

	/*
	 * A prefix match on the file name, so that the version behind the
	 * SONAME - libjitterentropy.so.3, libcrypto.so.3 - does not have to be
	 * spelled out by the caller.
	 */
	if (strncmp(base, ctx->soname, ctx->sonamelen))
		return 0;

	ctx->ret = fips_post_integrity(info->dlpi_name);
	if (ctx->ret)
		return 1; /* stop the walk on the first failure */

	ctx->attested++;

	return 0;
}

int fips_post_integrity_loaded(const char *soname)
{
	struct fips_loaded_ctx ctx;

	if (!soname || !soname[0])
		return -EINVAL;

	ctx.soname = soname;
	ctx.sonamelen = strlen(soname);
	ctx.attested = 0;
	ctx.ret = 0;

	dl_iterate_phdr(fips_loaded_cb, &ctx);

	return ctx.ret ? ctx.ret : (int)ctx.attested;
}
