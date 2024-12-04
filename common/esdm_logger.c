/* Logging support
 *
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>

#include "binhexbin.h"
#include "build_bug_on.h"
#include "constructor.h"
#include "helper.h"
#include "esdm_logger.h"
#include "term_colors.h"
#include "threading_support.h"
#include "visibility.h"

static enum esdm_logger_verbosity esdm_logger_verbosity_level = LOGGER_STATUS;
static enum esdm_logger_class esdm_logger_class_level = LOGGER_C_ANY;

struct esdm_logger_class_map {
	const enum esdm_logger_class class;
	const char *logdata;
};

static FILE *esdm_logger_stream = NULL;
static bool use_syslog = false;

static void log_syslog(int severity, const char *format, ...);

static const struct esdm_logger_class_map esdm_logger_class_mapping[] = {
	{ LOGGER_C_ANY, NULL },
	{ LOGGER_C_THREADING, "Threading support" },
	{ LOGGER_C_MD, "Message digest" },
	{ LOGGER_C_DRNG, "DRNG" },
	{ LOGGER_C_ES, "Entropy Source" },
	{ LOGGER_C_CUSE, "Linux device files" },
	{ LOGGER_C_RPC, "RPC" },
	{ LOGGER_C_SERVER, "ESDM server" },
};

static void esdm_logger_severity(enum esdm_logger_verbosity severity, char *sev,
				 const unsigned int sevlen)
{
	switch (severity) {
	case LOGGER_DEBUG2:
		snprintf(sev, sevlen, "Debug2");
		break;
	case LOGGER_DEBUG:
		snprintf(sev, sevlen, "Debug");
		break;
	case LOGGER_VERBOSE:
		snprintf(sev, sevlen, "Verbose");
		break;
	case LOGGER_WARN:
		snprintf(sev, sevlen, "Warning");
		break;
	case LOGGER_ERR:
		snprintf(sev, sevlen, "Error");
		break;
	case LOGGER_STATUS:
		snprintf(sev, sevlen, "Status");
		break;
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		snprintf(sev, sevlen, "Unknown");
	}
}

static int esdm_logger_class_idx(enum esdm_logger_class class,
				 unsigned int *idx)
{
	unsigned int i;

	*idx = 0;

	if (esdm_logger_class_level != LOGGER_C_ANY &&
	    esdm_logger_class_level != class)
		return -EOPNOTSUPP;

	for (i = 0; i < ARRAY_SIZE(esdm_logger_class_mapping); i++) {
		if (class == esdm_logger_class_mapping[i].class) {
			*idx = i;

			return 0;
		}
	}

	return -EINVAL;
}

static int esdm_logger_class(const enum esdm_logger_class class, char *s,
			     const unsigned int slen)
{
	unsigned int idx;
	int ret = esdm_logger_class_idx(class, &idx);

	if (ret)
		return ret;

	if (esdm_logger_class_mapping[idx].logdata)
		if (use_syslog) {
			snprintf(s, slen, "%s",
				 esdm_logger_class_mapping[idx].logdata);
		} else {
			snprintf(s, slen, " - %s",
				 esdm_logger_class_mapping[idx].logdata);
		}
	else
		s[0] = '\0';

	return 0;
}

static void log_syslog(int severity, const char *format, ...)
{
	va_list args;
	int log_prio = LOG_NOTICE;

	va_start(args, format);
	va_end(args);
	switch (severity) {
	case LOGGER_DEBUG2:
		log_prio = LOG_DEBUG;
		break;
	case LOGGER_DEBUG:
		log_prio = LOG_DEBUG;
		break;
	case LOGGER_VERBOSE:
		log_prio = LOG_DEBUG;
		break;
	case LOGGER_WARN:
		log_prio = LOG_WARNING;
		break;
	case LOGGER_ERR:
		log_prio = LOG_ERR;
		break;
	case LOGGER_STATUS:
		log_prio = LOG_NOTICE;
		break;
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		log_prio = LOG_INFO;
	}
	vsyslog(log_prio, format, args);
}

DSO_PUBLIC
void _esdm_logger(const enum esdm_logger_verbosity severity,
		  const enum esdm_logger_class class, const char *file,
		  const char *func, const uint32_t line, const char *fmt, ...)
{
	time_t now;
	struct tm now_detail;
	va_list args;
	int (*fprintf_color)(FILE *stream, const char *format, ...) = &fprintf;
	int ret;
	char msg[4096];
	char sev[10];
	char c[30];
	char thread_name[ESDM_THREAD_MAX_NAMELEN];

	if (!esdm_logger_stream)
		esdm_logger_stream = stderr;

	if (severity > esdm_logger_verbosity_level)
		return;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	esdm_logger_severity(severity, sev, sizeof(sev));
	ret = esdm_logger_class(class, c, sizeof(c));
	if (ret)
		return;

	now = time(NULL);
	localtime_r(&now, &now_detail);

	switch (severity) {
	case LOGGER_DEBUG2:
		fprintf_color = &fprintf_cyan;
		break;
	case LOGGER_DEBUG:
		fprintf_color = &fprintf_blue;
		break;
	case LOGGER_VERBOSE:
		fprintf_color = &fprintf_green;
		break;
	case LOGGER_WARN:
		fprintf_color = &fprintf_yellow;
		break;
	case LOGGER_ERR:
		fprintf_color = &fprintf_red;
		break;
	case LOGGER_STATUS:
		fprintf_color = &fprintf_magenta;
		break;
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		fprintf_color = &fprintf;
	}

	thread_get_name(thread_name, sizeof(thread_name));

	switch (esdm_logger_verbosity_level) {
	case LOGGER_DEBUG2:
	case LOGGER_DEBUG:
		if (use_syslog) {
			log_syslog(esdm_logger_verbosity_level,
				   "(%s) {%s} [%s:%s:%u] %s", thread_name, c,
				   file, func, line, msg);
		} else {
			fprintf_color(
				esdm_logger_stream,
				"ESDM (%.2d:%.2d:%.2d) (%s) %s%s [%s:%s:%u]: ",
				now_detail.tm_hour, now_detail.tm_min,
				now_detail.tm_sec, thread_name, sev, c, file,
				func, line);
		}
		break;
	case LOGGER_VERBOSE:
	case LOGGER_WARN:
	case LOGGER_ERR:
	case LOGGER_STATUS:
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		if (use_syslog) {
			log_syslog(esdm_logger_verbosity_level, "(%s) {%s} %s",
				   thread_name, c, msg);
		} else {
			fprintf_color(esdm_logger_stream,
				      "ESDM (%.2d:%.2d:%.2d) (%s) %s%s: ",
				      now_detail.tm_hour, now_detail.tm_min,
				      now_detail.tm_sec, thread_name, sev, c);
		}
		break;
	}

	if (!use_syslog) {
		fprintf(esdm_logger_stream, "%s", msg);
	}
}

/* this function is currently not used besides debugging and not
 * connected to syslog therefore. Change if necessary in the future.
 */
void _esdm_logger_binary(const enum esdm_logger_verbosity severity,
			 const enum esdm_logger_class class,
			 const unsigned char *bin, const uint32_t binlen,
			 const char *str, const char *file, const char *func,
			 const uint32_t line)
{
	time_t now;
	struct tm now_detail;
	int ret;
	char sev[10];
	char msg[4096];
	char c[30];

	if (severity > esdm_logger_verbosity_level)
		return;

	esdm_logger_severity(severity, sev, sizeof(sev));

	now = time(NULL);
	localtime_r(&now, &now_detail);

	ret = esdm_logger_class(class, c, sizeof(c));
	if (ret)
		return;

	switch (esdm_logger_verbosity_level) {
	case LOGGER_DEBUG2:
	case LOGGER_DEBUG:
		snprintf(msg, sizeof(msg),
			 "ESDM (%.2d:%.2d:%.2d) %s%s [%s:%s:%u]: %s",
			 now_detail.tm_hour, now_detail.tm_min,
			 now_detail.tm_sec, sev, c, file, func, line, str);
		break;
	case LOGGER_VERBOSE:
	case LOGGER_WARN:
	case LOGGER_ERR:
	case LOGGER_STATUS:
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		snprintf(msg, sizeof(msg), "ESDM (%.2d:%.2d:%.2d) %s%s: %s",
			 now_detail.tm_hour, now_detail.tm_min,
			 now_detail.tm_sec, sev, c, str);
		break;
	}

	bin2print(bin, binlen, esdm_logger_stream, msg);
}

/* this function is currently not used besides debugging/development and not
 * connected to syslog therefore. Change if necessary in the future.
 */
void esdm_logger_spinner(const unsigned int percentage, const char *fmt, ...)
{
	static unsigned int start = 0;

	if (esdm_logger_verbosity_level > LOGGER_ERR)
		return;

	if (percentage >= 100) {
		if (start < 2) {
			fprintf(stderr, "\n");
			start = 2;
		}
		return;
	}

	if (start) {
		unsigned int i;

		for (i = 0; i < 4; i++)
			fprintf(stderr, "\b");
	} else {
		va_list args;
		char msg[4096];

		va_start(args, fmt);
		vsnprintf(msg, sizeof(msg), fmt, args);
		va_end(args);

		fprintf(stderr, "ESDM progress: %s ", msg);
		start = 1;
	}

	fprintf(stderr, "%.3u%%", percentage);

	fflush(stderr);
}

static void esdm_logger_destructor(void)
{
	if (esdm_logger_stream && esdm_logger_stream != stderr)
		fclose(esdm_logger_stream);

	if (use_syslog)
		closelog();
}

ESDM_DEFINE_CONSTRUCTOR(esdm_logger_constructor);
static void esdm_logger_constructor(void)
{
	esdm_logger_stream = stderr;
	atexit(esdm_logger_destructor);
}

FILE *esdm_logger_log_stream(void)
{
	return esdm_logger_stream;
}

int esdm_logger_set_file(const char *pathname)
{
	FILE *out;

	out = fopen(pathname, "a");
	if (!out)
		return -errno;

	if (!esdm_logger_stream || esdm_logger_stream == stderr)
		esdm_logger_stream = out;
	else {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Reject to set new log file\n");
		return -EFAULT;
	}

	return 0;
}

DSO_PUBLIC
void esdm_logger_set_verbosity(const enum esdm_logger_verbosity level)
{
	esdm_logger_verbosity_level = level;
}

int esdm_logger_set_class(enum esdm_logger_class class)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(esdm_logger_class_mapping); i++) {
		if (class == esdm_logger_class_mapping[i].class) {
			esdm_logger_class_level = class;
			return 0;
		}
	}

	return -EINVAL;
}

void esdm_logger_get_class(const int fd)
{
	unsigned int i;

	/* Ensure that esdm_logger_class_mapping contains all LOGGER_C_ enums */
	BUILD_BUG_ON(ARRAY_SIZE(esdm_logger_class_mapping) != LOGGER_C_LAST);

	for (i = 0; i < ARRAY_SIZE(esdm_logger_class_mapping); i++) {
		dprintf(fd, "%u %s\n", esdm_logger_class_mapping[i].class,
			esdm_logger_class_mapping[i].logdata ?
				esdm_logger_class_mapping[i].logdata :
				"(unclassified)");
	}
}

enum esdm_logger_verbosity
esdm_logger_get_verbosity(const enum esdm_logger_class class)
{
	unsigned int idx;

	if (esdm_logger_class_idx(class, &idx))
		return LOGGER_NONE;
	return esdm_logger_verbosity_level;
}

void esdm_logger_inc_verbosity(void)
{
	if (esdm_logger_verbosity_level >= LOGGER_MAX_LEVEL - 1)
		return;

	esdm_logger_verbosity_level++;
}

DSO_PUBLIC
void esdm_logger_enable_syslog(const char *daemon_name)
{
	use_syslog = true;
	openlog(daemon_name ? daemon_name : "ESDM", LOG_NDELAY, LOG_DAEMON);
}
