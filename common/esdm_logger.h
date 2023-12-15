/*
* Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_LOGGER_H
#define ESDM_LOGGER_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

enum esdm_logger_verbosity {
	LOGGER_NONE,
	LOGGER_STATUS,
	LOGGER_ERR,
	LOGGER_WARN,
	LOGGER_VERBOSE,
	LOGGER_DEBUG,
	LOGGER_DEBUG2,

	LOGGER_MAX_LEVEL /* This must be last entry */
};

enum esdm_logger_class {
	LOGGER_C_ANY,
	LOGGER_C_MD,
	LOGGER_C_DRNG,
	LOGGER_C_THREADING,
	LOGGER_C_ES,
	LOGGER_C_CUSE,
	LOGGER_C_RPC,
	LOGGER_C_SERVER,

	LOGGER_C_LAST /* This must be last entry */
};

/* Helper that is not intended to be called directly */
void _esdm_logger(const enum esdm_logger_verbosity severity,
		  const enum esdm_logger_class class_, const char *file,
		  const char *func, const uint32_t line, const char *fmt, ...)
	__attribute__((format(printf, 6, 7)));
void _esdm_logger_binary(const enum esdm_logger_verbosity severity,
			 const enum esdm_logger_class class_,
			 const unsigned char *bin, const uint32_t binlen,
			 const char *str, const char *file, const char *func,
			 const uint32_t line);

/**
 * logger - log string with given severity
 * @param severity maximum severity level that causes the log entry to be logged
 * @param class logging class
 * @param fmt format string as defined by fprintf(3)
 */
#pragma GCC diagnostic push
#ifdef __clang__
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma clang diagnostic ignored "-Wvariadic-macros"
#else
#pragma GCC diagnostic ignored "-Wvariadic-macros"
#endif
#define esdm_logger(severity, class_, fmt...)                                  \
	do {                                                                   \
		_Pragma("GCC diagnostic push")                                 \
			_Pragma("GCC diagnostic ignored \"-Wpedantic\"")       \
				_esdm_logger(severity, class_, __FILE__,       \
					     __FUNCTION__, __LINE__, ##fmt);   \
		_Pragma("GCC diagnostic pop")                                  \
	} while (0);
#pragma GCC diagnostic pop

/**
 * logger - log status if LOGGER_WARN or LOGGER_ERR is found
 * @param class logging class
 * @param fmt format string as defined by fprintf(3)
 */
#pragma GCC diagnostic push
#ifdef __clang__
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma clang diagnostic ignored "-Wvariadic-macros"
#else
#pragma GCC diagnostic ignored "-Wvariadic-macros"
#endif
#define esdm_logger_status(class_, fmt...)                                     \
	esdm_logger(LOGGER_STATUS, class_, ##fmt)
#pragma GCC diagnostic pop

/**
 * logger_binary - log binary string as hex
 * @param severity maximum severity level that causes the log entry to be logged
 * @param class logging class
 * @param bin binary string
 * @param binlen length of binary string
 * @param str string that is prepended to hex-converted binary string
 */
#define esdm_logger_binary(severity, class_, bin, binlen, str)                 \
	do {                                                                   \
		_Pragma("GCC diagnostic push")                                 \
			_Pragma("GCC diagnostic ignored \"-Wpedantic\"")       \
				_esdm_logger_binary(severity, class_, bin,     \
						    binlen, str, __FILE__,     \
						    __FUNCTION__, __LINE__);   \
		_Pragma("GCC diagnostic pop")                                  \
	} while (0);

/**
 * logger - log a percentage only if LOG_NONE is given
 * @param percentage Integer indicating a percentage value
 * @param fmt format string printed during first call
 */
void esdm_logger_spinner(const unsigned int percentage, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/**
 * logger_set_verbosity - set verbosity level
 */
void esdm_logger_set_verbosity(const enum esdm_logger_verbosity level);

/**
 * logger_set_class - set logging class
 */
int esdm_logger_set_class(const enum esdm_logger_class class_);

/**
 * logger_get_class - List all logging classes to file descriptor
 */
void esdm_logger_get_class(const int fd);

/**
 * logger_get_verbosity - get verbosity level for given class
 */
enum esdm_logger_verbosity
esdm_logger_get_verbosity(const enum esdm_logger_class class_);

/**
 * logger_inc_verbosity - increase verbosity level by one
 */
void esdm_logger_inc_verbosity(void);

/**
 * Log into the given file
 *
 * Note: The status logging will always log to stderr and will be always
 *	 active if a log file is set.
 *
 * @param [in] pathname Path name of log file
 * @return 0 on success, < 0 on error
 */
int esdm_logger_set_file(const char *pathname);

/**
 * Retrieve the file stream to log to.
 */
FILE *esdm_logger_log_stream(void);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_LOGGER_H */
