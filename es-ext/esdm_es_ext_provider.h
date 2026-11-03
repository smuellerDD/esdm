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
 * The provider program behind esdm_es_ext_provider_main(), with options of a
 * program of its own next to the common ones - as esdm-es-pkcs11 has. Not API:
 * not installed nor exported (version.lds), reached in the static library.
 */

#ifndef _ESDM_ES_EXT_PROVIDER_H
#define _ESDM_ES_EXT_PROVIDER_H

#include <getopt.h>
#include <stdio.h>

#include "esdm_es_ext.h"

/*
 * A provider program, every member optional
 *
 * @name: For --version and the usage, else the name it was started under
 * @version: For --version, else the one of the library
 * @title: The first line of the usage
 * @socket_path: The default of --socket, which is required without
 * @short_options: Short options of the program, without a leading colon -
 *		   the common ones are s, m, u, v and h
 * @options: Long options of the program, ended by zeros, their codes below
 *	     0x1000
 * @option: Take option @opt with @arg: 0, or -1 having told why not
 * @usage: Print the options of the program to @out
 * @setup: Called before the source is set up: 0, or -1 having told why not
 * @secret: What the command line may hold by mistake, completing "as it may
 *	    hold ...": a wrong command line is then told without repeating any
 *	    of it, as it goes to the journal
 */
struct esdm_es_ext_provider_cli {
	const char *name;
	const char *version;
	const char *title;
	const char *socket_path;
	const char *short_options;
	const struct option *options;
	int (*option)(int opt, const char *arg);
	void (*usage)(FILE *out);
	int (*setup)(void);
	const char *secret;
};

/* Run the provider program @cli serving @plugin: its exit status */
int esdm_es_ext_provider_cli_main(const struct esdm_es_ext_provider_cli *cli,
				  const struct esdm_es_ext_plugin *plugin,
				  int argc, char *argv[]);

#endif /* _ESDM_ES_EXT_PROVIDER_H */
