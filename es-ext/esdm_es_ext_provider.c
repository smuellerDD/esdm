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

/* A provider program: its command line, and serving its source */

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "esdm_es_ext_proto.h"
#include "esdm_es_ext_provider.h"
#include "esdm_logger.h"
#include "helper.h"
#include "systemd_support.h"
#include "visibility.h"

static struct esdm_es_ext_server *provider_server;

/*
 * The signals ending the provider, blocked in every thread - those @init
 * starts too - and taken by sigwait(2) in a thread of their own: a handler
 * may be deferred for good. A thread sanitizer defers it until the thread
 * enters a function it intercepts, and the fortified poll(2) of the server,
 * __poll_chk(), is none: SIGTERM was ignored.
 */
static sigset_t provider_signal_set;

static void *provider_signals(void *arg)
{
	int sig;

	(void)arg;
	if (!sigwait(&provider_signal_set, &sig))
		esdm_es_ext_server_stop(provider_server);
	return NULL;
}

enum {
	PROVIDER_OPT_NAME = 0x1000,
	PROVIDER_OPT_ENTROPY_RATE,
	PROVIDER_OPT_VERSION,
};

static const struct option provider_options[] = {
	{ "socket", required_argument, NULL, 's' },
	{ "mode", required_argument, NULL, 'm' },
	{ "client_uid", required_argument, NULL, 'u' },
	{ "name", required_argument, NULL, PROVIDER_OPT_NAME },
	{ "entropy_rate", required_argument, NULL, PROVIDER_OPT_ENTROPY_RATE },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, PROVIDER_OPT_VERSION },
};

/* A uid, or the one of a user name; (uid_t)-1 for neither */
static uid_t provider_parse_uid(const char *arg)
{
	struct passwd *pw;
	unsigned long val;
	char *end;

	errno = 0;
	val = strtoul(arg, &end, 10);
	if (arg[0] && arg[0] != '-' && !*end && !errno &&
	    val < (unsigned long)(uid_t)-1)
		return (uid_t)val;

	pw = getpwnam(arg);
	return pw ? pw->pw_uid : (uid_t)-1;
}

/* A number in @base from 0 to @max, or -1 */
static long provider_parse_num(const char *arg, unsigned long max, int base)
{
	unsigned long val;
	char *end;

	errno = 0;
	val = strtoul(arg, &end, base);
	return errno || end == arg || *end || arg[0] == '-' || val > max ?
		       -1 :
		       (long)val;
}

static void provider_version(const struct esdm_es_ext_provider_cli *cli,
			     FILE *out, const char *name)
{
	if (cli->version)
		fprintf(out, "%s %s\n", name, cli->version);
	else
		fprintf(out, "%s (libesdm_es_ext %s)\n", name, VERSION);
}

static void provider_usage(const struct esdm_es_ext_provider_cli *cli,
			   const char *name)
{
	fprintf(stderr, "\n%s\n\n",
		cli->title ? cli->title :
			     "ESDM external entropy source provider");
	provider_version(cli, stderr, name);
	fprintf(stderr, "\nUsage:\n");
	if (cli->usage)
		cli->usage(stderr);
	fprintf(stderr,
		"\t-s --socket <PATH>\tUnix domain socket to serve on%s%s%s\n"
		"\t-m --mode <MODE>\tAccess mode of the socket (default 0666)\n"
		"\t-u --client_uid <USER>\tServe USER next to root, repeatable\n"
		"\t\t\t(default: nobody)\n"
		"\t   --entropy_rate <BITS>\tDeclare BITS per 256 bits, 0 to 256\n"
		"\t   --name <NAME>\tDeclare NAME, 1 to %u bytes of UTF-8\n"
		"\t-v --verbose\tVerbose logging, repeatable\n"
		"\t-h --help\tThis help information\n"
		"\t   --version\tPrint version\n",
		cli->socket_path ? " (default: " : "",
		cli->socket_path ? cli->socket_path : "",
		cli->socket_path ? ")" : "", ESDM_ES_EXT_NAME_MAX);
}

/*
 * Tell what is wrong with a command line that may hold a secret without
 * repeating it: getopt_long(3) would, the argument attached - "--pin=1234" -
 * into the journal of every start.
 */
static void provider_option_error(const struct esdm_es_ext_provider_cli *cli,
				  int c, const struct option *opts)
{
	const struct option *opt;

	for (opt = opts; c == ':' && opt->name; opt++) {
		if (opt->val == optopt) {
			fprintf(stderr, "--%s needs an argument\n", opt->name);
			return;
		}
	}

	fprintf(stderr,
		"Unknown, ambiguous or wrong option - not repeated, as it may hold %s\n",
		cli->secret);
}

/* The common options, followed by those of the program */
static struct option *
provider_options_merge(const struct esdm_es_ext_provider_cli *cli,
		       char **short_options)
{
	const struct option *opt;
	struct option *opts;
	size_t n = 0;

	for (opt = cli->options; opt && opt->name; opt++)
		n++;

	opts = calloc(ARRAY_SIZE(provider_options) + n + 1, sizeof(*opts));
	/* A leading colon: no message of getopt_long(), see above */
	if (!opts ||
	    asprintf(short_options, "%ss:m:u:vh%s", cli->secret ? ":" : "",
		     cli->short_options ? cli->short_options : "") < 0) {
		free(opts);
		return NULL;
	}
	memcpy(opts, provider_options, sizeof(provider_options));
	if (n)
		memcpy(opts + ARRAY_SIZE(provider_options), cli->options,
		       n * sizeof(*opts));

	return opts;
}

int esdm_es_ext_provider_cli_main(const struct esdm_es_ext_provider_cli *cli,
				  const struct esdm_es_ext_plugin *plugin,
				  int argc, char *argv[])
{
	uid_t client_uids[ESDM_ES_EXT_MAX_CLIENT_UIDS];
	const char *name = cli->name, *socket_path = cli->socket_path;
	const char *declared = NULL;
	char *short_options = NULL;
	struct option *opts;
	pthread_t signal_thread;
	uint32_t rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	unsigned int client_uids_num = 0, i, verbose = 0;
	mode_t mode = 0666;
	long val;
	int c, err, ret = 1;

	if (!name) {
		name = argc > 0 && argv[0] && argv[0][0] ?
			       argv[0] :
			       "esdm-es-ext-provider";
		if (strrchr(name, '/') && strrchr(name, '/')[1])
			name = strrchr(name, '/') + 1;
	}

	sigemptyset(&provider_signal_set);
	sigaddset(&provider_signal_set, SIGTERM);
	sigaddset(&provider_signal_set, SIGINT);
	sigaddset(&provider_signal_set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &provider_signal_set, NULL);

	opts = provider_options_merge(cli, &short_options);
	if (!opts) {
		fprintf(stderr, "Cannot take the command line: %s\n",
			strerror(ENOMEM));
		return 1;
	}

	if (cli->secret)
		opterr = 0;
	while ((c = getopt_long(argc, argv, short_options, opts, NULL)) != -1) {
		switch (c) {
		case 's':
			socket_path = optarg;
			break;
		case 'm':
			val = provider_parse_num(optarg, 0777, 8);
			if (val < 0) {
				fprintf(stderr,
					"--mode takes an octal access mode, not \"%s\"\n",
					optarg);
				goto out;
			}
			mode = (mode_t)val;
			break;
		case 'u':
			if (client_uids_num >= ESDM_ES_EXT_MAX_CLIENT_UIDS) {
				fprintf(stderr,
					"--client_uid may be given %u times at most\n",
					ESDM_ES_EXT_MAX_CLIENT_UIDS);
				goto out;
			}
			client_uids[client_uids_num] =
				provider_parse_uid(optarg);
			if (client_uids[client_uids_num++] == (uid_t)-1) {
				fprintf(stderr,
					"--client_uid takes a uid or a user name, not \"%s\"\n",
					optarg);
				goto out;
			}
			break;
		case PROVIDER_OPT_ENTROPY_RATE:
			val = provider_parse_num(
				optarg, ESDM_ES_EXT_ENTROPY_RATE_MAX, 10);
			if (val < 0) {
				fprintf(stderr,
					"--entropy_rate takes an entropy rate from 0 to %u, not \"%s\"\n",
					ESDM_ES_EXT_ENTROPY_RATE_MAX, optarg);
				goto out;
			}
			rate = (uint32_t)val;
			break;
		case PROVIDER_OPT_NAME:
			declared = esdm_es_ext_name_or_null(optarg);
			if (!declared) {
				fprintf(stderr,
					"--name takes 1 to %u bytes of UTF-8 without control characters\n",
					ESDM_ES_EXT_NAME_MAX);
				goto out;
			}
			break;
		case 'v':
			verbose++;
			break;
		case PROVIDER_OPT_VERSION:
			provider_version(cli, stdout, name);
			ret = 0;
			goto out;
		case 'h':
			provider_usage(cli, name);
			ret = 0;
			goto out;
		case '?':
		case ':':
			/* Told by getopt_long() already without a secret */
			if (cli->secret)
				provider_option_error(cli, c, opts);
			provider_usage(cli, name);
			goto out;
		default:
			if (!cli->option || cli->option(c, optarg))
				goto out;
			break;
		}
	}

	if (verbose) {
		unsigned int level =
			esdm_logger_get_verbosity(LOGGER_C_ANY) + verbose;

		esdm_logger_set_verbosity((enum esdm_logger_verbosity)(
			level < LOGGER_MAX_LEVEL ? level :
						   LOGGER_MAX_LEVEL - 1));
	}

	if (optind != argc || !socket_path) {
		if (!socket_path)
			fprintf(stderr, "--socket is required\n");
		else if (cli->secret)
			fprintf(stderr,
				"Unexpected argument - not repeated, as it may hold %s\n",
				cli->secret);
		else
			fprintf(stderr, "Unexpected argument \"%s\"\n",
				argv[optind]);
		provider_usage(cli, name);
		goto out;
	}

	if (cli->setup && cli->setup())
		goto out;

	/*
	 * The server sends with MSG_NOSIGNAL: this is for the I/O of the
	 * source, from its init on - a pcscd or token daemon gone must not end
	 * it.
	 */
	signal(SIGPIPE, SIG_IGN);

	err = esdm_es_ext_server_alloc(plugin, socket_path, mode,
				       &provider_server);
	if (err) {
		fprintf(stderr, "Cannot serve on %s: %s\n", socket_path,
			strerror(-err));
		goto out;
	}

	/*
	 * The ESDM runs as nobody unless told otherwise - else root alone. Any
	 * process of nobody may then take its client slots: --client_uid of a
	 * user only the ESDM runs as is better.
	 */
	if (!client_uids_num) {
		client_uids[0] = provider_parse_uid("nobody");
		if (client_uids[0] == (uid_t)-1)
			client_uids[0] = 0;
		client_uids_num = 1;
	}
	for (i = 0; i < client_uids_num; i++) {
		err = esdm_es_ext_server_allow_uid(provider_server,
						   client_uids[i]);
		if (err) {
			fprintf(stderr, "Cannot serve uid %u: %s\n",
				(unsigned int)client_uids[i], strerror(-err));
			goto out_free;
		}
	}

	/* Checked above */
	if (declared)
		esdm_es_ext_server_set_name(provider_server, declared);
	esdm_es_ext_server_set_entropy_rate(provider_server, rate);

	err = pthread_create(&signal_thread, NULL, provider_signals, NULL);
	if (err) {
		fprintf(stderr, "Cannot wait for signals: %s\n", strerror(err));
		goto out_free;
	}

	if (!declared)
		declared = esdm_es_ext_name_or_null(plugin->name);
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "Serving external entropy source %s on %s\n",
		    declared ? declared : name, socket_path);

	/* Serving, the source set up: a unit ordered before the ESDM is ready */
	systemd_notify_ready();

	err = esdm_es_ext_server_run(provider_server);
	if (err)
		fprintf(stderr, "Serving %s failed: %s\n", socket_path,
			strerror(-err));
	ret = err ? 1 : 0;

	systemd_notify_stopping();

	/* The signal thread ended with the signal, or waits for one still */
	pthread_kill(signal_thread, SIGTERM);
	pthread_join(signal_thread, NULL);

out_free:
	esdm_es_ext_server_free(provider_server);
	provider_server = NULL;
out:
	free(short_options);
	free(opts);
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_provider_main(const struct esdm_es_ext_plugin *plugin, int argc,
			      char *argv[])
{
	static const struct esdm_es_ext_provider_cli cli = { 0 };

	return esdm_es_ext_provider_cli_main(&cli, plugin, argc, argv);
}
