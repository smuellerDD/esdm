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
 * External entropy sources for the ESDM - see libesdm_es_ext(3).
 *
 * An external entropy source is served to the ESDM by a provider: a process
 * of its own on a Unix domain socket, which the ESDM reads (esdm-server
 * --es_ext PATH). No code of a source runs in the ESDM. A provider is the
 * callbacks of struct esdm_es_ext_plugin, served by esdm_es_ext_provider_main()
 * or esdm_es_ext_server_*(), or a program speaking the protocol below itself.
 */

#ifndef _ESDM_ES_EXT_H
#define _ESDM_ES_EXT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version of struct esdm_es_ext_plugin; later ones only append members */
#define ESDM_ES_EXT_PLUGIN_VERSION 1

/* The highest entropy rate: bits per 256 bits of data */
#define ESDM_ES_EXT_ENTROPY_RATE_MAX 256

/* Largest status of a source and of a provider, bytes of JSON without NUL */
#define ESDM_ES_EXT_STATUS_MAX 512
#define ESDM_ES_EXT_PROTO_STATUS_MAX 1024

/* Longest name of a source, bytes of UTF-8 without NUL */
#define ESDM_ES_EXT_NAME_MAX 32

/* Clients a provider serves at a time, and uids it can allow */
#define ESDM_ES_EXT_MAX_CLIENTS 8
#define ESDM_ES_EXT_MAX_CLIENT_UIDS 8

/**
 * struct esdm_es_ext_plugin - the callbacks of an external entropy source
 *
 *	static const struct esdm_es_ext_plugin my_source = {
 *		.version = ESDM_ES_EXT_PLUGIN_VERSION,
 *		.name = "my-noise-source",
 *		.get_entropy = my_get_entropy,
 *	};
 *
 *	int main(int argc, char *argv[])
 *	{
 *		return esdm_es_ext_provider_main(&my_source, argc, argv);
 *	}
 *
 * The callbacks are never called concurrently, and all run in the provider.
 *
 * @version: ESDM_ES_EXT_PLUGIN_VERSION
 * @name: The name the ESDM shows the source under in place of
 *	  "ExternalSocket", which it keeps as "instance": 1 to
 *	  ESDM_ES_EXT_NAME_MAX bytes of UTF-8 without control characters. An
 *	  invalid name, or one of another entropy source, is not taken. May be
 *	  NULL.
 * @init: Set the source up, its context in *@ctx. 0 or a negative errno, which
 *	  refuses to serve. May be NULL.
 * @fini: Tear the source down. May be NULL.
 * @get_entropy: Fill all @buflen bytes of @buf and set *@entropy_bits to their
 *		 entropy, at most @buflen * 8. 0 or a negative errno. Must not
 *		 block for long: a DRNG waits for it.
 * @selftest: Check the noise source without consuming the data the ESDM gets:
 *	      0 or a negative errno. Run before the ESDM first credits the
 *	      source, on every new connection, and on the ESDM self test
 *	      interval. May be NULL.
 * @status_json: Write the status of the source - one JSON object, NUL
 *		 terminated, of up to ESDM_ES_EXT_STATUS_MAX bytes - into @buf
 *		 of @buflen bytes: 0, -EMSGSIZE or another negative errno. The
 *		 ESDM shows it as "plugin" of the "provider" status of the
 *		 source, asked for at most every 5 seconds. May be NULL.
 * @entropy_rate: The rate the source declares, 0 to
 *		  ESDM_ES_EXT_ENTROPY_RATE_MAX - a higher one is capped - or
 *		  ESDM_ES_EXT_PROTO_RATE_NONE for none, called once after
 *		  @init. The ESDM credits a block with its claim, at most at
 *		  this rate - unless a rate is configured there. Without a
 *		  rate, the source is credited at 0. May be NULL.
 */
struct esdm_es_ext_plugin {
	uint32_t version;
	const char *name;
	int (*init)(void **ctx);
	void (*fini)(void *ctx);
	int (*get_entropy)(void *ctx, uint8_t *buf, size_t buflen,
			   uint32_t *entropy_bits);
	int (*selftest)(void *ctx);
	int (*status_json)(void *ctx, char *buf, size_t buflen);
	uint32_t (*entropy_rate)(void *ctx);
};

/******************************************************************************
 * Socket protocol
 *
 * The ESDM connects to a SOCK_SEQPACKET Unix domain socket and sends one
 * request at a time, each answered by one response: the protobuf messages
 * EsExtRequest and EsExtResponse of es_ext.proto in the ESDM sources, one per
 * message of the socket.
 *
 * A request has the version ESDM_ES_EXT_PROTO_VERSION, a type - GET_ENTROPY,
 * SELFTEST, STATUS or INFO - and the bytes asked for: 1 to
 * ESDM_ES_EXT_PROTO_MAX_DATA for GET_ENTROPY, 1 to
 * ESDM_ES_EXT_PROTO_STATUS_MAX for STATUS, else 0.
 *
 * A response has the version and the type of the request, and a status of 0
 * or a negative errno. With status 0 only, it carries for GET_ENTROPY the
 * bytes asked for and their entropy, at most 8 bits per byte; for STATUS a
 * JSON object of 1 to the bytes asked for; for INFO the entropy rate declared
 * (ESDM_ES_EXT_PROTO_RATE_NONE for none) and 0 to ESDM_ES_EXT_NAME_MAX bytes
 * of name.
 *
 * A message breaking this closes the connection. Every provider answers
 * every type, if only with an errno - -EOPNOTSUPP for no STATUS. The ESDM
 * asks INFO first and SELFTEST before GET_ENTROPY on a connection; a provider
 * does not rely on that order.
 *
 * The STATUS of libesdm_es_ext is { "server": { ... }, "plugin": ... }: the
 * "version", "plugin_api", declared "name" and "entropy_rate", "clients",
 * "client_slots", "requests", "selftest" verdict and "uptime_seconds" of the
 * server, and the status of @status_json - null for none, an error or one
 * that does not fit.
 ******************************************************************************/

#define ESDM_ES_EXT_PROTO_VERSION 1
#define ESDM_ES_EXT_PROTO_GET_ENTROPY 1
#define ESDM_ES_EXT_PROTO_SELFTEST 2
#define ESDM_ES_EXT_PROTO_STATUS 4
#define ESDM_ES_EXT_PROTO_INFO 5
#define ESDM_ES_EXT_PROTO_RATE_NONE 0xffffffffU
#define ESDM_ES_EXT_PROTO_MAX_DATA 512

/******************************************************************************
 * Provider server
 *
 * While esdm_es_ext_server_run() runs, no other function but
 * esdm_es_ext_server_stop() may be called on the server.
 ******************************************************************************/

struct esdm_es_ext_server;

/**
 * @brief Serve an external entropy source on a Unix domain socket
 *
 * Creates the socket file @socket_path with mode @mode - replacing a socket
 * there, but no other file - and calls the @init callback. The ESDM connects
 * with its privileges dropped (user nobody by default).
 *
 * @param [in] plugin Callbacks to serve, referenced until
 *		      esdm_es_ext_server_free()
 * @param [in] socket_path Path of the socket file
 * @param [in] mode Access mode of the socket file
 * @param [out] server The server
 *
 * @return 0 on success, -EPROTO for callbacks of an unknown version or without
 *	   get_entropy, -EADDRINUSE if another provider serves on @socket_path,
 *	   another negative errno otherwise
 */
int esdm_es_ext_server_alloc(const struct esdm_es_ext_plugin *plugin,
			     const char *socket_path, mode_t mode,
			     struct esdm_es_ext_server **server);

/**
 * @brief Serve only clients running as root and as @uid
 *
 * Without a uid allowed, any client is served. Any process running as an
 * allowed uid can take the client slots of the ESDM: allow the uid the ESDM
 * runs as, and best one nothing else runs as.
 *
 * @param [in] server The server
 * @param [in] uid The uid to serve, one of ESDM_ES_EXT_MAX_CLIENT_UIDS
 *
 * @return 0 on success, -EINVAL for (uid_t)-1, -ENOSPC beyond
 *	   ESDM_ES_EXT_MAX_CLIENT_UIDS
 */
int esdm_es_ext_server_allow_uid(struct esdm_es_ext_server *server, uid_t uid);

/**
 * @brief Declare @name in INFO in place of the name of the source
 *
 * @param [in] server The server
 * @param [in] name The name, NULL for the one of the source
 *
 * @return 0 on success, -EINVAL for an invalid name
 */
int esdm_es_ext_server_set_name(struct esdm_es_ext_server *server,
				const char *name);

/**
 * @brief Declare @rate in INFO in place of the rate of the source
 *
 * @param [in] server The server
 * @param [in] rate The rate, ESDM_ES_EXT_PROTO_RATE_NONE for the one of the
 *		    source
 *
 * @return 0 on success, -EINVAL beyond ESDM_ES_EXT_ENTROPY_RATE_MAX
 */
int esdm_es_ext_server_set_entropy_rate(struct esdm_es_ext_server *server,
					uint32_t rate);

/**
 * @brief Serve requests until esdm_es_ext_server_stop()
 *
 * Up to ESDM_ES_EXT_MAX_CLIENTS clients at a time, a client breaking the
 * protocol is disconnected. A client beyond takes the slot of the one idle the
 * longest - one of root only for another one of root, as the ESDM connects as
 * root at start up.
 *
 * @param [in] server The server
 *
 * @return 0 once stopped, a negative errno if serving failed
 */
int esdm_es_ext_server_run(struct esdm_es_ext_server *server);

/**
 * @brief Make esdm_es_ext_server_run() return - async-signal-safe
 *
 * @param [in] server The server
 */
void esdm_es_ext_server_stop(struct esdm_es_ext_server *server);

/**
 * @brief Close the connections, remove the socket file and call @fini
 *
 * @param [in] server The server, may be NULL
 */
void esdm_es_ext_server_free(struct esdm_es_ext_server *server);

/**
 * @brief The main() of a provider program
 *
 * Takes the command line (see libesdm_es_ext(3): --socket, --mode,
 * --client_uid, --name, --entropy_rate, -v, -h, --version), sets up the
 * source and serves it until SIGTERM, SIGINT or SIGHUP, telling systemd once
 * it serves. Logs to stderr.
 *
 * @param [in] plugin Callbacks of the source
 * @param [in] argc Argument count of main()
 * @param [in] argv Arguments of main()
 *
 * @return the exit status: 0 once ended by a signal, for --help and
 *	   --version; 1 otherwise
 */
int esdm_es_ext_provider_main(const struct esdm_es_ext_plugin *plugin, int argc,
			      char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_ES_EXT_H */
