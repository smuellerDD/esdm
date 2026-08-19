# Fuzz harnesses for the RPC interfaces. Each is built twice: as a libFuzzer
# binary, and with the seed-replaying driver in fuzz_driver.c, which needs no
# fuzzing engine and runs in the ordinary test suite.

fuzz_cc = meson.get_compiler('c')

# libFuzzer defines main() and calls into the harness - a link test needs the
# entry point the engine looks for.
fuzz_engine_probe = '''
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	(void)data;
	(void)size;
	return 0;
}
'''

have_libfuzzer = fuzz_cc.links(fuzz_engine_probe,
			       args: [ '-fsanitize=fuzzer' ],
			       name: 'libFuzzer')

if not have_libfuzzer
	message('No libFuzzer in this compiler - the fuzz harnesses are built with the replay driver only')
endif

# protobuf-c calls a closure of a generic type through the type of the message
# it carries, which the indirect call check of clang 17+ reports on every call.
# Turn that one check off where the compiler knows the option.
fuzz_c_args = [ ]
if fuzz_cc.has_argument('-fno-sanitize=function')
	fuzz_c_args += [ '-fno-sanitize=function' ]
endif

fuzz_targets = [
	# The requests the server takes off its two sockets, served by the whole
	# server built from its sources - the fuzzer is guided by what the ESDM
	# does with a request, not only by what the RPC layer does.
	{
		'name': 'rpc_request',
		'sources': [ common_src, crypto_src, esdm_src,
			     service_rpc_src, server_rpc_src, egd_server_src,
			     files('rpc_request_fuzz.c') ],
		'include': include_dirs_server,
		'deps': dependencies_server + dependencies_esdm_lib,
		'link': [ ],
	},
	# The responses a client parses. The client stack only, no server and
	# no ESDM - the bytes come from the harness.
	{
		'name': 'rpc_response',
		'sources': [ service_rpc_src, client_rpc_src,
			     files('rpc_response_fuzz.c') ],
		'include': [ include_dirs_client, include_dirs_server ],
		'deps': dependencies_client,
		'link': [ esdm_common_static_lib ],
	},
	# The server as a client reaches it: the client library on one side,
	# the server's accept loop and worker threads on the other, both in
	# this process. One input is a script of client calls.
	{
		'name': 'rpc_client',
		'sources': [ common_src, crypto_src, esdm_src, service_rpc_src,
			     server_rpc_src, egd_server_src, client_rpc_src,
			     files('rpc_client_fuzz.c') ],
		'include': [ include_dirs_server, include_dirs_client ],
		'deps': dependencies_server + dependencies_esdm_lib,
		'link': [ ],
	},
	# The EGD compatibility interface of the server: a byte stream with no
	# framing above the commands themselves, so an input is the stream and
	# the reads it arrives in.
	{
		'name': 'egd',
		# server_rpc_src for the stale socket removal the EGD server
		# shares with the RPC one - none of it is reached from here.
		'sources': [ common_src, crypto_src, esdm_src, service_rpc_src,
			     server_rpc_src, egd_server_src,
			     files('egd_fuzz.c') ],
		'include': include_dirs_server,
		'deps': dependencies_server + dependencies_esdm_lib,
		'link': [ ],
	},
	# The library itself, called the way a program linking it does. No RPC
	# at all: one input is a sequence of API calls, so what is fuzzed is
	# also the state they share.
	{
		'name': 'esdm_lib',
		'sources': [ common_src, crypto_src, esdm_src,
			     files('esdm_lib_fuzz.c') ],
		'include': include_dirs_server,
		'deps': dependencies_esdm_lib,
		'link': [ ],
	},
	# The EGD client library, the other side of the socket the EGD harness
	# above serves. No ESDM and no server: the answers come from the
	# harness, which is the impostor the client is talking to.
	{
		'name': 'egd_client',
		'sources': [ egd_client_src, files('egd_client_fuzz.c') ],
		'include': include_dirs_egd_client,
		'deps': [ dependency('threads') ],
		'link': [ esdm_common_static_lib ],
	},
	# The wire codec under both of them, called directly: no sockets, no
	# ESDM, and therefore the harness that gets through the most inputs.
	{
		'name': 'rpc_protocol',
		'sources': [ service_rpc_src, files('rpc_protocol_fuzz.c') ],
		'include': include_dirs_server,
		'deps': dependencies_server,
		'link': [ esdm_common_static_lib ],
	},
]

# The same request path as the first harness, driven by several threads at
# once: what a fuzzer cannot reach on its own, as it feeds one input at a time.
rpc_stress_test = executable(
		'rpc_stress_test',
		[ common_src, crypto_src, esdm_src, service_rpc_src,
		  server_rpc_src, egd_server_src, files('rpc_stress.c') ],
		include_directories: include_dirs_server,
		dependencies: dependencies_server + dependencies_esdm_lib,
		c_args: fuzz_c_args,
	)

test('RPC request path under concurrent load', rpc_stress_test, timeout: 300)

foreach fuzz_target : fuzz_targets
	fuzz_replay = executable(
			fuzz_target['name'] + '_fuzz_replay',
			[ fuzz_target['sources'], files('fuzz_driver.c') ],
			include_directories: fuzz_target['include'],
			dependencies: fuzz_target['deps'],
			link_with: fuzz_target['link'],
			c_args: fuzz_c_args,
		)

	# The seeds are the harness' regression corpus. The client harness binds
	# the RPC sockets, whose paths are fixed at build time, so it runs alone.
	test('Fuzz seeds - ' + fuzz_target['name'], fuzz_replay, timeout: 120,
		is_parallel: fuzz_target['name'] != 'rpc_client')

	if have_libfuzzer
		executable(
			fuzz_target['name'] + '_fuzz',
			fuzz_target['sources'],
			include_directories: fuzz_target['include'],
			dependencies: fuzz_target['deps'],
			link_with: fuzz_target['link'],
			c_args: fuzz_c_args + [ '-fsanitize=fuzzer' ],
			link_args: [ '-fsanitize=fuzzer' ],
		)
	endif
endforeach
