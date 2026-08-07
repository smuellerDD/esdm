# Tests of the RPC wire protocol helpers.
#
# These exercise the encode/decode and allocator code of service-rpc/service/
# directly, without a server, a socket or any privileges - unlike the tests in
# tests/rpc_client, which drive the whole stack against a running esdm-server.

rpc_protocol_test = executable(
		'rpc_protocol_test',
		[ service_rpc_src, 'rpc_protocol_test.c' ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		dependencies: dependencies_server,
		link_with: esdm_common_static_lib,
	)

test('RPC wire protocol', rpc_protocol_test)
