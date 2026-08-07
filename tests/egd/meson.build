# Tests of the EGD interface. The client library is exercised against the test
# peer next to them, which can produce the answers a correct server never gives,
# and both sides are exercised together against the esdm-server.
#
# Only the latter needs a server - and thus privileges - so everything else runs
# in an ordinary unprivileged test run as well.
egd_test_peer = files([
	'egd_peer.c'
	])

egd_test_deps = [ dependency('threads') ]

egd_client_test = executable(
		'egd_client_test',
		[ egd_test_peer, 'egd_client_test.c' ],
		include_directories: include_dirs_egd_client,
		dependencies: egd_test_deps,
		link_with: [ esdm_egd_client_lib.get_static_lib() ]
	)

egd_robust_test = executable(
		'egd_robust_test',
		[ egd_test_peer, 'egd_robust_test.c' ],
		include_directories: include_dirs_egd_client,
		dependencies: egd_test_deps,
		link_with: [ esdm_egd_client_lib.get_static_lib() ]
	)

# Several of these wait for answers that never come, so they need more than the
# default timeout - which they must never come close to, as running into it is
# how a wedged client would show up.
test('EGD client library', egd_client_test, timeout: 120)

test('EGD client robustness', egd_robust_test, timeout: 120)

if get_option('esdm-server').enabled()
	# The server side driven in-process and spoken to in raw protocol
	# bytes. Unlike the test below it needs no daemon and therefore no
	# privileges, and it decides itself when the ESDM turns operational -
	# which is the only way to observe what the blocking read command does
	# while it is not.
	egd_server_raw_test = executable(
			'egd_server_raw_test',
			[ egd_server_src, files('../test_ipc_ns.c'),
			  'egd_server_raw_test.c' ],
			include_directories: include_dirs_server,
			dependencies: [ dependencies_server, egd_test_deps ],
			link_with: esdm_static_lib
		)

	test('EGD server raw protocol', egd_server_raw_test, timeout: 300)

	egd_server_test = executable(
			'egd_server_test',
			[ 'egd_server_test.c' ],
			include_directories: include_dirs_egd_client,
			dependencies: egd_test_deps,
			link_with: [ esdm_egd_client_lib.get_static_lib() ]
		)

	# Skipped (77) unless it is run as root: the esdm-server refuses to
	# start otherwise. The daemon it starts claims the fixed socket,
	# semaphore and IPC names, so the test puts itself in namespaces of its
	# own - which is what lets it run next to the rest.
	test('EGD server interface', egd_server_test,
		env: [ 'ESDM_SERVER=' + esdm_server.full_path() ],
		timeout: 300)
endif
