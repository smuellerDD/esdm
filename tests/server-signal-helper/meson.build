# Tests of esdm-server-signal-helper.
#
# What the helper decides - which mode, and whether the pidfile names something
# worth signalling - happens before any RPC, in static functions. The
# translation unit is compiled into the test to reach them, with its main()
# renamed out of the way so the test can both call it and have one of its own.
if get_option('esdm-server').enabled()
	signal_helper_test = executable(
			'signal_helper_test',
			[ 'signal_helper_test.c' ],
			c_args: [ '-Dmain=esdm_signal_helper_main_unused' ],
			include_directories: [
				include_dirs_client,
				include_directories('../../frontends/server-signal-helper'),
				include_directories('../common') ],
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib,
				     esdm_rpc_client_lib ],
		)

	test('esdm-server-signal-helper', signal_helper_test)
endif
