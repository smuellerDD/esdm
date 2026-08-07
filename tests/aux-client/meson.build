# Tests of the auxiliary client library - the interface an external entropy
# provider uses. It needs neither privileges nor a running server, so this runs
# in an ordinary test run.
if get_option('esdm-aux-client').enabled()
	aux_client_test = executable(
			'aux_client_test',
			[ files('../test_ipc_ns.c'), 'aux_client_test.c' ],
			include_directories: [ include_dirs_client,
					       include_dirs_aux_client,
					       include_directories('../common') ],
			link_with: [ esdm_aux_client_lib.get_static_lib(),
				     esdm_common_static_lib ],
		)

	test('ESDM auxiliary client', aux_client_test, timeout: 60)
endif
