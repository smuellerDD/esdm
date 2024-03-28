if get_option('esdm-server').enabled()
	esdm_tester_common = files([
		'env.c'
		])

	rpc_get_random_bytes_full_test = executable(
			'rpc_get_random_bytes_full_test',
			[ esdm_tester_common, 'rpc_get_random_bytes_full_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_random_bytes_pr_test = executable(
			'rpc_get_random_bytes_pr_test',
			[ esdm_tester_common, 'rpc_get_random_bytes_pr_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	# This is just a helper for debugging - no real test
	esdm_rpc_invoker = executable(
			'esdm_rpc_invoker',
			[ esdm_tester_common, 'esdm_rpc_invoker.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_random_bytes_min_test = executable(
			'rpc_get_random_bytes_min_test',
			[ esdm_tester_common, 'rpc_get_random_bytes_min_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_random_bytes_test = executable(
			'rpc_get_random_bytes_test',
			[ esdm_tester_common, 'rpc_get_random_bytes_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_get_seed_test = executable(
			'rpc_get_seed_test',
			[ esdm_tester_common, 'rpc_get_seed_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_status_test = executable(
			'rpc_status_test',
			[ esdm_tester_common, 'rpc_status_test.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)
	
	rpc_ent_lvl_test = executable(
			'rpc_ent_lvl_test',
			[ esdm_tester_common, 'rpc_ent_lvl.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	rpc_seed_lvl_test = executable(
			'rpc_seed_lvl_test',
			[ esdm_tester_common, 'rpc_seed_lvl.c' ],
			include_directories: include_dirs_client,
			dependencies: [ dependencies_client ],
			link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ]
		)

	# Available test targets:
	#	esdm-server: esdm_server
	#	esdm-cuse-random: esdm_cuse_random
	#	esdm-cuse-urandom: esdm_cuse-urandom
	#	libesdm-getrandom: esdm_getrandom_lib
	tester_esdm_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		]

	test('RPC call get_random_bytes_full_test', rpc_get_random_bytes_full_test,
		env: [ tester_esdm_env ],
		is_parallel: false)

	test('RPC call get_random_bytes_pr_test', rpc_get_random_bytes_pr_test,
		env: [ tester_esdm_env ],
		is_parallel: false)

	test('RPC call get_random_bytes_min_test', rpc_get_random_bytes_min_test,
		env: [ tester_esdm_env ],
		is_parallel: false)

	test('RPC call get_random_bytes_test', rpc_get_random_bytes_test,
		env: [ tester_esdm_env ],
		is_parallel: false)

	test('RPC call get_seed_test', rpc_get_seed_test,
		env: [ tester_esdm_env ],
		is_parallel: false)

	test('RPC call status_test', rpc_status_test,
		env: [ tester_esdm_env ],
		is_parallel: false)

	test('RPC call ent_lvl_test', rpc_ent_lvl_test,
		env: [ tester_esdm_env ],
		is_parallel: false)

	test('RPC call seed_lvl_test', rpc_seed_lvl_test,
		env: [ tester_esdm_env ],
		is_parallel: false)
endif
