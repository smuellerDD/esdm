if get_option('esdm-server').enabled()
	esdm_status_test = executable(
		'esdm_status_test',
		[ 'esdm_status_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_version_test = executable(
		'esdm_version_test',
		[ 'esdm_version_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_get_random_bytes_full_test = executable(
		'esdm_get_random_bytes_full_test',
		[ 'esdm_get_random_bytes_full_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_get_random_bytes_min_test = executable(
		'esdm_get_random_bytes_min_test',
		[ 'esdm_get_random_bytes_min_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_get_random_bytes_test = executable(
		'esdm_get_random_bytes_test',
		[ 'esdm_get_random_bytes_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_drng_mgr_max_wo_reseed_test = executable(
		'esdm_drng_mgr_max_wo_reseed_test',
		[ 'esdm_drng_mgr_max_wo_reseed_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_drng_seed_entropy_test = executable(
		'esdm_drng_seed_entropy_test',
		[ 'esdm_drng_seed_entropy_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	test('ESDM API call esdm_status', esdm_status_test)
	test('ESDM API call esdm_version', esdm_version_test)
	test('ESDM API call esdm_get_random_bytes_full', esdm_get_random_bytes_full_test)
	test('ESDM API call esdm_get_random_bytes_min', esdm_get_random_bytes_min_test)
	test('ESDM API call esdm_get_random_bytes', esdm_get_random_bytes_test)
	test('ESDM DRNG manager max w/o reseed - 1 DRNG', esdm_drng_mgr_max_wo_reseed_test,
		args : [ '1' ],
		is_parallel: false)
	test('ESDM DRNG manager max w/o reseed - 2 DRNG', esdm_drng_mgr_max_wo_reseed_test,
		args : [ '2' ],
		is_parallel: false)

	test('ESDM seed entropy - all ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '0' ],
		timeout: 300,
		is_parallel: false)
	test('ESDM seed entropy - all ES, FIPS', esdm_drng_seed_entropy_test,
		args : [ '1', '0' ],
		timeout: 300,
		is_parallel: false)
	test('ESDM seed entropy - JENT ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '1' ],
		timeout: 300,
		is_parallel: false)
	test('ESDM seed entropy - JENT ES, FIPS', esdm_drng_seed_entropy_test,
		args : [ '1', '1' ],
		timeout: 300,
		is_parallel: false)
	test('ESDM seed entropy - CPU ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '2' ],
		timeout: 300,
		is_parallel: false)
	test('ESDM seed entropy - CPU ES, FIPS', esdm_drng_seed_entropy_test,
		args : [ '1', '2' ],
		timeout: 300,
		is_parallel: false)
	test('ESDM seed entropy - KRNG ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '3' ],
		timeout: 300,
		is_parallel: false)
	# This test will never work as KRNG will provide 0 bits of entropy, skip it
	#test('ESDM seed entropy - KRNG ES, FIPS', esdm_drng_seed_entropy_test,
	#     args : [ '1', '3' ],
	#     is_parallel: false)
	test('ESDM seed entropy - Sched ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '4' ],
		timeout: 300,
		is_parallel: false)
	test('ESDM seed entropy - Sched ES, FIPS', esdm_drng_seed_entropy_test,
		args : [ '1', '4' ],
		timeout: 300,
		is_parallel: false)
endif
