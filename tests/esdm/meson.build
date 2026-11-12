# Every test here drives the ESDM in process and therefore touches the
# machine-global System V names - see tests/test_ipc_ns.c.
esdm_ipc_ns = files('../test_ipc_ns.c')

# fips.c only exists in a FIPS build. It is compiled into the test rather than
# linked, so the configuration probe of its constructor can be stubbed out: a
# failing power-on self test would exit() before main() runs.
if get_option('fips140')
	esdm_fips_test = executable(
		'esdm_fips_test',
		[ files('../../esdm/fips.c'), 'esdm_fips_test.c' ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		dependencies: dependencies_server,
		link_with: esdm_common_static_lib,
	)

	test('ESDM FIPS mode detection', esdm_fips_test, suite: 'core')
endif

if get_option('esdm-server').enabled()
	esdm_status_test = executable(
		'esdm_status_test',
		[ esdm_ipc_ns, 'esdm_status_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_status_text_test = executable(
		'esdm_status_text_test',
		[ 'esdm_status_text_test.c' ],
		include_directories: [ include_dirs_server,
				       include_directories('../common') ],
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_version_test = executable(
		'esdm_version_test',
		[ esdm_ipc_ns, 'esdm_version_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_get_random_bytes_full_test = executable(
		'esdm_get_random_bytes_full_test',
		[ esdm_ipc_ns, 'esdm_get_random_bytes_full_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_get_random_bytes_test = executable(
		'esdm_get_random_bytes_test',
		[ esdm_ipc_ns, 'esdm_get_random_bytes_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	esdm_drng_mgr_max_wo_reseed_test = executable(
		'esdm_drng_mgr_max_wo_reseed_test',
		[ esdm_ipc_ns, 'esdm_drng_mgr_max_wo_reseed_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_drng_mgr_throughput_test = executable(
		'esdm_drng_mgr_throughput_test',
		[ esdm_ipc_ns, 'esdm_drng_mgr_throughput_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_drng_mgr_max_wo_reseed_bits_test = executable(
		'esdm_drng_mgr_max_wo_reseed_bits_test',
		[ esdm_ipc_ns, 'esdm_drng_mgr_max_wo_reseed_bits_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_drng_seed_entropy_test = executable(
		'esdm_drng_seed_entropy_test',
		[ esdm_ipc_ns, 'esdm_drng_seed_entropy_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_get_seed_test = executable(
		'esdm_get_seed_test',
		[ esdm_ipc_ns, 'esdm_get_seed_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_reseed_worker_test = executable(
		'esdm_reseed_worker_test',
		[ esdm_ipc_ns, 'esdm_reseed_worker_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_ntg1_seeding_test = executable(
		'esdm_ntg1_seeding_test',
		[ esdm_ipc_ns, 'esdm_ntg1_seeding_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	test('ESDM API call esdm_status', esdm_status_test, suite: 'core')
	test('ESDM status text', esdm_status_text_test, suite: 'core')
	test('ESDM API call esdm_version', esdm_version_test, suite: 'core')
	test('ESDM API call esdm_get_random_bytes_full', esdm_get_random_bytes_full_test,
		suite: 'core')
	test('ESDM API call esdm_get_random_bytes', esdm_get_random_bytes_test,
		suite: 'core')
	test('ESDM DRNG manager max w/o reseed - 1 DRNG', esdm_drng_mgr_max_wo_reseed_test,
		args : [ '1' ],
		suite: 'core')
	test('ESDM DRNG manager max w/o reseed - 2 DRNG', esdm_drng_mgr_max_wo_reseed_test,
		args : [ '2' ],
		suite: 'core')

	test('ESDM DRNG manager max w/o reseed bits - 1 DRNG', esdm_drng_mgr_max_wo_reseed_bits_test,
		args : [ '1' ],
		suite: 'core')
	test('ESDM DRNG manager max w/o reseed bits - 2 DRNG', esdm_drng_mgr_max_wo_reseed_bits_test,
		args : [ '2' ],
		suite: 'core')

	# Serial: it reports a rate, and a rate measured while the rest of the
	# suite has the machine says more about the suite than about the ESDM.
	test('ESDM DRNG manager sustained generation', esdm_drng_mgr_throughput_test,
		timeout: 300,
		is_parallel: false,
		priority: -10,
		suite: 'core')

	test('ESDM seed entropy - all ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '0' ],
		timeout: 300,
		suite: 'core')
	test('ESDM seed entropy - all ES, FIPS', esdm_drng_seed_entropy_test,
		args : [ '1', '0' ],
		timeout: 300,
		suite: 'core')
	test('ESDM seed entropy - JENT ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '1' ],
		timeout: 300,
		suite: 'core')
	test('ESDM seed entropy - JENT ES, FIPS', esdm_drng_seed_entropy_test,
		args : [ '1', '1' ],
		timeout: 300,
		suite: 'core')
	test('ESDM seed entropy - CPU ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '2' ],
		timeout: 300,
		suite: 'core')
	test('ESDM seed entropy - CPU ES, FIPS', esdm_drng_seed_entropy_test,
		args : [ '1', '2' ],
		timeout: 300,
		suite: 'core')
	test('ESDM seed entropy - KRNG ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '3' ],
		timeout: 300,
		suite: 'core')
	# This test will never work as KRNG will provide 0 bits of entropy, skip it
	#test('ESDM seed entropy - KRNG ES, FIPS', esdm_drng_seed_entropy_test,
	#     args : [ '1', '3' ],
	#     timeout: 300)
	test('ESDM seed entropy - Sched ES, no FIPS', esdm_drng_seed_entropy_test,
		args : [ '0', '4' ],
		timeout: 300,
		suite: 'core')
	test('ESDM seed entropy - Sched ES, FIPS', esdm_drng_seed_entropy_test,
		args : [ '1', '4' ],
		timeout: 300,
		suite: 'core')

	test('ESDM get seed - all ES, no FIPS', esdm_get_seed_test,
		args : [ '0' ],
		timeout: 300,
		suite: 'core')
	test('ESDM get seed - all ES, FIPS', esdm_get_seed_test,
		args : [ '1' ],
		timeout: 300,
		suite: 'core')

	test('ESDM NTG.1 seeding strategy', esdm_ntg1_seeding_test,
		suite: 'core')

	test('ESDM asynchronous reseed worker', esdm_reseed_worker_test,
		timeout: 120,
		suite: 'core')


	esdm_aux_xdrbg_test = executable(
		'esdm_aux_xdrbg_test',
		[ esdm_ipc_ns, 'esdm_aux_xdrbg_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	test('ESDM aux pool XDRBG-256', esdm_aux_xdrbg_test, suite: 'core')

	esdm_aux_xof_failure_test = executable(
		'esdm_aux_xof_failure_test',
		[ esdm_ipc_ns, 'esdm_aux_xof_failure_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	test('ESDM aux pool XOF failure', esdm_aux_xof_failure_test,
		suite: 'core')

	esdm_lifecycle_test = executable(
		'esdm_lifecycle_test',
		[ esdm_ipc_ns, 'esdm_lifecycle_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	test('ESDM non-blocking getters, node count, re-init',
		esdm_lifecycle_test,
		timeout: 120,
		suite: 'core')
endif
