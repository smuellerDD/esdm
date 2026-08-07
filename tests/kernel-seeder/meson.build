if get_option('esdm-server').enabled()
	kernel_seeder_tester = executable(
		'kernel_seeder_tester',
		[ 'kernel_seeder_test.c' ],
		include_directories: include_dirs_client,
	)

	# Available test targets:
	#	esdm-server: esdm_server
	#	esdm-kernel-seeder: esdm_kernel_seeder
	tester_kernel_seeder_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		'ESDM_KERNEL_SEEDER=' + esdm_kernel_seeder.full_path()
		]

	# The end-to-end part of this test spawns an ESDM server and inserts
	# entropy into the running kernel - keep it away from everything else.
	test('Kernel entropy feeder', kernel_seeder_tester,
		env: [ tester_kernel_seeder_env ],
		timeout: 180,
		is_parallel: false)
endif
