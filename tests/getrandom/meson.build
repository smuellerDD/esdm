if get_option('linux-getrandom').enabled()
	getrandom_syscall = executable(
			'getrandom_tester',
			[ 'getrandom_test.c', 'env.c' ],
			dependencies: esdm_getrandom_dep
		)

	# Available test targets:
	#	esdm-server: esdm_server
	#	esdm-cuse-random: esdm_cuse_random
	#	esdm-cuse-urandom: esdm_cuse-urandom
	#	libesdm-getrandom: esdm_getrandom_lib
	tester_getrandom_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		'ESDM_LIB_GETRANDOM=' + esdm_getrandom_lib.full_path()
		]

	test('System call getrandom', getrandom_syscall,
		env: [ tester_getrandom_env , 'LD_PRELOAD=' + esdm_getrandom_lib.full_path()],
		is_parallel: false)
endif
