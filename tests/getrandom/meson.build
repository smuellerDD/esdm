if get_option('linux-getrandom').enabled()
	getrandom_syscall = executable(
			'getrandom_tester',
			[ 'getrandom_test.c', 'env.c' ],
			# env.c waits for the RPC socket the server creates
			include_directories: include_dirs_server,
			dependencies: esdm_getrandom_dep
		)

	getrandom_get_seed_test = executable(
			'getrandom_get_seed_test',
			[ 'getrandom_get_seed_test.c', 'env.c' ],
			include_directories: include_dirs_server,
			dependencies: esdm_getrandom_dep
		)

	# Available test targets:
	#	esdm-server: esdm_server
	#	esdm-cuse-random: esdm_cuse_random
	#	esdm-cuse-urandom: esdm_cuse-urandom
	#	libesdm-getrandom: esdm_getrandom_lib
	tester_getrandom_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		'ESDM_LIB_GETRANDOM=' + esdm_getrandom_lib.full_path(),
		# These two tests interpose the getrandom library with
		# LD_PRELOAD, so on a sanitizer build it is loaded ahead of the
		# ASan runtime that it pulls in itself. ASan refuses to start in
		# that situation ("ASan runtime does not come first in initial
		# library list"), which is exactly how this library is meant to
		# be used and cannot be fixed by relinking - so turn the check
		# off. The rest of the value restates what meson would set,
		# because naming the variable here replaces its default.
		'ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1' +
			':verify_asan_link_order=0'
		]

	test('System call getrandom', getrandom_syscall,
		env: [ tester_getrandom_env , 'LD_PRELOAD=' + esdm_getrandom_lib.full_path()])

	test('System call getrandom get_seed', getrandom_get_seed_test,
		env: [ tester_getrandom_env , 'LD_PRELOAD=' + esdm_getrandom_lib.full_path()])

endif
