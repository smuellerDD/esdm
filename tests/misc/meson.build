# How fast random data arrives, one request size at a time. Built as a plain
# tool to run by hand against whatever the machine offers, and once more per
# frontend below as a tester that brings an ESDM of its own up.
speedtest = executable(
		'speedtest',
		[ 'speedtest.c' ],
	)

# The request sizes to measure: the small ones cost a round trip each and are
# what the frontends are judged on, the large ones move the data. The set the
# shell script this replaces measured.
speedtest_sizes = [ '-b', '16', '-b', '32', '-b', '64', '-b', '128',
		    '-b', '256', '-b', '512', '-b', '1024', '-b', '4096' ]

# A second per size, rather than the two the tool defaults to: enough for the
# figure to settle, and it is paid once per size and frontend.
speedtest_args = [ '-e', '1' ] + speedtest_sizes

if get_option('linux-getrandom').enabled()
	# Measured through the interposition library, which is the only way the
	# ESDM answers a getrandom() call at all.
	speedtest_getrandom = executable(
			'speedtest_getrandom',
			[ 'speedtest.c', files('../getrandom/env.c') ],
			c_args: '-DESDM_SPEEDTEST_GETRANDOM_ENV',
			# env.c waits for the RPC socket the server creates
			include_directories: [
				include_directories('../getrandom'),
				include_dirs_server ],
			dependencies: esdm_getrandom_dep,
		)

	test('Speed of getrandom', speedtest_getrandom,
		args: speedtest_args,
		env: [
			'ESDM_SERVER=' + esdm_server.full_path(),
			'ESDM_LIB_GETRANDOM=' + esdm_getrandom_lib.full_path(),
			# See tests/getrandom/meson.build: the library loads
			# ahead of the ASan runtime it pulls in itself.
			'ASAN_OPTIONS=halt_on_error=1:abort_on_error=1' +
				':print_summary=1:verify_asan_link_order=0',
			'LD_PRELOAD=' + esdm_getrandom_lib.full_path()
			],
		# A measurement is only worth reading if it had the machine
		# to itself, and it takes a second per size on top of the
		# daemon startup.
		timeout: 300,
		is_parallel: false,
		priority: -10)
endif

if get_option('linux-devfiles').enabled()
	# Shares the environment of the device tests, which is what brings the
	# ESDM and the two CUSE daemons up.
	misc_cuse_env = files('../cuse/env.c')

	# Ahead of the server directories, which hold a privileges.h of their own
	misc_cuse_includes = [ include_directories('../cuse'),
			       include_dirs_server ]

	parallel_stress_tester = executable(
			'parallel_stress_tester',
			[ misc_cuse_env, 'parallel_stress.c' ],
			include_directories: misc_cuse_includes,
			link_with: esdm_common_static_lib,
		)

	# What the two device files deliver per request size, which is what the
	# stress test next to it does not say: it loads the daemons, it does not
	# time them.
	speedtest_devfiles = executable(
			'speedtest_devfiles',
			[ 'speedtest.c', misc_cuse_env ],
			c_args: '-DESDM_SPEEDTEST_CUSE_ENV',
			include_directories: misc_cuse_includes,
			link_with: esdm_common_static_lib,
		)

	# Available test targets:
	#	esdm-server: esdm_server
	#	esdm-cuse-random: esdm_cuse_random
	#	esdm-cuse-urandom: esdm_cuse-urandom
	tester_misc_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		'ESDM_CUSE_RANDOM=' + esdm_cuse_random.full_path(),
		'ESDM_CUSE_URANDOM=' + esdm_cuse_urandom.full_path()
		]

	# Serial for the reason the device tests are, and beyond that because it
	# takes the machine for itself: it loads every CPU at once.
	test('Parallel device stress', parallel_stress_tester,
		env: [ tester_misc_env ],
		timeout: 900,
		is_parallel: false,
		priority: -10,
		suite: 'cuse')

	# Serial for the same reason, and because a measurement shared with
	# another test measures that test as well.
	test('Speed of the device files', speedtest_devfiles,
		args: speedtest_args,
		env: [ tester_misc_env ],
		timeout: 300,
		is_parallel: false,
		priority: -10,
		suite: 'cuse')
endif
