if get_option('linux-devfiles').enabled()
	cuse_tester_common = files([
		'env.c'
		])

	ioctl_addent_tester = executable(
		'ioctl_addent_tester',
		[ cuse_tester_common, 'ioctl_addent.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	ioctl_clear_tester = executable(
		'ioctl_clear_tester',
		[ cuse_tester_common, 'ioctl_clear.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	ioctl_getent_tester = executable(
		'ioctl_getent_tester',
		[ cuse_tester_common, 'ioctl_getent.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	ioctl_reseed_tester = executable(
		'ioctl_reseed_tester',
		[ cuse_tester_common, 'ioctl_reseed.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	ioctl_setent_tester = executable(
		'ioctl_setent_tester',
		[ cuse_tester_common, 'ioctl_setent.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	ioctl_getinfo_tester = executable(
		'ioctl_getinfo_tester',
		[ cuse_tester_common, 'ioctl_getinfo.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	poll_read_tester = executable(
		'poll_read_tester',
		[ cuse_tester_common, 'poll_read.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	poll_write_tester = executable(
		'poll_write_tester',
		[ cuse_tester_common, 'poll_write.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	random_read_tester = executable(
		'random_read_tester',
		[ cuse_tester_common, 'random_read.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	random_write_tester = executable(
		'random_write_tester',
		[ cuse_tester_common, 'random_write.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	random_read_no_server_tester = executable(
		'random_read_no_server_tester',
		[ cuse_tester_common, 'random_read_no_server.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	random_write_no_server_tester = executable(
		'random_write_no_server_tester',
		[ cuse_tester_common, 'random_write_no_server.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_common_static_lib,
		)

	# Available test targets:
	#	esdm-server: esdm_server
	#	esdm-cuse-random: esdm_cuse_random
	#	esdm-cuse-urandom: esdm_cuse-urandom
	#	libesdm-getrandom: esdm_getrandom_lib
	tester_cuse_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		'ESDM_CUSE_RANDOM=' + esdm_cuse_random.full_path(),
		'ESDM_CUSE_URANDOM=' + esdm_cuse_urandom.full_path()
		]

	test('IOCTL RNDADDENTROPY /dev/random', ioctl_addent_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('IOCTL RNDADDENTROPY /dev/urandom', ioctl_addent_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('IOCTL RNDCLEARPOOL /dev/random', ioctl_clear_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		timeout: 300,
		is_parallel: false)
	test('IOCTL RNDCLEARPOOL /dev/urandom', ioctl_clear_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		timeout: 300,
		is_parallel: false)

	test('IOCTL RNDGETENTCNT /dev/random', ioctl_getent_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('IOCTL RNDGETENTCNT /dev/urandom', ioctl_getent_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('IOCTL RNDRESEEDCRNG /dev/random', ioctl_reseed_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('IOCTL RNDRESEEDCRNG /dev/urandom', ioctl_reseed_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('IOCTL RNDADDTOENTCNT /dev/random', ioctl_setent_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('IOCTL RNDADDTOENTCNT /dev/urandom', ioctl_setent_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('IOCTL get info /dev/random', ioctl_getinfo_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('IOCTL get info /dev/urandom', ioctl_getinfo_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('Poll writer FD /dev/random', poll_write_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('Poll writer FD /dev/urandom', poll_write_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('Read /dev/random', random_read_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('Read /dev/urandom', random_read_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('Write /dev/random', random_write_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('Write /dev/urandom', random_write_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('Read /dev/random - w/o ESDM server', random_read_no_server_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('Read /dev/urandom - w/o ESDM server', random_read_no_server_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	test('Write /dev/random - w/o ESDM server', random_write_no_server_tester,
		env: [ tester_cuse_env ],
		args : ['random' ],
		is_parallel: false)
	test('Write /dev/urandom - w/o ESDM server', random_write_no_server_tester,
		env: [ tester_cuse_env ],
		args : ['urandom' ],
		is_parallel: false)

	# Poll read is not yet well implemented
	#test('Poll reader FD /dev/random', poll_read_tester,
	#	env: [ tester_cuse_env ],
	#	args : ['random' ],
	#	is_parallel: false)
	#test('Poll reader FD /dev/urandom', poll_read_tester,
	#	env: [ tester_cuse_env ],
	#	args : ['urandom' ],
	#	is_parallel: false)
endif
