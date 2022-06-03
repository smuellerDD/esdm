sha256_tester = executable(
		'sha256_tester',
		[ 'sha256_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

sha512_tester = executable(
		'sha512_tester',
		[ 'sha512_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

hmac_sha2_256_tester = executable(
		'hmac_sha2_256_tester',
		[ 'hmac_sha2_256_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

hmac_sha2_512_tester = executable(
		'hmac_sha2_512_tester',
		[ 'hmac_sha2_512_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

test('SHA256', sha256_tester)
test('SHA512', sha512_tester)

test('HMAC SHA256', hmac_sha2_256_tester)
test('HMAC SHA512', hmac_sha2_512_tester)

if get_option('drng_hash_drbg').enabled()
	hash_drbg_tester = executable(
			'hash_drbg_tester',
			[ 'hash_drbg_tester.c' ],
			dependencies: dependencies_server,
			include_directories: include_dirs_server,
			link_with: esdm_static_lib,
		)
	test('Hash DRBG SHA512', hash_drbg_tester)
endif
