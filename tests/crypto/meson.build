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

sha3_tester = executable(
		'sha3_tester',
		[ 'sha3_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)

test('SHA256', sha256_tester, suite: 'crypto')
test('SHA512', sha512_tester, suite: 'crypto')
test('SHA3', sha3_tester, suite: 'crypto')

test('HMAC SHA256', hmac_sha2_256_tester, suite: 'crypto')
test('HMAC SHA512', hmac_sha2_512_tester, suite: 'crypto')

# The XDRBG-256 on the SHAKE256 of the crypto backend, against the known answer
# of its reference implementation
xdrbg_tester = executable(
		'xdrbg_tester',
		[ 'xdrbg_tester.c' ],
		dependencies: dependencies_server,
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
	)
test('XDRBG-256', xdrbg_tester, suite: 'crypto')

if get_option('drng_hash_drbg').enabled()
	hash_drbg_tester = executable(
			'hash_drbg_tester',
			[ 'hash_drbg_tester.c' ],
			dependencies: dependencies_server,
			include_directories: include_dirs_server,
			link_with: esdm_static_lib,
		)
	test('Hash DRBG SHA512', hash_drbg_tester, suite: 'crypto')
endif
