# Security tests: each checks one security property of the ESDM and states it in
# ESDM_TEST_DESCRIPTION. Like those of tests/esdm they drive the ESDM in process
# and therefore touch the machine-global System V names - see
# tests/test_ipc_ns.c.
esdm_ipc_ns = files('../test_ipc_ns.c')

if get_option('esdm-server').enabled()
	esdm_selftest_security_test = executable(
		'esdm_selftest_security_test',
		[ esdm_ipc_ns, 'esdm_selftest_security_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_reseed_security_test = executable(
		'esdm_reseed_security_test',
		[ esdm_ipc_ns, 'esdm_reseed_security_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_jent_only_security_test = executable(
		'esdm_jent_only_security_test',
		[ esdm_ipc_ns, 'esdm_jent_only_security_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_static_lib,
		dependencies: dependencies_server,
	)

	esdm_output_min_entropy_security_test = executable(
		'esdm_output_min_entropy_security_test',
		[ esdm_ipc_ns, 'esdm_output_min_entropy_security_test.c' ],
		include_directories: include_dirs_server,
		link_with: esdm_lib,
		dependencies: dependencies_server,
	)

	# Skips without ea_non_iid in PATH; its estimators take a while on 1 MiB.
	test('ESDM security - output min-entropy',
		esdm_output_min_entropy_security_test,
		timeout: 300,
		suite: 'security',
		env: { 'ESDM_TEST_DESCRIPTION':
			'1 MiB of output scores more than 6 bits of ' +
			'min-entropy per byte with the SP800-90B non-IID ' +
			'estimators of ea_non_iid: a bound against a broken ' +
			'DRNG, not an entropy claim. Skipped without ' +
			'ea_non_iid.' })

	test('ESDM security - self tests', esdm_selftest_security_test,
		suite: 'security',
		env: { 'ESDM_TEST_DESCRIPTION':
			'The crypto and entropy source self tests pass at ' +
			'start up, periodically and on demand. After a ' +
			'failed self test the ESDM hands out neither random ' +
			'nor seed data, and the periodic self test worker ' +
			'stops.' })

	# Waits up to 90 seconds for the Jitter RNG to seed the ESDM before it
	# counts that as a failure, which a slow sanitizer build may need.
	test('ESDM security - Jitter RNG as the only credited source',
		esdm_jent_only_security_test,
		timeout: 180,
		suite: 'security',
		env: { 'ESDM_TEST_DESCRIPTION':
			'With the Jitter RNG as the only credited entropy ' +
			'source, the ESDM is seeded and hands out data. ' +
			'Once that source fails, the prediction resistance ' +
			'interface stops at once and the ordinary interface ' +
			'after its budget of generate operations without a ' +
			'full reseed. Then no interface hands out data.' })

	# Sits out two reseed intervals of five seconds and 2^11 requests.
	test('ESDM security - reseed on interval and request threshold',
		esdm_reseed_security_test,
		timeout: 120,
		suite: 'security',
		env: { 'ESDM_TEST_DESCRIPTION':
			'A DRNG is not reseeded before the reseed interval ' +
			'elapsed, but soon after. It is also reseeded once ' +
			'the number of generate requests reaches the reseed ' +
			'threshold, lowered to 2^10 for this test.' })
endif
