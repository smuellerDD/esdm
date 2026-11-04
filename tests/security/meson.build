# Security tests: each checks one security property of the ESDM and states it in
# ESDM_TEST_DESCRIPTION, under the headline in ESDM_TEST_HEADLINE. Like those of
# tests/esdm they drive the ESDM in process and therefore touch the
# machine-global System V names - see tests/test_ipc_ns.c.
#
# A test is the function of the same name in the C file of the same name, which
# main() calls. Its file and function are passed in ESDM_TEST_FILE and
# ESDM_TEST_FUNCTION, so the static test plan in it can be found from the
# output of a run - see tests/test_plan.h.
esdm_ipc_ns = files('../test_ipc_ns.c')

if get_option('esdm-server').enabled()
	security_tests = [
		# Skips without ea_non_iid in PATH; its estimators take a while
		# on 1 MiB.
		{
			'name': 'output min-entropy',
			'test': 'esdm_output_min_entropy_security_test',
			'link_with': esdm_lib,
			'timeout': 300,
			'headline': 'Min-entropy of the output',
			'description':
				'1 MiB of output scores more than 6 bits of ' +
				'min-entropy per byte with the SP800-90B ' +
				'non-IID estimators of ea_non_iid: a bound ' +
				'against a broken DRNG, not an entropy claim. ' +
				'Skipped without ea_non_iid.',
		},
		{
			'name': 'self tests',
			'test': 'esdm_selftest_security_test',
			'link_with': esdm_static_lib,
			'timeout': 30,
			'headline': 'Self tests and the reaction to a failure',
			'description':
				'The crypto and entropy source self tests pass ' +
				'at start up, periodically and on demand. After ' +
				'a failed self test the ESDM hands out neither ' +
				'random nor seed data, and the periodic self ' +
				'test worker stops.',
		},
		# Waits up to 90 seconds for the Jitter RNG to seed the ESDM
		# before it counts that as a failure, which a slow sanitizer
		# build may need.
		{
			'name': 'Jitter RNG as the only credited source',
			'test': 'esdm_jent_only_security_test',
			'link_with': esdm_static_lib,
			'timeout': 180,
			'headline':
				'Jitter RNG as the only credited entropy source',
			'description':
				'With the Jitter RNG as the only credited ' +
				'entropy source, the ESDM is seeded and hands ' +
				'out data. Once that source fails, the ' +
				'prediction resistance interface stops at once ' +
				'and the ordinary interface after its budget of ' +
				'generate operations without a full reseed. ' +
				'Then no interface hands out data.',
		},
		# Sits out two reseed intervals of five seconds and 2^11
		# requests.
		{
			'name': 'reseed on interval and request threshold',
			'test': 'esdm_reseed_security_test',
			'link_with': esdm_static_lib,
			'timeout': 120,
			'headline': 'Reseed on interval and request threshold',
			'description':
				'A DRNG is not reseeded before the reseed ' +
				'interval elapsed, but soon after. It is also ' +
				'reseeded once the number of generate requests ' +
				'reaches the reseed threshold, lowered to 2^10 ' +
				'for this test.',
		},
	]

	foreach t : security_tests
		test('ESDM security - ' + t['name'],
			executable(t['test'],
				[ esdm_ipc_ns, t['test'] + '.c' ],
				include_directories: include_dirs_server,
				link_with: t['link_with'],
				dependencies: dependencies_server,
			),
			timeout: t['timeout'],
			suite: 'security',
			env: {
				'ESDM_TEST_HEADLINE': t['headline'],
				'ESDM_TEST_DESCRIPTION': t['description'],
				'ESDM_TEST_FILE':
					'tests/security/' + t['test'] + '.c',
				'ESDM_TEST_FUNCTION': t['test'],
			})
	endforeach
endif
