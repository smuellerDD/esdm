botan_rng_tester = executable(
		'botan-rng-tester',
		[ 'botan_rng_tester.cpp', 'env.c' ],
		include_directories: include_dirs_botan_rng,
		dependencies: [ botan_dep ],
        link_with: [ esdm_botan_rng_lib ],
	)

tester_esdm_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		]

test('Botan 3.x RNG Class', botan_rng_tester, env: tester_esdm_env)