openssl_rng_tester = executable(
		'openssl-rng-tester',
		[ 'openssl_rng_tester.c', 'env.c' ],
		dependencies: [ openssl_dep ],
	)

tester_esdm_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		]

test('OpenSSL 3.x RNG Provider - simple random', openssl_rng_tester, 
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'random', 'rng'],
	env: tester_esdm_env
)

test('OpenSSL 3.x RNG Provider - instance pr', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_pr', 'rng'],
	env: tester_esdm_env
)

test('OpenSSL 3.x RNG Provider - instance full', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_full', 'rng'],
	env: tester_esdm_env
)

test('OpenSSL 3.x SEED-SRC Provider - simple random', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'random', 'seed-src'],
	env: tester_esdm_env
)

test('OpenSSL 3.x SEED-SRC Provider - instance pr', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_pr', 'seed-src'],
	env: tester_esdm_env
)

test('OpenSSL 3.x SEED-SRC Provider - instance full', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_full', 'seed-src'],
	env: tester_esdm_env
)
