openssl_rng_tester = executable(
		'openssl-rng-tester',
		[ 'openssl_rng_tester.c', 'env.c' ],
		# env.c waits for the RPC socket the server creates
		include_directories: include_dirs_server,
		dependencies: [ openssl_dep ],
	)

tester_esdm_env = [
		'ESDM_SERVER=' + esdm_server.full_path(),
		]

# The EGD provider against the EGD test peer instead of an esdm-server. The
# protocol is the same, so everything the provider does is reachable - and
# unlike a server, the peer can be made to go away mid-life, which is what
# executes the failure paths. It needs no privileges either.
egd_provider_test = executable(
		'egd_provider_test',
		[ 'egd_provider_test.c', files('../egd/egd_peer.c') ],
		include_directories: [ include_dirs_egd_client,
				       include_directories('../egd'),
				       include_directories('../common') ],
		dependencies: [ openssl_dep, dependency('threads') ],
	)

test('OpenSSL 3.x EGD Provider - against the test peer', egd_provider_test,
	args: [ meson.project_build_root() + '/frontends/openssl-provider' ])

test('OpenSSL 3.x RNG Provider - simple random', openssl_rng_tester, 
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'random', 'rng'],
	env: tester_esdm_env,
	# Each test forks its own esdm-server bound to a fixed RPC socket path,
	# so they must not run concurrently with each other.
)

test('OpenSSL 3.x RNG Provider - instance pr', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_pr', 'rng'],
	env: tester_esdm_env,
	# Each test forks its own esdm-server bound to a fixed RPC socket path,
	# so they must not run concurrently with each other.
)

test('OpenSSL 3.x RNG Provider - instance full', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_full', 'rng'],
	env: tester_esdm_env,
	# Each test forks its own esdm-server bound to a fixed RPC socket path,
	# so they must not run concurrently with each other.
)

test('OpenSSL 3.x SEED-SRC Provider - simple random', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'random', 'seed-src'],
	env: tester_esdm_env,
	# Each test forks its own esdm-server bound to a fixed RPC socket path,
	# so they must not run concurrently with each other.
)

test('OpenSSL 3.x SEED-SRC Provider - instance pr', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_pr', 'seed-src'],
	env: tester_esdm_env,
	# Each test forks its own esdm-server bound to a fixed RPC socket path,
	# so they must not run concurrently with each other.
)

test('OpenSSL 3.x SEED-SRC Provider - instance full', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_full', 'seed-src'],
	env: tester_esdm_env,
	# Each test forks its own esdm-server bound to a fixed RPC socket path,
	# so they must not run concurrently with each other.
)

# The EGD provider. It speaks the EGD protocol rather than the RPC one, so it
# exercises a path the tests above do not touch at all.
test('OpenSSL 3.x EGD Provider - simple random', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'random', 'egd'],
	env: tester_esdm_env,
)

test('OpenSSL 3.x EGD Provider - instance full', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_full', 'egd'],
	env: tester_esdm_env,
)

# Expected to fail: the EGD protocol has no way to ask for prediction
# resistance, so this provider refuses rather than quietly handing back data
# that does not have the property the caller asked for. The two tests above
# would catch a socket that is simply not reachable.
test('OpenSSL 3.x EGD Provider - instance pr is refused', openssl_rng_tester,
	args: [meson.project_build_root() + '/frontends/openssl-provider', 'instantiate_pr', 'egd'],
	env: tester_esdm_env,
	should_fail: true,
)
