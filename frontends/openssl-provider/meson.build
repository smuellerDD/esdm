# Shared by every provider below, whatever its backend is.
openssl_provider_shared_src = [
	'prov_error.c'
]

# The RPC based providers additionally share their whole implementation; only
# the table of offered algorithms differs between them.
openssl_provider_src = [
	'common.c'
] + openssl_provider_shared_src

esdm_openssl_rng_provider_lib = library(
	'esdm-rng-provider',
	[
		'rng-provider.c',
		openssl_provider_src
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	link_with: esdm_rpc_client_lib,
	install: true
)
pkgconfig.generate(esdm_openssl_rng_provider_lib)

# Variant that defaults all generate / get_seed calls to the prediction
# resistance RPC (esdm_rpcc_get_random_bytes_pr) regardless of the
# prediction_resistance flag passed in by OpenSSL.
esdm_openssl_rng_provider_pr_lib = library(
	'esdm-rng-provider-pr',
	[
		'rng-provider.c',
		openssl_provider_src
	],
	c_args: [
		'-DESDM_OSSL_PROV_FORCE_PR=1',
		'-DESDM_PROV_NAME="ESDM RNG Provider (PR)"',
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	link_with: esdm_rpc_client_lib,
	install: true
)
pkgconfig.generate(esdm_openssl_rng_provider_pr_lib)

# Variant talking the EGD protocol instead of the ESDM RPC. It needs neither
# the RPC client library nor the two RPC sockets - a single Unix domain stream
# socket is all it takes, which is what makes it usable in environments where
# the RPC interface cannot be reached. Its algorithms carry the property
# "provider=esdm-egd" so it can be told apart from the RPC based ones when both
# are loaded.
esdm_openssl_egd_provider_lib = library(
	'esdm-egd-provider',
	[
		'egd-provider.c',
		openssl_provider_shared_src
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	# The EGD client, not the RPC client the other providers pull in.
	link_with: esdm_egd_client_lib.get_static_lib(),
	install: true
)
pkgconfig.generate(esdm_openssl_egd_provider_lib)

# Variant talking to the prediction resistance EGD socket. The protocol cannot
# select the generator per request, so this is a matter of which socket the
# provider connects to - which is exactly what the different default path here
# expresses. Its algorithms carry "provider=esdm-egd-pr".
esdm_openssl_egd_provider_pr_lib = library(
	'esdm-egd-provider-pr',
	[
		'egd-provider.c',
		openssl_provider_shared_src
	],
	c_args: [
		'-DESDM_EGD_PROV_FORCE_PR=1',
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	link_with: esdm_egd_client_lib.get_static_lib(),
	install: true
)
pkgconfig.generate(esdm_openssl_egd_provider_pr_lib)

esdm_openssl_seed_src_provider_lib = library(
	'esdm-seed-src-provider',
	[
		'seed-src-provider.c',
		openssl_provider_src
	],
	version: meson.project_version(),
	soversion:version_array[0],
	include_directories: include_dirs_client,
	dependencies: [ dependencies_client, openssl_dep ],
	link_with: esdm_rpc_client_lib,
	install: true
)
pkgconfig.generate(esdm_openssl_seed_src_provider_lib)
