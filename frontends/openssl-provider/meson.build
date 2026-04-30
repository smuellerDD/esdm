openssl_provider_src = [
	'common.c'
]

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
