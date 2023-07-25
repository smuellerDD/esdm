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
pkg.generate(esdm_openssl_rng_provider_lib)

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
pkg.generate(esdm_openssl_seed_src_provider_lib)
