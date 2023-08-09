botan_rng_src = [
	'botan-rng.cpp'
]

esdm_botan_rng_lib = library(
		'esdm-botan-rng',
		[
		  botan_rng_src
		],
		version: meson.project_version(),
		soversion:version_array[0],
		include_directories: include_dirs_client,
		dependencies: [ dependencies_client, botan_dep ],
		link_with: esdm_rpc_client_lib,
		install: true
		)
pkgconfig.generate(esdm_botan_rng_lib)

include_user_files += files([
	'botan-rng.hpp'
])
