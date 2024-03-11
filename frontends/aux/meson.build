esdm_aux_src = [
	'esdm_aux_need_entropy.c'
]

esdm_aux_lib = library(
		'esdm-aux',
		[
		  esdm_aux_src
		],
		version: meson.project_version(),
		soversion:version_array[0],
		include_directories: include_dirs_client,
		dependencies: [ dependencies_client ],
		link_with: esdm_rpc_client_lib,
		install: true
		)
pkgconfig.generate(esdm_aux_lib)

include_user_files += files([
	'esdm_aux_client.h'
])
