# for i in $(ls *.c | sort); do echo "'$i',"; done
aux_client_src = files([
	'esdm_aux_need_entropy.c'
])

esdm_aux_client_lib = library('esdm_aux_client',
	[ aux_client_src ],
	include_directories: include_dirs_client,
	link_with: esdm_common_static_lib,
	version: meson.project_version(),
	soversion: version_array[0],
	install: true
	)
pkgconfig.generate(esdm_aux_client_lib)

include_user_files += files([
	'esdm_aux_client.h'
])
