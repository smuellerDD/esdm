getrandom_src = [
	'getrandom.c'
]

esdm_getrandom_lib = library(
		'esdm-getrandom',
		[ getrandom_src ],
		version: meson.project_version(),
		soversion:version_array[0],
		include_directories: include_dirs_client,
		dependencies: [ dependencies_client ],
		link_with: esdm_rpc_client_lib,
		install: true
		)
pkgconfig.generate(esdm_getrandom_lib)

esdm_getrandom_dep = declare_dependency(
		link_with: esdm_getrandom_lib,
		link_args: [ '-Wl,--wrap=getrandom', '-Wl,--wrap=getentropy' ],
		)
