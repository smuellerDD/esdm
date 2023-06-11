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

esdm_getrandom_dep = declare_dependency(
		link_with: esdm_getrandom_lib,
		#link_args: [ '-Wl,--wrap=getrandom', '-Wl,--wrap=getentropy' ],
		# Meson seems to have an issue here: This argument is converted
		# into -Wl,--start-group frontends/getrandom/libesdm-getrandom.so.0.1.1 -Wl,--end-group -Wl,--wrap=getrandom -Wl,--wrap=getentropy
		# but the linker wants it as -lesdm-getrandom -Wl,--wrap=getrandom -Wl,--wrap=getentropy
		#link_args: [ '-Wl,--wrap=getrandom', '-Wl,--wrap=getentropy' ]
		)
