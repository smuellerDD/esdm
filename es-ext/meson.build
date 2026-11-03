# libesdm_es_ext: what an external entropy source is developed against, see
# esdm_es_ext.h. It depends on the ESDM logger, json-c and protobuf-c only.
es_ext_lib_src = files([
	'esdm_es_ext_provider.c',
	'esdm_es_ext_server.c',
]) + es_ext_proto_src

# Exports restricted to the API, see version.lds
esdm_es_ext_version_lds = meson.current_source_dir() / 'version.lds'
esdm_es_ext_link_args = [
	'-Wl,--version-script,' + esdm_es_ext_version_lds
]
if not cc.has_multi_link_arguments(esdm_es_ext_link_args)
	warning('Linker does not support version scripts - libesdm_es_ext.so exports every DSO_PUBLIC symbol')
	esdm_es_ext_link_args = []
endif

esdm_es_ext_lib = both_libraries('esdm_es_ext',
	[ es_ext_lib_src ],
	include_directories: include_dirs_es_ext,
	dependencies: [ dependency('threads'), json_c_dep, protobuf_c_dep ],
	link_with: esdm_common_static_lib,
	version: meson.project_version(),
	soversion: version_array[0],
	link_args: esdm_es_ext_link_args,
	link_depends: files('version.lds'),
	install: true
	)
pkgconfig.generate(esdm_es_ext_lib,
	description: 'Library to develop external entropy sources for the ESDM against')

include_user_files += files([
	'esdm_es_ext.h'
])
