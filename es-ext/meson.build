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

# The providers of the ESDM: they reach esdm_es_ext_provider.h, the provider
# program with options of their own, in the static library.
if get_option('es_pkcs11').enabled()
	esdm_es_pkcs11 = executable('esdm-es-pkcs11',
		[ 'pkcs11/esdm_es_pkcs11.c', 'pkcs11/esdm_es_pkcs11_main.c' ],
		c_args: [ '-DESDM_ES_PKCS11_VERSION="' + meson.project_version() + '"' ],
		include_directories: include_dirs_es_ext,
		link_with: [ esdm_es_ext_lib.get_static_lib(), esdm_common_static_lib ],
		dependencies: [ dependency('threads'), json_c_dep, protobuf_c_dep,
				dependency('libp11', required: true) ],
		install: true
		)

	# Its systemd unit, and the system user it runs as
	es_pkcs11_conf_data = configuration_data()
	es_pkcs11_conf_data.set('PATH',
		get_option('prefix') + '/' + get_option('bindir'))
	es_pkcs11_conf_data.set('SERVICE_TYPE',
		get_option('systemd').enabled() ? 'Type=notify' : 'Type=exec')
	esdm_es_pkcs11_service = configure_file(
		input: 'pkcs11/esdm-es-pkcs11.service.in',
		output: 'esdm-es-pkcs11.service',
		configuration: es_pkcs11_conf_data)
	install_data(esdm_es_pkcs11_service,
		install_dir: get_option('prefix') / 'lib/systemd/system')
	install_data('pkcs11/esdm-es-pkcs11.sysusers',
		rename: 'esdm-es-pkcs11.conf',
		install_dir: get_option('prefix') / 'lib/sysusers.d')
endif
