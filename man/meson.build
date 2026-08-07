# Man pages are plain roff sources; the only thing generated is the version in
# the .TH line, so building the documentation needs no extra tool chain.
man_conf_data = configuration_data()
man_conf_data.set('VERSION', meson.project_version())

# Pages that are always installed: the ESDM library, plus the client libraries
# that are built unconditionally.
man_pages = [
	'libesdm.3',
	'libesdm_rpc_client.3',
	'libesdm_egd_client.3',
]

if get_option('esdm-server').enabled()
	man_pages += [
		'esdm-server.8',
		'esdm-server-signal-helper.8',
		'esdm-kernel-seeder.8',
	]
endif

if get_option('esdm-tool').enabled()
	man_pages += [ 'esdm-tool.1' ]
endif

if get_option('linux-devfiles').enabled()
	man_pages += [
		'esdm-cuse-random.8',
		# Documented together with esdm-cuse-random; the page is a .so
		# redirect to it.
		'esdm-cuse-urandom.8',
		'esdm-proc.8',
	]
endif

if get_option('linux-getrandom').enabled()
	man_pages += [ 'libesdm_getrandom.3' ]
endif

if get_option('esdm-aux-client').enabled()
	man_pages += [ 'libesdm_aux_client.3' ]
endif

if get_option('openssl-rand-provider').enabled()
	man_pages += [ 'esdm-openssl-provider.7' ]
endif

# Raw entropy measurement tooling - only built for validation, so only
# documented where it is actually installed.
if get_option('validation-helpers').enabled()
	man_pages += [
		'esdm-getrawentropy.8',
		'esdm-extractlsb.8',
	]
endif

if get_option('es_ebpf_testing').enabled()
	man_pages += [ 'esdm-ebpf-collect.8' ]
endif

foreach page : man_pages
	install_man(configure_file(
		input: page + '.in',
		output: page,
		configuration: man_conf_data))
endforeach
