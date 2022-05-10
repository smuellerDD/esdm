cuse_src = [
	'cuse_device.c',
	'privileges.c'
]

cuse_deps = [ dependency('fuse3') ]

if get_option('selinux').enabled()
	cuse_src += 'selinux.c'
	cuse_deps += dependency('libselinux')
endif

esdm_cuse_random = executable(
		'esdm-cuse-random',
		[ cuse_src, 'cuse_random.c' ],
		include_directories: include_dirs_client,
		dependencies: [ dependencies_client, cuse_deps ],
		link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ],
		install: true
		)

esdm_cuse_urandom = executable(
		'esdm-cuse-urandom',
		[ cuse_src,  'cuse_urandom.c' ],
		include_directories: include_dirs_client,
		dependencies: [ dependencies_client, cuse_deps ],
		link_with: [ esdm_common_static_lib, esdm_rpc_client_lib ],
		install: true
		)

cuse_conf_data = configuration_data()
cuse_conf_data.set('PATH', get_option('prefix') / get_option('bindir'))
esdm_cuse_random_service = configure_file(
	input : 'esdm-cuse-random.service.in',
	output : 'esdm-cuse-random.service',
	configuration : cuse_conf_data)
esdm_cuse_urandom_service = configure_file(
	input : 'esdm-cuse-urandom.service.in',
	output : 'esdm-cuse-urandom.service',
	configuration : cuse_conf_data)
install_data(esdm_cuse_random_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
install_data(esdm_cuse_urandom_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
