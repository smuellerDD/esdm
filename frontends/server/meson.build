server_src = [
	'server_main.c'
]

# ESDM-Server
dependencies_server += dependency('threads')

esdm_server = executable(
		'esdm-server',
		[ service_rpc_src, server_rpc_src, server_src, ],
		include_directories: include_dirs_server,
		dependencies: dependencies_server,
		link_with: [  esdm_common_static_lib, esdm_lib, ],
		install: true
		)

server_conf_data = configuration_data()
server_conf_data.set('PATH', get_option('prefix') + '/' + get_option('bindir'))
esdm_server_service = configure_file(
	input : 'esdm-server.service.in',
	output : 'esdm-server.service',
	configuration : server_conf_data)
install_data(esdm_server_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
