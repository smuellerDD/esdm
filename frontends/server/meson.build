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
if get_option('systemd').enabled()
	server_conf_data.set('UNIT_SNIPPET', '''
	# SOCKET ACTIVATION BEGIN
	Requires=esdm-server-priv.socket
	After=esdm-server-priv.socket

	Requires=esdm-server-unpriv.socket
	After=esdm-server-unpriv.socket
	# SOCKET ACTIVATION END
	'''
	)

	server_conf_data.set('SERVICE_TYPE', 'Type=notify')
else
	server_conf_data.set('UNIT_SNIPPET', '''
	# NO SOCKET ACTIVATION BEGIN
	DefaultDependencies=no
	After=local-fs.target
	Before=shutdown.target
	Conflicts=shutdown.target
	# NO SOCKET ACTIVATION END
	'''
	)

	server_conf_data.set('SERVICE_TYPE', '')
endif
esdm_server_service = configure_file(
	input : 'esdm-server.service.in',
	output : 'esdm-server.service',
	configuration : server_conf_data)
install_data(esdm_server_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')

server_socket_priv_conf_data = configuration_data()
server_socket_priv_conf_data.set('SOCKET_PATH', get_option('esdm-server-rpc-path-privileged') + '/esdm-rpc-priv.socket')
esdm_server_priv_socket = configure_file(
	input : 'esdm-server-priv.socket.in',
	output : 'esdm-server-priv.socket',
	configuration : server_socket_priv_conf_data)
install_data(esdm_server_priv_socket,
	     install_dir: get_option('prefix') / 'lib/systemd/system')

server_socket_unpriv_conf_data = configuration_data()
server_socket_unpriv_conf_data.set('SOCKET_PATH', get_option('esdm-server-rpc-path-unprivileged') + '/esdm-rpc-unpriv.socket')
esdm_server_unpriv_socket = configure_file(
	input : 'esdm-server-unpriv.socket.in',
	output : 'esdm-server-unpriv.socket',
	configuration : server_socket_unpriv_conf_data)
install_data(esdm_server_unpriv_socket,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
