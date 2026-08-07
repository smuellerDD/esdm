server_src = [
	'server_main.c'
]

# ESDM-Server
dependencies_server += dependency('threads')

esdm_server = executable(
		'esdm-server',
		[ service_rpc_src, server_rpc_src, egd_server_src, server_src, ],
		include_directories: include_dirs_server,
		dependencies: dependencies_server,
		link_with: [  esdm_common_static_lib, esdm_lib, ],
		install: true
		)

server_conf_data = configuration_data()
server_conf_data.set('PATH', get_option('prefix') + '/' + get_option('bindir'))
if get_option('systemd').enabled()
	# The EGD socket is deliberately only ordered, not required: the EGD
	# compatibility interface is opt-in, so it must stay off unless the
	# administrator starts esdm-server-egd.socket. The ordering is a no-op
	# while that unit is not started, and makes systemd hand the descriptor
	# over before the server starts once it is.
	server_conf_data.set('UNIT_SNIPPET', '''
	# SOCKET ACTIVATION BEGIN
	Requires=esdm-server-priv.socket
	After=esdm-server-priv.socket

	Requires=esdm-server-unpriv.socket
	After=esdm-server-unpriv.socket

	After=esdm-server-egd.socket
	After=esdm-server-egd-pr.socket
	# SOCKET ACTIVATION END
	'''
	)

	# NotifyAccess=all: when the server runs with --pid_namespace, the
	# READY notification is sent by the daemon child inside the PID
	# namespace, not by the supervisor main process; harmless otherwise
	server_conf_data.set('SERVICE_TYPE', 'Type=notify\nNotifyAccess=all')
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

if get_option('es_sched_ebpf').enabled() or get_option('es_irq_ebpf').enabled()
	# The eBPF entropy sources load their programs during the privileged
	# initialization phase (as root, before the privilege drop). The
	# bpf(2) and perf_event_open(2) syscalls are not part of
	# @system-service and must be allowed explicitly; the capability
	# check is satisfied by CAP_SYS_ADMIN which is already in the
	# bounding set, CAP_BPF/CAP_PERF_MON are added for environments
	# starting the server as a non-root user with ambient capabilities.
	server_conf_data.set('EBPF_UNIT_SNIPPET', '''
# EBPF ENTROPY SOURCES BEGIN
CapabilityBoundingSet=CAP_BPF CAP_PERF_MON
SystemCallFilter=bpf perf_event_open
# EBPF ENTROPY SOURCES END
'''
	)
else
	server_conf_data.set('EBPF_UNIT_SNIPPET', '')
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

server_socket_egd_conf_data = configuration_data()
server_socket_egd_conf_data.set('SOCKET_PATH', get_option('esdm-server-egd-socket-path'))
esdm_server_egd_socket = configure_file(
	input : 'esdm-server-egd.socket.in',
	output : 'esdm-server-egd.socket',
	configuration : server_socket_egd_conf_data)
install_data(esdm_server_egd_socket,
	     install_dir: get_option('prefix') / 'lib/systemd/system')

# Counterpart serving the prediction resistance generator. The EGD protocol
# cannot ask for prediction resistance per request, so it gets a socket of its
# own - see esdm_egd_server_enable_pr().
server_socket_egd_pr_conf_data = configuration_data()
server_socket_egd_pr_conf_data.set('SOCKET_PATH', get_option('esdm-server-egd-pr-socket-path'))
esdm_server_egd_pr_socket = configure_file(
	input : 'esdm-server-egd-pr.socket.in',
	output : 'esdm-server-egd-pr.socket',
	configuration : server_socket_egd_pr_conf_data)
install_data(esdm_server_egd_pr_socket,
	     install_dir: get_option('prefix') / 'lib/systemd/system')

server_socket_unpriv_conf_data = configuration_data()
server_socket_unpriv_conf_data.set('SOCKET_PATH', get_option('esdm-server-rpc-path-unprivileged') + '/esdm-rpc-unpriv.socket')
esdm_server_unpriv_socket = configure_file(
	input : 'esdm-server-unpriv.socket.in',
	output : 'esdm-server-unpriv.socket',
	configuration : server_socket_unpriv_conf_data)
install_data(esdm_server_unpriv_socket,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
