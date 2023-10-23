esdm_server_signal_helper = executable(
		'esdm-server-signal-helper',
		[ 'server_signal_helper.c' ],
		include_directories: include_dirs_client,
        dependencies: [ dependencies_client ],
		link_with: esdm_rpc_client_lib,
		install: true
		)

esdm_server_suspend_service = configure_file(
	input : 'esdm-server-suspend.service.in',
	output : 'esdm-server-suspend.service',
	configuration : server_conf_data)
esdm_server_resume_service = configure_file(
	input : 'esdm-server-resume.service.in',
	output : 'esdm-server-resume.service',
	configuration : server_conf_data)

install_data(esdm_server_suspend_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
install_data(esdm_server_resume_service,
	     install_dir: get_option('prefix') / 'lib/systemd/system')
