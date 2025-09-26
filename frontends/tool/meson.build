esdm_tool_src = [
	'tool_main.c',
	'common.c',
	'stress_delay.c',
	'stress_process.c',
	'stress_thread.c',
]

esdm_tool = executable(
		'esdm-tool',
		esdm_tool_src,
		include_directories: [ include_dirs_client, include_dirs_aux_client ],
		dependencies: [ dependencies_client ],
		link_with:  [ esdm_common_static_lib, esdm_rpc_client_lib ] + (get_option('esdm-aux-client').enabled() ? [esdm_aux_client_lib] : []),
		install: true
		)

tool_wait_conf_data = configuration_data()
tool_wait_conf_data.set('PATH', get_option('prefix') + '/' + get_option('bindir'))
tool_wait_service = configure_file(
	input : 'esdm-wait-until-fully-seeded.service.in',
	output : 'esdm-wait-until-fully-seeded.service',
	configuration : tool_wait_conf_data)
install_data(tool_wait_service,
	install_dir: get_option('prefix') / 'lib/systemd/system')
