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
		link_with:  [ esdm_rpc_client_lib, esdm_aux_client_lib ],
		install: true
		)
