esdm_tool = executable(
		'esdm-tool',
		[ 'tool_main.c' ],
		include_directories: include_dirs_client,
        dependencies: [ dependencies_client ],
		link_with: esdm_rpc_client_lib,
		install: true
		)
