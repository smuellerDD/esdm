# Tests of the esdm-tool helper code.
#
# Only the parts that stand on their own are covered here: the timing
# arithmetic, the formatters and the result collector. The stress modes around
# them talk to a running esdm-server and are exercised by tests/rpc_client.
if get_option('esdm-tool').enabled()
	tool_common_test = executable(
			'tool_common_test',
			[ files('../../frontends/tool/common.c'),
			  'tool_common_test.c' ],
			include_directories: [
				include_directories('../../frontends/tool'),
				include_directories('../common') ],
		)

	test('esdm-tool helper code', tool_common_test)

	# The command line layer is driven through the installed binary rather
	# than linked, because what is under test is what a user gets: the exit
	# status and the message, not a function's return value.
	tool_cli_test = executable(
			'tool_cli_test',
			[ 'tool_cli_test.c' ],
			include_directories: [ include_dirs_server,
					       include_directories('../common') ],
		)

	test('esdm-tool command line', tool_cli_test,
		# Several of its checks wait out the RPC client's connection
		# attempts, which is what taking no answer looks like.
		timeout: 120,
		args: [ esdm_tool.full_path() ])

	# The other half of the command line: what each command does once a
	# server answers it. Skipped (77) unless run as root, which is what
	# starting the server needs.
	if get_option('esdm-server').enabled()
		tool_server_test = executable(
				'tool_server_test',
				[ 'tool_server_test.c' ],
				include_directories: [
					include_dirs_server,
					include_directories('../common') ],
				dependencies: [ json_c_dep ],
			)

		# The stress modes and the benchmark are loops against the
		# server rather than single requests, so this needs more than
		# the default - and more than its own watchdog, which is what
		# should report a command that never returns.
		test('esdm-tool against a running server', tool_server_test,
			args: [ esdm_tool.full_path() ],
			env: [ 'ESDM_SERVER=' + esdm_server.full_path() ],
			timeout: 600)
	endif
endif
