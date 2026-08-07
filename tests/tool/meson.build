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
endif
